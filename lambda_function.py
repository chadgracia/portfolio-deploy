"""
Client Portfolio — prototype (Gracia Group)

Lambda behind a Function URL. Renders a client's holdings, values each against a
market-price estimate, and persists newly-entered holdings to S3.

AUTH: magic-link + signed session cookie (HMAC, same pattern as deal_update_form).
A client opens /?client=<id>&token=<hmac> once; that sets a 30-day signed
session cookie, and every read/write is scoped to the client the cookie proves.
Generate a client's link locally:  python lambda_function.py <person_id> <display_name> <base_url>
(client_id is an opaque Pipeline person_id; the HMAC_SECRET env var must match production).

PROTOTYPE SCOPE / KNOWN LIMITS — read before this touches a real client:
  - The magic link is permanent per client (HMAC over client_id). If you want
    links that expire, add an expiry into the token; the session cookie already
    expires after SESSION_DAYS.
  - Market Price comes from the Hiive Price field on each Pipeline company, read
    out of companies.json by company_id (see company_prices()). Holdings whose
    company has no Hiive Price yet render "—".
  - Storage is one JSON object per client in S3, whole-object read-modify-write.
    Fine for a handful of clients; revisit if concurrency or volume grows.
"""

import os
import json
import time
import base64
import hmac
import hashlib
import html
import urllib.parse
import uuid
from datetime import datetime, timezone

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

# ── Config ────────────────────────────────────────────────────────────────────
BUCKET       = "gracia-portfolios"                       # per-client portfolio storage
HMAC_SECRET  = os.environ.get("HMAC_SECRET", "change-me-in-env")  # set in Lambda env
IDENTITY_SECRET = os.environ.get("IDENTITY_SECRET", "")  # shared with trades-gracia-web; verifies the SSO handoff
COOKIE_NAME  = "gg_session"
SESSION_DAYS = 365

# Admin gate: the one client_id allowed to invite others. Set in the Lambda env.
ADMIN_CLIENT_ID = os.environ.get("ADMIN_CLIENT_ID", "")

# Pipeline (PD) person page; the admin roll-up links each Client ID here (new tab).
PD_PERSON_URL = "https://app.pipelinecrm.com/people/"

# Where client action emails (Get Bids / Get Offers / Feature Request) are sent.
CHAD_EMAIL = "cgracia@rainmakersecurities.com"
SES_SENDER = "agent@agent.graciagroup.com"   # already a verified SES sender

# ── Market Price source (Hiive Price from the CRM snapshot) ──────────────────────
# Real marks come from the persisted Hiive Price field on each Pipeline company, read
# out of companies.json by company_id. Holdings whose company has no Hiive Price yet
# render "—" in the Market Price / Value / Gain columns.
FIELD_HIIVE_PRICE      = "custom_label_3999575"
FIELD_HIIVE_PRICE_DATE = "custom_label_3999576"

# ── Last Round (LR) source ────────────────────────────────────────────────────────
# The "$LR" currency field on each Pipeline company (last primary-round price/sh),
# read out of companies.json by company_id, with the "LR Date" field as its as-of date.
FIELD_LAST_ROUND      = "custom_label_3064363"   # $LR
FIELD_LAST_ROUND_DATE = "custom_label_3826032"   # LR Date

# ── Catalyst source (one-line catalyst written by the valuation-scanner) ──
FIELD_CATALYST        = "custom_label_3999603"   # Catalyst

# Exact CRM Structure values (custom_label_3064360)
STRUCTURES = ["Direct", "Fund/SPV", "Forward", "Unknown", "None"]
# Structures where shares x underlying mark is NOT a clean position value
INDIRECT_STRUCTURES = {"Fund/SPV", "Forward"}


# ── Company master list (Pipeline CRM mirror in S3) ──────────────────────────────
# The tracked universe = Pipeline companies of Org. Type "Traded Issuer" (id 5103523),
# read live from the shared CRM snapshot. Pipeline company_id is the join key; names
# are display-only. Cached for the life of the warm Lambda instance (read once).
COMPANIES_BUCKET  = "full-pipeline-cache"
COMPANIES_KEY     = "companies.json"
PEOPLE_KEY        = "people.json"        # 113 MB CRM people snapshot; source for the index below
PEOPLE_INDEX_KEY  = "people_index.json"  # small email->id / id->{email,first_name} index (build_people_index.py)
ORG_TYPE_FIELD    = "custom_label_625142"
KEEP_ORG_TYPE_IDS = {5103523}        # Traded Issuer (id 5103523); Private Company intentionally excluded

_companies_cache = None   # {company_id(str): name}, set on first use


def _org_type_ids(rec):
    v = rec.get("custom_fields", {}).get(ORG_TYPE_FIELD)
    if v is None:
        return set()
    vals = v if isinstance(v, list) else [v]
    out = set()
    for x in vals:
        try:
            out.add(int(x))
        except (TypeError, ValueError):
            pass
    return out


def tracked_companies():
    """{company_id(str): name} for Unicorn + Private Company orgs, sorted by name.
    Read once from the CRM snapshot, then cached on the warm instance."""
    global _companies_cache
    if _companies_cache is not None:
        return _companies_cache
    s3 = boto3.client("s3")
    obj = s3.get_object(Bucket=COMPANIES_BUCKET, Key=COMPANIES_KEY)
    data = json.loads(obj["Body"].read())
    out = {}
    for rec in data.get("companies", []):
        if not (_org_type_ids(rec) & KEEP_ORG_TYPE_IDS):
            continue
        cid, name = rec.get("id"), (rec.get("name") or "").strip()
        if cid is None or not name:
            continue
        out[str(cid)] = name
    _companies_cache = dict(sorted(out.items(), key=lambda kv: kv[1].lower()))
    return _companies_cache


_prices_cache = None   # {company_id(str): {"hiive_price", "as_of", "last_round", "last_round_as_of"}}


def _price_float(v):
    if v in (None, "", 0, "0"):
        return None
    try:
        if isinstance(v, str):
            v = v.replace("$", "").replace(",", "").strip()
            if not v:
                return None
        return float(v)
    except (TypeError, ValueError):
        return None


def company_prices():
    """{company_id(str): {"hiive_price", "as_of", "last_round", "last_round_as_of"}}
    read from the CRM snapshot's Hiive Price and $LR fields. Cached on the warm
    instance; a company is included if it has either a Hiive Price or an LR price
    (holdings with neither render "—")."""
    global _prices_cache
    if _prices_cache is not None:
        return _prices_cache
    s3 = boto3.client("s3")
    obj = s3.get_object(Bucket=COMPANIES_BUCKET, Key=COMPANIES_KEY)
    data = json.loads(obj["Body"].read())
    out = {}
    for rec in data.get("companies", []):
        cid = rec.get("id")
        if cid is None:
            continue
        custom = rec.get("custom_fields", {}) or {}
        price = _price_float(custom.get(FIELD_HIIVE_PRICE))
        last_round = _price_float(custom.get(FIELD_LAST_ROUND))
        if price is None and last_round is None:
            continue
        out[str(cid)] = {
            "hiive_price": price,
            "as_of": custom.get(FIELD_HIIVE_PRICE_DATE) or None,
            "last_round": last_round,
            "last_round_as_of": (custom.get(FIELD_LAST_ROUND_DATE) or None)
                                 if FIELD_LAST_ROUND_DATE else None,
        }
    _prices_cache = out
    return _prices_cache


_catalysts_cache = None   # {company_id(str): catalyst_text}, set on first use


def company_catalysts():
    """{company_id(str): catalyst_text} read from the CRM snapshot's Catalyst
    field. Cached on the warm instance. Companies with no catalyst are omitted."""
    global _catalysts_cache
    if _catalysts_cache is not None:
        return _catalysts_cache
    s3 = boto3.client("s3")
    obj = s3.get_object(Bucket=COMPANIES_BUCKET, Key=COMPANIES_KEY)
    data = json.loads(obj["Body"].read())
    out = {}
    for rec in data.get("companies", []):
        cid = rec.get("id")
        if cid is None:
            continue
        custom = rec.get("custom_fields", {}) or {}
        text = (custom.get(FIELD_CATALYST) or "").strip()
        if text:
            out[str(cid)] = text
    _catalysts_cache = out
    return _catalysts_cache


_people_index_cache = None   # parsed people_index.json, set on first use


def _people_index():
    """The small people_index.json (built from the 113 MB people.json by the
    upstream build_people_index.py), read + parsed ONCE and cached on the warm
    instance. Shape:
        {"by_id":    {id_str: {"email": ..., "first_name": ..., "name": "First Last"}},
         "by_email": {email_lower: id_str}}
    The single source both lookups read, so they can't diverge. The full 113 MB
    people.json is NEVER loaded here — that parse is what OOM'd / timed out the
    function. A short S3 connect/read timeout (no retry storm) fails fast on a stuck
    read. May raise on a read/parse error — callers are fail-closed."""
    global _people_index_cache
    if _people_index_cache is not None:
        return _people_index_cache
    cfg = BotoConfig(connect_timeout=5, read_timeout=5, retries={"max_attempts": 1})
    s3 = boto3.client("s3", config=cfg)
    obj = s3.get_object(Bucket=COMPANIES_BUCKET, Key=PEOPLE_INDEX_KEY)
    _people_index_cache = json.loads(obj["Body"].read())
    return _people_index_cache


def lookup_person(client_id):
    """Look up a person by id via people_index.json, for the invite feature.
    Returns {"found": True, "email", "first_name"} or {"found": False}. Ids are
    strings in the index; client_id is a string. Never raises — a missing index or
    unknown id just yields {"found": False}. (The index's by_id entries are already
    normalized by build_people_index.py: clean email + first_name with full_name
    fallback, so no variant handling is needed here.)"""
    try:
        rec = _people_index().get("by_id", {}).get(str(client_id))
        if rec:
            return {"found": True,
                    "email": (rec.get("email") or "").strip(),
                    "first_name": (rec.get("first_name") or "").strip()}
    except Exception as e:
        print(f"lookup_person failed: {e}")
    return {"found": False}


def picker_index():
    """{display_label: company_id}. Duplicate names get a ' #id' suffix so the name
    the datalist submits always resolves to exactly one company."""
    companies = tracked_companies()
    counts = {}
    for n in companies.values():
        counts[n] = counts.get(n, 0) + 1
    idx = {}
    for cid, name in companies.items():
        idx[name if counts[name] == 1 else f"{name} #{cid}"] = cid
    return idx


# ── Storage (S3, one object per client) ─────────────────────────────────────────
def _key(client_id):
    return f"portfolios/{client_id}.json"


def load_portfolio(client_id):
    s3 = boto3.client("s3")
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=_key(client_id))
        return json.loads(obj["Body"].read())
    except ClientError as e:
        # Only a genuine "not found" means an empty portfolio. Any other error
        # must raise — silently returning empty here would let a later save wipe
        # a real portfolio on a transient read failure.
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return {"client_id": client_id, "holdings": []}
        raise


def save_portfolio(portfolio):
    s3 = boto3.client("s3")
    s3.put_object(
        Bucket=BUCKET,
        Key=_key(portfolio["client_id"]),
        ContentType="application/json",
        Body=json.dumps(portfolio).encode("utf-8"),
    )


# ── Mutations ───────────────────────────────────────────────────────────────────
def _to_float(v):
    try:
        v = (v or "").strip()
        return float(v) if v != "" else None
    except (TypeError, ValueError):
        return None


def add_holding(portfolio, form):
    # The datalist submits the company NAME; resolve it back to the Pipeline id.
    name_in = (form.get("company") or "").strip()
    company_id = picker_index().get(name_in)
    if not company_id:
        return  # not a recognized company; the picker should prevent this
    status = "watchlist" if form.get("status") == "watchlist" else "holding"
    structure = form.get("structure", "None")
    if structure not in STRUCTURES:
        structure = "None"
    txn = (form.get("transaction_date") or "").strip() or None
    now = datetime.now(timezone.utc).isoformat()
    # Mark at add time, so we can later show movement since the item was added.
    info = company_prices().get(company_id)
    portfolio["holdings"].append({
        "holding_id": "hld_" + uuid.uuid4().hex[:8],
        "company_id": company_id,
        "company_name": tracked_companies()[company_id],
        "status": status,                              # "holding" or "watchlist"
        "shares": _to_float(form.get("shares")),
        "pps_cost": _to_float(form.get("pps_cost")),   # Gross PPS paid; Target Price for watchlist
        "structure": structure,
        "transaction_date": txn,                       # optional, manual
        "price_at_add": info["hiive_price"] if info else None,
        "created_at": now,
        "updated_at": now,
    })


def remove_holding(portfolio, holding_id):
    portfolio["holdings"] = [
        h for h in portfolio["holdings"] if h.get("holding_id") != holding_id
    ]


def convert_holding(portfolio, holding_id, form):
    # Watchlist -> holding. The Target Price already lives in pps_cost and becomes the
    # starting cost basis (editable later); shares are optional at convert time.
    for h in portfolio["holdings"]:
        if h.get("holding_id") != holding_id:
            continue
        h["status"] = "holding"
        if (form.get("shares") or "").strip():
            h["shares"] = _to_float(form.get("shares"))
        h["updated_at"] = datetime.now(timezone.utc).isoformat()
        break


def update_holding(portfolio, holding_id, form):
    # Partial update: only the field(s) present in the form are changed.
    for h in portfolio["holdings"]:
        if h.get("holding_id") != holding_id:
            continue
        if "shares" in form:
            h["shares"] = _to_float(form.get("shares"))
        if "pps_cost" in form:
            h["pps_cost"] = _to_float(form.get("pps_cost"))
        h["updated_at"] = datetime.now(timezone.utc).isoformat()
        break


# ── Client action emails (Get Bids / Get Offers / Feature Request) ───────────────
def _notify_chad(subject, body):
    try:
        boto3.client("ses", region_name="us-east-1").send_email(
            Source=SES_SENDER,
            Destination={"ToAddresses": [CHAD_EMAIL]},
            Message={"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}},
        )
    except Exception as e:
        print(f"notify_chad failed: {e}")


def notify_interest(portfolio, client_id, holding_id, action):
    h = next((x for x in portfolio.get("holdings", []) if x.get("holding_id") == holding_id), None)
    if not h:
        return
    who = portfolio.get("display_name") or f"client {client_id}"
    label = "GET BIDS (client wants to sell)" if action == "get_bids" else "GET OFFERS (client wants to buy)"
    verb = "Get Bids" if action == "get_bids" else "Get Offers"
    body = (
        "Automated portfolio request - follow up with the client directly.\n\n"
        f"Client:      {who} ({client_id})\n"
        f"Request:     {label}\n"
        f"Company:     {h.get('company_name', '?')}\n"
        f"Structure:   {h.get('structure', '')}\n"
        f"Shares held: {h.get('shares')}\n"
    )
    _notify_chad(f"[Portfolio] {verb} - {who} - {h.get('company_name', '?')}", body)


def notify_feature(portfolio, client_id, message):
    message = (message or "").strip()
    if not message:
        return
    who = portfolio.get("display_name") or f"client {client_id}"
    body = (
        "Automated feature request from the portfolio app.\n\n"
        f"Client: {who} ({client_id})\n\n"
        f"{message}\n"
    )
    _notify_chad(f"[Portfolio] Feature request - {who}", body)


def _send_email(to_addr, subject, body):
    try:
        boto3.client("ses", region_name="us-east-1").send_email(
            Source=SES_SENDER,
            Destination={"ToAddresses": [to_addr]},
            Message={"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}},
        )
    except Exception as e:
        print(f"send_email failed: {e}")


def send_invite(target_id, to_addr, first_name, base_url):
    link = f"{base_url}/?client={target_id}&token={make_token(target_id)}"
    first_name = (first_name or "").strip() or "there"
    subject = "A portfolio tracker I thought you might find useful (beta)"
    body = (
        f"Hi {first_name},\n\n"
        "I created a portfolio tracker for my personal pre-IPO holdings because I "
        "wanted a way to get a sense of current valuations based on the bids we're "
        "seeing, plus news that could move the price, all in one place. I thought I'd "
        "share this beta with a few clients. You can add your own positions and it'll "
        "track them the same way — if you find it useful, let me know!\n\n"
        "Open yours here:\n"
        f"{link}\n\n"
        "The link is private to you, so please don't forward it. The figures are "
        "indicative third-party estimates for tracking only — not an offer, a quote, "
        "or a Rainmaker valuation.\n\n"
        "Chad Gracia\n"
        "Rainmaker Securities\n"
    )
    _send_email(to_addr, subject, body)


def _json_ok():
    return {"statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"ok": True})}


# ── Valuation (computed at read time, never stored) ──────────────────────────────
def value_holding(h):
    info = company_prices().get(h.get("company_id"))
    hp = info["hiive_price"] if info else None
    shares, pps = h.get("shares"), h.get("pps_cost")
    current = shares * hp if (shares is not None and hp is not None) else None
    cost = shares * pps if (shares is not None and pps is not None) else None
    gl = current - cost if (current is not None and cost is not None) else None
    return {
        "hiive_price": hp,
        "as_of": info["as_of"] if info else None,
        "last_round": info["last_round"] if info else None,
        "last_round_as_of": info["last_round_as_of"] if info else None,
        "current": current,
        "cost": cost,
        "gl": gl,
    }


# ── Formatting helpers ───────────────────────────────────────────────────────────
def _money(v):
    if v is None:
        return "—"
    sign = "-" if v < 0 else ""
    return "{}${:,.2f}".format(sign, abs(v))


def _shares(v):
    if v is None:
        return "—"
    return "{:,.0f}".format(v) if float(v).is_integer() else "{:,.2f}".format(v)


def _gl_class(v):
    if v is None:
        return ""
    return "pos" if v >= 0 else "neg"


def _raw(v):
    if v is None:
        return ""
    f = float(v)
    return str(int(f)) if f.is_integer() else str(f)


def _hover_cell(display, title, cls="num"):
    t = f' title="{html.escape(title)}"' if title else ""
    return f'<td class="{cls}"{t}>{display}</td>'


def _edit_cell(holding_id, field, value, display, title=None, target=None):
    # target (a client_id) is set only by the admin roll-up: it rides along as
    # data-target-client-id so the edit POST writes to THAT client, not the admin's
    # own portfolio. Omitted in the client view, where edits target the own session.
    t = f' title="{html.escape(title)}"' if title else ""
    tgt = f' data-target-client-id="{html.escape(str(target))}"' if target else ""
    return (
        f'<td class="num"{t}><span class="editable" '
        f'data-holding-id="{html.escape(holding_id)}" '
        f'data-field="{field}" data-value="{html.escape(_raw(value))}"{tgt}>{display}</span></td>'
    )


# ── Inline-edit script (click a Shares or Cost cell; Enter saves, Esc cancels) ─────
EDIT_SCRIPT = """<script>
// Full-screen "working" overlay shown while a mutating POST is in flight. Adding the
// first holding can take ~a minute (cold start + loading the company list), so this
// reassures the client and stops them closing the tab or double-submitting. It clears
// itself when the post/redirect response loads the next page.
function ggShowWorking(msg) {
  if (document.querySelector('.working-overlay')) return;
  var ov = document.createElement('div');
  ov.className = 'working-overlay';
  ov.innerHTML = '<div class="working-box"><div class="spinner"></div><p>' + msg + '</p></div>';
  document.body.appendChild(ov);
}
(function () {
  document.querySelectorAll('.editable').forEach(function (cell) {
    cell.addEventListener('click', function () {
      if (cell.querySelector('input')) return;
      var orig = cell.textContent;
      var raw = cell.getAttribute('data-value') || '';
      var input = document.createElement('input');
      input.type = 'number'; input.step = 'any'; input.min = '0';
      input.value = raw; input.className = 'cell-edit';
      cell.textContent = ''; cell.appendChild(input);
      input.focus(); input.select();
      var done = false;
      function commit(save) {
        if (done) return;
        done = true;
        if (!save || input.value.trim() === raw.trim()) { cell.textContent = orig; return; }
        var form = document.createElement('form');
        form.method = 'post';
        function hidden(name, value) {
          var i = document.createElement('input');
          i.type = 'hidden'; i.name = name; i.value = value;
          form.appendChild(i);
        }
        hidden('action', 'update');
        hidden('holding_id', cell.getAttribute('data-holding-id'));
        hidden(cell.getAttribute('data-field'), input.value);
        var tgt = cell.getAttribute('data-target-client-id');
        if (tgt) hidden('target_client_id', tgt);   // admin roll-up: write to that client
        ggShowWorking('Saving… please keep this page open.');
        document.body.appendChild(form); form.submit();
      }
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); commit(true); }
        else if (e.key === 'Escape') { e.preventDefault(); commit(false); }
      });
      input.addEventListener('blur', function () { commit(true); });
    });
  });
})();
(function () {
  function post(data) {
    var body = Object.keys(data).map(function (k) {
      return encodeURIComponent(k) + '=' + encodeURIComponent(data[k]);
    }).join('&');
    return fetch(window.location.pathname, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body
    });
  }
  document.querySelectorAll('.act').forEach(function (btn) {
    btn.addEventListener('click', function () {
      if (btn.disabled) return;
      btn.disabled = true;
      post({ action: btn.getAttribute('data-act'), holding_id: btn.getAttribute('data-hid') })
        .then(function (r) {
          if (!r.ok) throw 0;
          btn.textContent = 'Sent \\u2713';
          btn.classList.add('done');
        })
        .catch(function () {
          btn.disabled = false;
          alert('Could not send - please try again, or email Chad directly.');
        });
    });
  });
  var send = document.getElementById('fr-send');
  if (send) {
    send.addEventListener('click', function () {
      var ta = document.getElementById('fr-text');
      var msg = document.getElementById('fr-msg');
      var text = (ta.value || '').trim();
      if (!text) { ta.focus(); return; }
      send.disabled = true;
      msg.textContent = '';
      post({ action: 'feature_request', message: text })
        .then(function (r) {
          if (!r.ok) throw 0;
          ta.value = '';
          msg.textContent = 'Thanks - sent to Chad.';
          setTimeout(function () { send.disabled = false; }, 600);
        })
        .catch(function () {
          send.disabled = false;
          msg.textContent = 'Could not send - try again.';
        });
    });
  }
})();
(function () {
  var lookupBtn = document.getElementById('inv-lookup');
  if (!lookupBtn) return;   // panel only present for the admin session
  var idEl = document.getElementById('inv-id');
  var emailEl = document.getElementById('inv-email');
  var nameEl = document.getElementById('inv-name');
  var sendBtn = document.getElementById('inv-send');
  var msgEl = document.getElementById('inv-msg');
  var firstName = '';
  var invitedAt = null;
  function fmtDate(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString();
  }
  function post(data) {
    var body = Object.keys(data).map(function (k) {
      return encodeURIComponent(k) + '=' + encodeURIComponent(data[k]);
    }).join('&');
    return fetch(window.location.pathname, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body
    });
  }
  lookupBtn.addEventListener('click', function () {
    var tid = (idEl.value || '').trim();
    if (!tid) { idEl.focus(); return; }
    msgEl.textContent = '';
    post({ action: 'invite_lookup', target_id: tid })
      .then(function (r) { if (!r.ok) throw 0; return r.json(); })
      .then(function (d) {
        if (d.found) {
          firstName = d.first_name || '';
          emailEl.value = d.email || '';
          nameEl.textContent = (firstName || 'Match found') + ' \\u2014 confirm the email and send.';
        } else {
          firstName = '';
          nameEl.textContent = 'No match in the directory \\u2014 enter their email manually.';
        }
        invitedAt = d.invited_at || null;
        if (invitedAt) {
          msgEl.style.color = 'var(--neg)';
          msgEl.textContent = '\\u26a0 Already invited ' + fmtDate(invitedAt)
            + (d.invited_email ? ' (' + d.invited_email + ')' : '');
        } else {
          msgEl.style.color = '';
          msgEl.textContent = '';
        }
      })
      .catch(function () { nameEl.textContent = 'Lookup failed \\u2014 enter the email manually.'; });
  });
  sendBtn.addEventListener('click', function () {
    var tid = (idEl.value || '').trim();
    var email = (emailEl.value || '').trim();
    if (!tid) { idEl.focus(); return; }
    if (!email) { emailEl.focus(); return; }
    // Warn-and-allow: a prior invite just requires an explicit confirm, never blocks.
    if (invitedAt && !confirm('Already invited ' + fmtDate(invitedAt) + '. Resend?')) return;
    sendBtn.disabled = true;
    sendBtn.textContent = 'Sending\\u2026';
    msgEl.style.color = '';
    msgEl.textContent = '';
    post({ action: 'invite_send', target_id: tid, email: email, first_name: firstName })
      .then(function (r) {
        if (!r.ok) throw 0;
        invitedAt = new Date().toISOString();   // reflect the resend within this session
        msgEl.style.color = '';
        msgEl.textContent = 'Invite sent \\u2713';
      })
      .catch(function () {
        msgEl.style.color = 'var(--neg)';
        msgEl.textContent = 'Could not send \\u2014 try again.';
      })
      .then(function () {
        sendBtn.disabled = false;
        sendBtn.textContent = 'Send invite';
      });
  });
})();
(function () {
  // Segmented Holding|Watchlist toggle morphs each add form: in watchlist mode hide
  // Shares / Structure / Transaction date and relabel Cost -> Target Price.
  document.querySelectorAll('form.addform').forEach(function (f) {
    var radios = f.querySelectorAll('input[name="status"]');
    if (!radios.length) return;
    var shares = f.querySelector('.f-shares'), struct = f.querySelector('.f-structure'),
        date = f.querySelector('.f-date'), costLabel = f.querySelector('.cost-label'),
        costInput = f.querySelector('input[name="pps_cost"]'), btn = f.querySelector('button[type="submit"]');
    function apply() {
      var watch = (f.querySelector('input[name="status"]:checked') || {}).value === 'watchlist';
      [shares, struct, date].forEach(function (el) { if (el) el.style.display = watch ? 'none' : ''; });
      if (costLabel) costLabel.textContent = watch ? 'Target Price' : 'Cost per share (Gross)';
      if (costInput) costInput.placeholder = watch ? "Price you'd buy at" : 'Original purchase price';
      if (btn) btn.textContent = watch ? 'Add to watchlist' : 'Add holding';
    }
    radios.forEach(function (r) { r.addEventListener('change', apply); });
    apply();
  });
})();
(function () {
  // "I bought this" — convert a watchlist item to a holding, prompting for shares.
  document.querySelectorAll('.convert-btn').forEach(function (b) {
    b.addEventListener('click', function () {
      var sh = prompt('How many shares did you buy? (leave blank to fill in later)');
      if (sh === null) return;   // cancelled
      var f = document.createElement('form'); f.method = 'post';
      function hid(n, v) { var i = document.createElement('input'); i.type = 'hidden'; i.name = n; i.value = v; f.appendChild(i); }
      hid('action', 'convert');
      hid('holding_id', b.getAttribute('data-hid'));
      if (sh.trim()) hid('shares', sh.trim());
      var tgt = b.getAttribute('data-target-client-id');
      if (tgt) hid('target_client_id', tgt);
      ggShowWorking('Converting… please keep this page open.');
      document.body.appendChild(f); f.submit();
    });
  });
})();
(function () {
  // Working overlay on any add/remove submit (full-page POST → ~1 min on a cold
  // start). HTML5 validation runs first, so it only fires on a real submit. The
  // button is disabled to block a double-submit.
  document.querySelectorAll('form.addform').forEach(function (f) {
    f.addEventListener('submit', function () {
      var b = f.querySelector('button[type="submit"]');
      if (b) { b.disabled = true; b.textContent = 'Adding…'; }
      ggShowWorking('Adding — this can take up to a minute. Please keep this page open.');
    });
  });
  document.querySelectorAll('form.rmform').forEach(function (f) {
    f.addEventListener('submit', function () { ggShowWorking('Removing… please keep this page open.'); });
  });
})();
</script>"""


# ── Render ───────────────────────────────────────────────────────────────────────
# Admin-only invite panel; rendered into the page solely for the admin session.
INVITE_PANEL_HTML = """
    <div class="feedback">
      <h2>Invite a client</h2>
      <div class="invrow">
        <input id="inv-id" autocomplete="off" placeholder="Client ID (Pipeline person ID)">
        <button type="button" id="inv-lookup" class="btn-primary">Look up</button>
      </div>
      <p id="inv-name" class="inv-name"></p>
      <div class="invrow">
        <input id="inv-email" type="email" autocomplete="off" placeholder="client@example.com">
        <button type="button" id="inv-send" class="btn-primary">Send invite</button>
      </div>
      <span id="inv-msg" class="fr-msg"></span>
    </div>"""


def _add_form(target_id=None):
    """Add a holding OR a watchlist item. A segmented Holding|Watchlist toggle
    (Holding selected by default) morphs the fields via JS: in watchlist mode Shares,
    Structure and Transaction date hide and 'Cost per share' relabels to 'Target
    Price'. pps_cost stores the cost basis (holding) or the target price (watchlist).
    target_id (admin roll-up) scopes the write to that client; None = own portfolio.
    The company datalist (id 'company-list') is emitted once per page by the caller."""
    suffix = html.escape(str(target_id)) if target_id else "self"
    structure_opts = "".join(f'<option>{s}</option>' for s in STRUCTURES)
    target_hidden = (f'<input type="hidden" name="target_client_id" value="{html.escape(str(target_id))}">'
                     if target_id else "")
    return f"""
    <div class="add">
      <form method="post" class="addform">
        <input type="hidden" name="action" value="add">
        {target_hidden}
        <div class="seg" role="radiogroup" aria-label="Entry type">
          <input type="radio" id="m-h-{suffix}" name="status" value="holding" checked>
          <label for="m-h-{suffix}">Holding</label>
          <input type="radio" id="m-w-{suffix}" name="status" value="watchlist">
          <label for="m-w-{suffix}">Watchlist</label>
        </div>
        <div class="grid">
          <div class="field f-company">
            <label>Company</label>
            <input name="company" list="company-list" required autocomplete="off"
                   placeholder="Start typing a company…">
          </div>
          <div class="field f-structure">
            <label>Structure</label>
            <select name="structure">{structure_opts}</select>
          </div>
          <div class="field f-shares">
            <label>Shares</label>
            <input type="number" name="shares" step="any" min="0" placeholder="e.g. 1500">
          </div>
          <div class="field f-cost">
            <label class="cost-label">Cost per share (Gross)</label>
            <input type="number" name="pps_cost" step="any" min="0" placeholder="Original purchase price">
          </div>
          <div class="field f-date">
            <label>Transaction date <span class="opt">(optional)</span></label>
            <input type="date" name="transaction_date">
          </div>
        </div>
        <button type="submit" class="btn-primary">Add holding</button>
      </form>
    </div>"""


def _watchlist_table(items, target_id=None, show_client_actions=True):
    """Watchlist ('tracking to buy') table: Company, Target Price (inline-editable),
    LR, Market Price, Recent Developments, actions. Never counted in portfolio totals.
    The Market Price cell turns green when it has reached / fallen below the Target
    Price. Actions: Get Offers (client view only), 'I bought this' convert, remove."""
    rows = ""
    for h in items:
        v = value_holding(h)
        hp, target = v["hiive_price"], h.get("pps_cost")
        hit = hp is not None and target is not None and hp <= target
        lr_title = f'As of {v["last_round_as_of"]}' if v["last_round_as_of"] else None
        price_title = f'As of {v["as_of"]}' if v["as_of"] else None
        price_cell = (f'<td class="num wl-hit" title="At or below your target">{_money(hp)} ●</td>'
                      if hit else _hover_cell(_money(hp), price_title))
        cat = company_catalysts().get(str(h.get("company_id", "")))
        cat_cell = (f'<td class="catalyst has-cat">{html.escape(cat)}</td>'
                    if cat else '<td class="catalyst empty-cat">—</td>')
        hid = html.escape(h.get("holding_id", ""))
        tgt_hidden = (f'<input type="hidden" name="target_client_id" value="{html.escape(str(target_id))}">'
                      if target_id else "")
        tgt_data = f' data-target-client-id="{html.escape(str(target_id))}"' if target_id else ""
        acts = ""
        if show_client_actions:
            acts += f'<button type="button" class="act" data-act="get_offers" data-hid="{hid}">Get Offers</button>'
        acts += f'<button type="button" class="act convert-btn" data-hid="{hid}"{tgt_data}>I bought this</button>'
        acts += (f'<form method="post" class="rmform" onsubmit="return confirm(\'Remove from watchlist?\')">'
                 f'<input type="hidden" name="action" value="remove">'
                 f'<input type="hidden" name="holding_id" value="{hid}">{tgt_hidden}'
                 f'<button type="submit" class="x" title="Remove">&times;</button></form>')
        rows += f"""
        <tr>
          <td class="co">{html.escape(h.get("company_name", ""))}</td>
          {_edit_cell(h.get("holding_id", ""), "pps_cost", target, _money(target), title="Target price", target=target_id)}
          {_hover_cell(_money(v["last_round"]), lr_title)}
          {price_cell}
          {cat_cell}
          <td class="acts">{acts}</td>
        </tr>"""
    return f"""
    <h2 class="wl-head">Watchlist</h2>
    <p class="subtitle">Companies you're tracking to buy — the market price turns green when it reaches your target.</p>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Company</th><th class="num">Target Price</th><th class="num">LR</th>
          <th class="num">Market Price&#42;</th><th class="catalyst">Recent Developments</th><th></th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    </div>"""


def render_portfolio(portfolio, is_admin=False):
    all_items = portfolio.get("holdings", [])
    held = [h for h in all_items if h.get("status") != "watchlist"]
    watch = [h for h in all_items if h.get("status") == "watchlist"]
    title = portfolio.get("display_name") or "Your portfolio"
    invite_panel = INVITE_PANEL_HTML if is_admin else ""
    rows = ""
    tot_current = tot_cost = 0.0
    have_any_value = False
    have_indirect = False

    for h in held:
        v = value_holding(h)
        if v["current"] is not None:
            tot_current += v["current"]
            have_any_value = True
        if v["cost"] is not None:
            tot_cost += v["cost"]

        indirect_mark = h.get("structure") in INDIRECT_STRUCTURES and v["current"] is not None
        if indirect_mark:
            have_indirect = True

        lr_title = f'As of {v["last_round_as_of"]}' if v["last_round_as_of"] else None
        price_title = f'As of {v["as_of"]}' if v["as_of"] else None

        value_cell = _money(v["current"])
        if indirect_mark:
            value_cell += '<span class="flag">*</span>'

        cost_title = f'Txn date: {h.get("transaction_date") or "—"}'

        cat = company_catalysts().get(str(h.get("company_id", "")))
        cat_cell = (f'<td class="catalyst has-cat">{html.escape(cat)}</td>'
                    if cat else '<td class="catalyst empty-cat">—</td>')

        rows += f"""
        <tr>
          <td class="co">{html.escape(h.get("company_name", ""))}
              <span class="struct">{html.escape(h.get("structure", ""))}</span></td>
          {_edit_cell(h.get("holding_id", ""), "shares", h.get("shares"), _shares(h.get("shares")))}
          {_edit_cell(h.get("holding_id", ""), "pps_cost", h.get("pps_cost"), _money(h.get("pps_cost")), title=cost_title)}
          {_hover_cell(_money(v["last_round"]), lr_title)}
          {_hover_cell(_money(v["hiive_price"]), price_title)}
          <td class="num">{value_cell}</td>
          <td class="num {_gl_class(v["gl"])}">{_money(v["gl"])}</td>
          {cat_cell}
          <td class="acts">
            <button type="button" class="act" data-act="get_bids" data-hid="{html.escape(h.get("holding_id",""))}">Get Bids</button>
            <button type="button" class="act" data-act="get_offers" data-hid="{html.escape(h.get("holding_id",""))}">Get Offers</button>
            <form method="post" class="rmform" onsubmit="return confirm('Remove this holding?')">
              <input type="hidden" name="action" value="remove">
              <input type="hidden" name="holding_id" value="{html.escape(h.get("holding_id",""))}">
              <button type="submit" class="x" title="Remove">&times;</button>
            </form>
          </td>
        </tr>"""

    if not held:
        rows = """
        <tr><td colspan="9" class="empty">No holdings yet. Add one below to see it valued.</td></tr>"""

    total_gl = (tot_current - tot_cost) if (have_any_value and tot_cost) else None
    totals = ""
    if have_any_value:
        totals = f"""
        <tr class="totals">
          <td>Portfolio</td><td></td><td></td><td></td><td></td>
          <td class="num">{_money(tot_current)}</td>
          <td class="num {_gl_class(total_gl)}">{_money(total_gl)}</td>
          <td></td>
          <td></td>
        </tr>"""

    indirect_note = ""
    if have_indirect:
        indirect_note = """
        <p class="note">* Fund/SPV and Forward positions are shown at the
        underlying company's per-share mark. Fund-level fees and carry are not
        reflected, so the figure overstates the position's net value.</p>"""

    options = "".join(
        f'<option value="{html.escape(label)}"></option>'
        for label in picker_index()
    )
    watchlist_section = _watchlist_table(watch, show_client_actions=True) if watch else ""

    body = f"""
    <h1>{html.escape(title)}</h1>
    <p class="subtitle">Indicative valuations against the latest market-price estimate.</p>

    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Company</th><th class="num">Shares</th><th class="num">Cost Basis / sh</th>
          <th class="num">LR</th><th class="num">Market Price&#42;</th><th class="num">Value</th>
          <th class="num">Gain / Loss</th><th class="catalyst">Recent Developments</th><th></th>
        </tr>
      </thead>
      <tbody>{rows}{totals}</tbody>
    </table>
    </div>
    {indirect_note}

    <p class="disclaimer">&#42; Market Price is an indicative third-party estimate,
    not a Rainmaker Securities valuation, and reflects the as-of date shown on hover. Figures
    are for tracking only and are not an offer, a quote, or investment advice.</p>

    {watchlist_section}

    <h2>Add to your portfolio</h2>
    <datalist id="company-list">{options}</datalist>
    {_add_form()}

    <div class="feedback">
      <h2>Feature Request</h2>
      <textarea id="fr-text" rows="3" placeholder="Let us know what would make this more useful for you."></textarea>
      <div><button type="button" id="fr-send" class="btn-primary">Send</button>
      <span id="fr-msg" class="fr-msg"></span></div>
    </div>
    {invite_panel}"""
    return html_response(body + EDIT_SCRIPT)


# ── Admin roll-up ─────────────────────────────────────────────────────────────────
# An admin-only view of EVERY client's portfolio with full edit capability: Shares
# and Cost Basis are inline-editable, holdings can be added (a per-client form) and
# removed (a per-row ×). Every control carries the block's target_client_id so the
# write lands on THAT client, never the logged-in admin's own portfolio. The admin
# gate on the write path (handler) is the security boundary. Only the client-facing
# action buttons (Get Bids / Get Offers) are intentionally omitted.
def _admin_holdings_table(portfolio, target_id):
    """The same valued table render_portfolio builds — same value_holding, _money,
    _shares, gain/loss, catalysts, indirect-mark note. Shares and Cost Basis are
    inline-editable and each row carries a remove (×) form, all tagged with target_id
    so writes land on that client. 9 cols (trailing column holds the remove button).
    Watchlist items are excluded here — they render in their own _watchlist_table."""
    holdings = [h for h in portfolio.get("holdings", []) if h.get("status") != "watchlist"]
    rows = ""
    tot_current = tot_cost = 0.0
    have_any_value = False
    have_indirect = False

    for h in holdings:
        v = value_holding(h)
        if v["current"] is not None:
            tot_current += v["current"]
            have_any_value = True
        if v["cost"] is not None:
            tot_cost += v["cost"]

        indirect_mark = h.get("structure") in INDIRECT_STRUCTURES and v["current"] is not None
        if indirect_mark:
            have_indirect = True

        lr_title = f'As of {v["last_round_as_of"]}' if v["last_round_as_of"] else None
        price_title = f'As of {v["as_of"]}' if v["as_of"] else None

        value_cell = _money(v["current"])
        if indirect_mark:
            value_cell += '<span class="flag">*</span>'

        cost_title = f'Txn date: {h.get("transaction_date") or "—"}'

        cat = company_catalysts().get(str(h.get("company_id", "")))
        cat_cell = (f'<td class="catalyst has-cat">{html.escape(cat)}</td>'
                    if cat else '<td class="catalyst empty-cat">—</td>')

        rows += f"""
        <tr>
          <td class="co">{html.escape(h.get("company_name", ""))}
              <span class="struct">{html.escape(h.get("structure", ""))}</span></td>
          {_edit_cell(h.get("holding_id", ""), "shares", h.get("shares"), _shares(h.get("shares")), target=target_id)}
          {_edit_cell(h.get("holding_id", ""), "pps_cost", h.get("pps_cost"), _money(h.get("pps_cost")), title=cost_title, target=target_id)}
          {_hover_cell(_money(v["last_round"]), lr_title)}
          {_hover_cell(_money(v["hiive_price"]), price_title)}
          <td class="num">{value_cell}</td>
          <td class="num {_gl_class(v["gl"])}">{_money(v["gl"])}</td>
          {cat_cell}
          <td class="acts">
            <form method="post" class="rmform" onsubmit="return confirm('Remove this holding?')">
              <input type="hidden" name="action" value="remove">
              <input type="hidden" name="holding_id" value="{html.escape(h.get("holding_id",""))}">
              <input type="hidden" name="target_client_id" value="{html.escape(str(target_id))}">
              <button type="submit" class="x" title="Remove">&times;</button>
            </form>
          </td>
        </tr>"""

    total_gl = (tot_current - tot_cost) if (have_any_value and tot_cost) else None
    totals = ""
    if have_any_value:
        totals = f"""
        <tr class="totals">
          <td>Portfolio</td><td></td><td></td><td></td><td></td>
          <td class="num">{_money(tot_current)}</td>
          <td class="num {_gl_class(total_gl)}">{_money(total_gl)}</td>
          <td></td>
          <td></td>
        </tr>"""

    indirect_note = ""
    if have_indirect:
        indirect_note = """
        <p class="note">* Fund/SPV and Forward positions are shown at the
        underlying company's per-share mark. Fund-level fees and carry are not
        reflected, so the figure overstates the position's net value.</p>"""

    return f"""
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Company</th><th class="num">Shares</th><th class="num">Cost Basis / sh</th>
          <th class="num">LR</th><th class="num">Market Price&#42;</th><th class="num">Value</th>
          <th class="num">Gain / Loss</th><th class="catalyst">Recent Developments</th><th></th>
        </tr>
      </thead>
      <tbody>{rows}{totals}</tbody>
    </table>
    </div>
    {indirect_note}"""


def render_admin_overview(admin_id):
    """Admin-only roll-up of every client's portfolio, with full edit capability.
    Lists all portfolio objects under portfolios/ in BUCKET, derives each client_id
    from the key, loads it with load_portfolio(), and renders an editable holdings
    table, a watchlist table, and an add form per client (see _admin_holdings_table /
    _watchlist_table / _add_form); every write carries that client's target_client_id.
    Each block is headed by the
    client's full name (index "name", else portfolio display_name, else first_name,
    else "Client <id>") as a mailto link, followed by the Client ID linking to that
    person's Pipeline page in a new tab. Blocks are sorted by name. admin_id isn't
    used for scoping — the admin sees everyone — but is kept for symmetry with the
    call site."""
    s3 = boto3.client("s3")
    client_ids = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix="portfolios/"):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".json"):
                cid = key[len("portfolios/"):-len(".json")]
                if cid:
                    client_ids.append(cid)

    try:
        by_id = _people_index().get("by_id", {})
    except Exception:
        by_id = {}   # index missing/unreachable: fall back to bare ids, don't break the page

    blocks = []
    for cid in client_ids:
        portfolio = load_portfolio(cid)
        rec = by_id.get(str(cid)) or {}
        email = (rec.get("email") or "").strip()
        # Full "First Last" name: prefer the index's full name, then the portfolio's
        # display_name, then the index first_name, then a bare "Client <id>". (The
        # index carries "name" only once it's been rebuilt to include it — see
        # build_people_index.py; until then non-seeded clients fall back to first_name.)
        name = ((rec.get("name") or "").strip()
                or (portfolio.get("display_name") or "").strip()
                or (rec.get("first_name") or "").strip()
                or f"Client {cid}")
        # Clicking the name opens a pre-addressed email; the Client ID opens that
        # person's main page in Pipeline in a new tab. Both are styled muted (.cname /
        # .pd-id) rather than default link-blue.
        name_html = (f'<a class="cname" href="mailto:{html.escape(email)}">{html.escape(name)}</a>'
                     if email else html.escape(name))
        pd_url = PD_PERSON_URL + urllib.parse.quote(str(cid))
        id_html = (f'<a class="pd-id" href="{html.escape(pd_url)}" target="_blank" rel="noopener">'
                   f'Client ID {html.escape(str(cid))}</a>')
        items = portfolio.get("holdings", [])
        held = [h for h in items if h.get("status") != "watchlist"]
        watch = [h for h in items if h.get("status") == "watchlist"]
        table_html = (_admin_holdings_table(portfolio, cid)
                      if held else '<p class="empty">(no holdings yet)</p>')
        watch_html = _watchlist_table(watch, target_id=cid, show_client_actions=False) if watch else ""
        blocks.append((name, f"""
    <section class="client-block" style="margin-top:2.5rem">
      <h2>{name_html}{id_html}</h2>
      {table_html}
      {watch_html}
      {_add_form(cid)}
    </section>"""))

    blocks.sort(key=lambda b: b[0].lower())

    # One shared company datalist for every per-client add form (avoids repeating the
    # full option list in each block); _add_form references it by id 'company-list'.
    company_options = "".join(
        f'<option value="{html.escape(label)}"></option>' for label in picker_index())
    body = f"""
    <h1>All client portfolios</h1>
    <p class="subtitle">Add, edit, or remove holdings and watchlist items — changes save to that client's portfolio.</p>
    <datalist id="company-list">{company_options}</datalist>
    {INVITE_PANEL_HTML}
    {"".join(block for _, block in blocks)}"""
    # INVITE_PANEL_HTML is the admin invite tool placed above the roll-up. EDIT_SCRIPT
    # wires both the invite panel and the inline-edit cells; the add/remove forms are
    # plain POSTs. Every write here carries target_client_id and is admin-gated on the
    # server, so it lands on the intended client and never leaks to non-admins.
    return html_response(body + EDIT_SCRIPT)


# ── HTML shell ───────────────────────────────────────────────────────────────────
# Quiet top nav back to the main Gracia Group properties. Same-tab links; the
# session cookie persists, so a client can leave and return without re-auth.
TOPNAV_HTML = """
    <nav class="topnav">
      <div class="navgroup">
        <a class="navbtn brand" href="https://www.graciagroup.com">Gracia Group</a>
      </div>
      <div class="navgroup">
        <a class="navbtn" href="https://trades.graciagroup.com/">Indications</a>
        <button class="navbtn navbtn-soon" type="button" disabled title="Coming soon">Download PDF</button>
      </div>
    </nav>"""

# Firm legal disclosure, pinned to the very bottom of every page.
DISCLOSURE_HTML = """
    <footer class="legal">
      <p class="lead">DISCLOSURE: Rainmaker Securities, LLC (“RMS”) is a FINRA registered broker-dealer and SIPC member. Find this broker-dealer and its agents on BrokerCheck. Our relationship summary can be found on the RMS website.</p>
      <p>RMS is engaged by its clients to make referrals to buyers or sellers of private securities (“Securities”). If such client closes a Securities transaction with a buyer or seller so referred, RMS is entitled to a success fee from the client. Such success fee may be in the form of cash or in warrants to purchase securities of the client or client’s affiliate. RMS or RMS representatives may hold equity in its issuer clients or in the issuers of securities purchased or sold by the parties to a transaction.</p>
      <p>This communication is confidential and is addressed only to its intended recipient. This communication does not represent an offer or solicitation to buy or sell Securities. Such an offer must be made via definitive legal documentation by the seller of securities.</p>
      <p>Investments in the Securities are speculative and involve a high degree of risk. An investor in the Securities should have little to no need for liquidity in the foreseeable future and have sufficient finances to withstand the loss of the entire investment.</p>
      <p>RMS does not recommend the purchase or sale of Securities. Potential buyers or sellers of the Securities should seek professional counsel prior to entering into any transaction.</p>
      <h3>Risk Factors</h3>
      <p>Investments in the Securities are speculative and involve a high degree of risk. Companies engaging in private placements may be early stage and high risk. You should be able to afford the increased risk of loss with such investments, including the potential of a total loss.</p>
      <p>An investor in the Securities should have little to no need for liquidity in the foreseeable future. Unlike an investment purchased on a stock exchange, an investment in a private placement is highly illiquid. You will most likely be investing in restricted securities, may have difficulty finding a buyer for the securities when you can resell and, as a result, may need to hold the securities indefinitely.</p>
      <p>Limited disclosure Information. Companies engaging in private placements are not required to provide the disclosure that would be required in a registered offering. You may have less information to make an informed investment decision than, for example, stock purchased on a stock exchange, including information that may help you determine whether the price asked for the investment is a fair price. Potential buyers or sellers of the Securities should seek professional counsel prior to entering into any transaction.</p>
    </footer>"""


def html_response(body_html, status=200):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gracia Group — Portfolio</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600&display=swap" rel="stylesheet">
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --ink: #16181d; --muted: #6b7280; --line: #e7e5e0;
      --bg: #f4f2ee; --card: #ffffff; --accent: #1a1a1a;
      --pos: #1f7a4d; --neg: #b23b3b;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg); color: var(--ink);
      min-height: 100vh; padding: 40px 24px;
      font-variant-numeric: tabular-nums;
    }}
    .card {{
      background: var(--card); border: 1px solid var(--line);
      border-radius: 14px; box-shadow: 0 1px 24px rgba(20,24,29,0.05);
      padding: 40px; max-width: 1120px; margin: 0 auto;
    }}
    .logo {{
      font-size: 12px; font-weight: 600; letter-spacing: 0.14em;
      text-transform: uppercase; color: var(--muted); margin-bottom: 24px;
    }}
    .topnav {{
      display: flex; justify-content: space-between; align-items: center;
      gap: 10px; flex-wrap: wrap; margin-bottom: 26px;
    }}
    .navgroup {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
    .navbtn {{
      font-size: 12px; font-weight: 600; letter-spacing: 0.03em; line-height: 1;
      color: var(--muted); text-decoration: none; background: #fff;
      padding: 8px 13px; border: 1px solid var(--line); border-radius: 8px;
      transition: color 0.15s, border-color 0.15s;
    }}
    .navbtn:hover {{ color: var(--ink); border-color: var(--muted); }}
    .navbtn.brand {{ color: var(--ink); }}
    .navbtn-soon {{ color: #b6b2aa; border-style: dashed; cursor: not-allowed; }}
    .navbtn-soon:hover {{ color: #b6b2aa; border-color: var(--line); }}
    .legal {{
      margin-top: 44px; padding-top: 28px; border-top: 1px solid var(--line);
      font-size: 11px; line-height: 1.6; color: var(--muted);
    }}
    .legal .lead {{ font-weight: 600; color: #4b4f57; }}
    .legal h3 {{
      font-family: inherit; font-size: 11px; font-weight: 700; letter-spacing: 0.08em;
      text-transform: uppercase; color: var(--ink); margin: 20px 0 8px;
    }}
    .legal p {{ margin: 0 0 10px; }}
    h1 {{ font-family: 'Fraunces', Georgia, serif; font-size: 30px; font-weight: 600; letter-spacing: -0.01em; }}
    h2 {{ font-family: 'Fraunces', Georgia, serif; font-size: 19px; font-weight: 600; margin-bottom: 16px; }}
    .subtitle {{ font-size: 14px; color: var(--muted); margin: 6px 0 26px; }}
    /* Admin roll-up heading links: muted, not default link-blue. */
    .cname {{ color: var(--ink); text-decoration: none; border-bottom: 1px solid var(--line); }}
    .cname:hover {{ border-bottom-color: var(--muted); }}
    .pd-id {{ margin-left: .6rem; font-size: .78em; font-weight: 400; color: var(--muted); text-decoration: none; }}
    .pd-id:hover {{ color: var(--ink); }}
    /* "Working" overlay while a mutating POST is in flight (add/remove/inline-edit). */
    .working-overlay {{ position: fixed; inset: 0; z-index: 1000; background: rgba(244,242,238,.9);
      display: flex; align-items: center; justify-content: center; }}
    .working-box {{ max-width: 320px; padding: 0 24px; text-align: center; color: var(--ink); font-size: 15px; line-height: 1.5; }}
    .working-box p {{ margin-top: 16px; }}
    .spinner {{ width: 38px; height: 38px; margin: 0 auto; border: 3px solid var(--line);
      border-top-color: var(--accent); border-radius: 50%; animation: ggspin .8s linear infinite; }}
    @keyframes ggspin {{ to {{ transform: rotate(360deg); }} }}
    /* Segmented Holding|Watchlist toggle in the add form. */
    .seg {{ display: inline-flex; border: 1px solid var(--line); border-radius: 9px; overflow: hidden; margin-bottom: 18px; }}
    .seg input {{ position: absolute; opacity: 0; pointer-events: none; }}
    .seg label {{ padding: 8px 18px; font-size: 13px; font-weight: 600; color: var(--muted); cursor: pointer; background: #fff; }}
    .seg label + input + label {{ border-left: 1px solid var(--line); }}
    .seg input:checked + label {{ background: var(--accent); color: #fff; }}
    /* Watchlist section + "at/below target" highlight. */
    .wl-head {{ margin-top: 34px; }}
    td.wl-hit {{ color: var(--pos); font-weight: 700; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th {{
      text-align: left; font-size: 11px; font-weight: 600; color: var(--muted);
      text-transform: uppercase; letter-spacing: 0.06em;
      padding: 0 14px 10px; border-bottom: 1px solid var(--line);
    }}
    td {{ padding: 14px; border-bottom: 1px solid var(--line); vertical-align: middle; }}
    .num {{ text-align: right; white-space: nowrap; }}
    .co {{ font-weight: 600; }}
    .struct {{
      display: inline-block; margin-left: 8px; font-weight: 500; font-size: 11px;
      color: var(--muted); background: var(--bg); padding: 2px 8px; border-radius: 6px;
    }}
    .flag {{ color: var(--muted); }}
    .pos {{ color: var(--pos); }}
    .neg {{ color: var(--neg); }}
    th.catalyst {{ text-align: left; }}
    td.catalyst {{ max-width: 240px; white-space: normal; line-height: 1.4; font-size: 13px; }}
    td.catalyst.has-cat {{
      background: #eef6f0; color: #1f5138; font-weight: 600; border-left: 2px solid var(--pos);
    }}
    td.catalyst.empty-cat {{ color: var(--muted); text-align: center; }}
    .empty {{ text-align: center; color: var(--muted); padding: 40px 14px; }}
    .totals td {{ font-weight: 700; border-top: 2px solid var(--ink); border-bottom: none; padding-top: 16px; }}
    .rm form {{ margin: 0; }}
    .rm button {{
      background: none; border: none; color: #c9c5bd; font-size: 20px;
      cursor: pointer; line-height: 1; padding: 0 4px;
    }}
    .rm button:hover {{ color: var(--neg); }}
    .note {{ font-size: 12px; color: var(--muted); margin-top: 14px; font-style: italic; }}
    .disclaimer {{
      font-size: 12px; color: var(--muted); line-height: 1.5;
      margin: 24px 0 0; padding: 14px 16px; background: var(--bg); border-radius: 10px;
    }}
    .add {{ margin-top: 40px; padding-top: 32px; border-top: 1px solid var(--line); }}
    .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px 20px; margin-bottom: 22px; }}
    .field label {{ display: block; font-size: 13px; font-weight: 600; color: #444; margin-bottom: 6px; }}
    .opt {{ font-weight: 400; color: var(--muted); }}
    input, select {{
      width: 100%; padding: 10px 14px; border: 1px solid var(--line);
      border-radius: 9px; font-size: 15px; background: #fff; color: var(--ink);
      transition: border-color 0.15s; font-family: inherit;
    }}
    input:focus, select:focus {{ outline: none; border-color: var(--accent); }}
    .btn-primary {{
      background: var(--accent); color: #fff; border: none; padding: 13px 28px;
      border-radius: 9px; font-size: 15px; font-weight: 600; cursor: pointer; width: auto;
    }}
    .btn-primary:hover {{ opacity: 0.9; }}
    @media (max-width: 600px) {{ .grid {{ grid-template-columns: 1fr; }} .card {{ padding: 24px; }} }}
    .editable {{ display: inline-block; width: 100%; cursor: pointer; border-bottom: 1px dashed transparent; }}
    .editable:hover {{ border-bottom-color: var(--muted); }}
    .cell-edit {{ width: 78px; padding: 3px 6px; font-size: 14px; text-align: right; }}
    td.acts {{ white-space: nowrap; text-align: right; }}
    td.acts .act {{
      display: block; width: 100%; margin: 0 0 4px; padding: 5px 8px;
      font-size: 11px; font-weight: 600; border-radius: 6px; cursor: pointer;
      border: 1px solid var(--line); background: #fff; color: var(--ink);
      font-family: inherit; transition: border-color 0.15s, color 0.15s;
    }}
    td.acts .act:hover {{ border-color: var(--accent); color: var(--accent); }}
    td.acts .act.done {{ color: var(--pos); border-color: var(--pos); cursor: default; }}
    td.acts .rmform {{ margin: 4px 0 0; }}
    td.acts .x {{ background: none; border: none; color: #c9c5bd; font-size: 18px; cursor: pointer; line-height: 1; padding: 0; }}
    td.acts .x:hover {{ color: var(--neg); }}
    .feedback {{ margin-top: 40px; padding-top: 32px; border-top: 1px solid var(--line); }}
    .feedback textarea {{
      width: 100%; padding: 12px 14px; border: 1px solid var(--line); border-radius: 9px;
      font-size: 15px; font-family: inherit; color: var(--ink); resize: vertical; margin-bottom: 14px;
    }}
    .feedback textarea:focus {{ outline: none; border-color: var(--accent); }}
    .fr-msg {{ margin-left: 14px; font-size: 13px; color: var(--pos); font-weight: 600; }}
    .invrow {{ display: flex; gap: 10px; align-items: center; margin-bottom: 12px; }}
    .invrow input {{ flex: 1; }}
    .inv-name {{ font-size: 13px; color: var(--muted); margin: 0 0 12px; min-height: 1em; }}
  </style>
</head>
<body>
  <div class="card">
    {TOPNAV_HTML}
    <div class="logo">Private Portfolio Snapshot &amp; Tracker</div>
    {body_html}
    {DISCLOSURE_HTML}
  </div>
</body>
</html>"""
    }


# ── Auth: magic link + signed session cookie ─────────────────────────────────────
def _b64u(b):                       # bytes -> unpadded base64url str
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64u_decode(s):                # unpadded base64url str -> bytes
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(client_id):
    """Permanent magic-link token: HMAC over the client_id."""
    sig = hmac.new(HMAC_SECRET.encode(), client_id.encode(), hashlib.sha256).digest()
    return _b64u(sig)


def verify_token(client_id, token):
    return hmac.compare_digest(make_token(client_id), token or "")


def _verify_sso_handoff(token):
    """Email if the trading site's signed, unexpired handoff verifies, else None.
    Token is base64url(f"{email}|{exp}|{sig}"), sig = HMAC-SHA256(IDENTITY_SECRET,
    f"{email}|{exp}").hexdigest(). Never raises."""
    if not (IDENTITY_SECRET and token):
        return None
    try:
        parts = _b64u_decode(token).decode().split("|")
        if len(parts) != 3:
            return None
        email, exp, sig = parts
        expected = hmac.new(IDENTITY_SECRET.encode(), f"{email}|{exp}".encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        if int(exp) < int(time.time()):
            return None
        return email
    except Exception:
        return None


def lookup_person_id_by_email(email):
    """str(person_id) for the lead whose email matches (case-insensitive) via
    people_index.json's by_email map, else None. Reads the same shared index as
    lookup_person, so the two can't diverge. Never raises."""
    target = (email or "").strip().lower()
    if not target:
        return None
    try:
        cid = _people_index().get("by_email", {}).get(target)
        return str(cid) if cid is not None else None
    except Exception:
        return None


def make_session(client_id):
    """Signed, expiring session value:  base64url(client_id|exp).base64url(sig)."""
    payload = f"{client_id}|{int(time.time()) + SESSION_DAYS * 86400}"
    p = _b64u(payload.encode())
    sig = hmac.new(HMAC_SECRET.encode(), p.encode(), hashlib.sha256).digest()
    return f"{p}.{_b64u(sig)}"


def read_session(value):
    """Return client_id if the cookie is validly signed and unexpired, else None."""
    try:
        p, s = (value or "").split(".", 1)
        expected = hmac.new(HMAC_SECRET.encode(), p.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64u(expected), s):
            return None
        client_id, exp = _b64u_decode(p).decode().split("|", 1)
        if int(exp) < int(time.time()):
            return None
        return client_id
    except Exception:
        return None


def get_cookie(event, name):
    for c in (event.get("cookies") or []):          # Function URL 2.0 payload
        if c.startswith(name + "="):
            return c[len(name) + 1:]
    hdr = (event.get("headers") or {}).get("cookie", "")
    for part in hdr.split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return None


def login_required(msg):
    return f"""
    <h1>Portfolio access</h1>
    <p class="subtitle">{html.escape(msg)}</p>
    <p class="disclaimer">Open the personal link sent to you. If your link has
    expired, contact Chad at cgracia@rainmakersecurities.com for a new one.</p>"""


# ── Routing ──────────────────────────────────────────────────────────────────────
def _parse_body(event):
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    return {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}


def lambda_handler(event, context):
    method = (event.get("requestContext", {}).get("http", {}).get("method") or "GET").upper()
    raw_path = event.get("rawPath", "/")
    qs = event.get("queryStringParameters") or {}

    # 1) Magic-link arrival: verify, set session cookie, redirect to a clean URL.
    if qs.get("client") and qs.get("token"):
        if verify_token(qs["client"], qs["token"]):
            cookie = (f"{COOKIE_NAME}={make_session(qs['client'])}; Path=/; HttpOnly; "
                      f"Secure; SameSite=Lax; Max-Age={SESSION_DAYS * 86400}")
            return {"statusCode": 303,
                    "headers": {"Location": raw_path, "Set-Cookie": cookie}, "body": ""}
        return html_response(login_required("That link isn't valid."), 403)

    # 1b) Cross-site SSO handoff from the trading site: verify the signed email,
    #     map it to a person_id, set the same session cookie. Falls through to a
    #     friendly message when the email isn't in the CRM snapshot yet.
    if qs.get("sso"):
        email = _verify_sso_handoff(qs["sso"])
        if not email:
            return html_response(login_required(
                "That portfolio link has expired — head back to the trading site "
                "and click “Your Portfolio” again."), 403)
        cid = lookup_person_id_by_email(email)
        if not cid:
            return html_response(login_required(
                "We couldn't find a portfolio linked to your email yet — please "
                "contact Chad and he'll get you set up."), 200)
        cookie = (f"{COOKIE_NAME}={make_session(cid)}; Path=/; HttpOnly; "
                  f"Secure; SameSite=Lax; Max-Age={SESSION_DAYS * 86400}")
        return {"statusCode": 303,
                "headers": {"Location": raw_path, "Set-Cookie": cookie}, "body": ""}

    # 2) Everything else requires a valid session; scope strictly to that client.
    client_id = read_session(get_cookie(event, COOKIE_NAME))
    if not client_id:
        return html_response(login_required("Please open your personal portfolio link."), 401)

    # Server-side admin gate: only this client_id may mint invites to any portfolio.
    is_admin = bool(ADMIN_CLIENT_ID) and client_id == ADMIN_CLIENT_ID

    if method == "POST":
        form = _parse_body(event)
        # Admin roll-up edits carry target_client_id to write ANOTHER client's
        # portfolio. The is_admin gate here is the security boundary: a non-admin's
        # target_client_id is ignored, so they can only ever touch their own.
        target = form.get("target_client_id")
        edit_id = target if (target and is_admin) else client_id
        portfolio = load_portfolio(edit_id)
        portfolio.setdefault("client_id", edit_id)   # ensure save targets the right key
        action = form.get("action")
        # Client action buttons + feedback: email Chad, return JSON (no reload).
        if action in ("get_bids", "get_offers"):
            notify_interest(portfolio, client_id, form.get("holding_id", ""), action)
            return _json_ok()
        if action == "feature_request":
            notify_feature(portfolio, client_id, form.get("message", ""))
            return _json_ok()
        # Admin-only invite endpoints. The gate is enforced here, not just in the UI:
        # these can mint a link to any client's portfolio, so a non-admin gets 403.
        if action == "invite_lookup":
            if not is_admin:
                return {"statusCode": 403, "headers": {"Content-Type": "application/json"},
                        "body": json.dumps({"ok": False, "error": "forbidden"})}
            target_id = form.get("target_id", "")
            result = lookup_person(target_id)
            # Surface prior-invite status so the panel can warn before a resend.
            prior = load_portfolio(target_id)
            result["invited_at"] = prior.get("invited_at")
            result["invited_email"] = prior.get("invited_email")
            return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
                    "body": json.dumps(result)}
        if action == "invite_send":
            if not is_admin:
                return {"statusCode": 403, "headers": {"Content-Type": "application/json"},
                        "body": json.dumps({"ok": False, "error": "forbidden"})}
            target_id = form.get("target_id", "")
            email = form.get("email", "")
            base_url = "https://" + event["requestContext"]["domainName"]
            send_invite(target_id, email, form.get("first_name", ""), base_url)
            # Stamp the client's portfolio so a later lookup can warn on resend.
            invited = load_portfolio(target_id)
            invited["invited_at"] = datetime.now(timezone.utc).isoformat()
            invited["invited_email"] = email
            save_portfolio(invited)
            return _json_ok()
        if action == "remove":
            remove_holding(portfolio, form.get("holding_id", ""))
        elif action == "update":
            update_holding(portfolio, form.get("holding_id", ""), form)
        elif action == "convert":
            convert_holding(portfolio, form.get("holding_id", ""), form)
        else:
            add_holding(portfolio, form)
        save_portfolio(portfolio)
        # Post/Redirect/Get so a refresh doesn't resubmit the form.
        return {"statusCode": 303, "headers": {"Location": raw_path}, "body": ""}

    if is_admin:
        return render_admin_overview(client_id)
    return render_portfolio(load_portfolio(client_id), is_admin)


# ── Local helper: seed a client's portfolio + mint their magic link ────────────────
# Usage:  python lambda_function.py <person_id> <display_name> <base_url>
# <person_id> is the opaque Pipeline person_id used as the client key.
# Seeds portfolios/<person_id>.json with an empty portfolio ONLY if it doesn't
# already exist, so re-minting a link never overwrites real holdings.
# HMAC_SECRET must match production (export it before running).
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("usage: python lambda_function.py <person_id> <display_name> <base_url>")
        sys.exit(1)
    cid, display_name, base = sys.argv[1], sys.argv[2], sys.argv[3]

    # Seed an empty portfolio only if one doesn't already exist.
    s3 = boto3.client("s3")
    try:
        s3.head_object(Bucket=BUCKET, Key=_key(cid))
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "NotFound", "404"):
            save_portfolio({"client_id": cid, "display_name": display_name, "holdings": []})
        else:
            raise

    print(f"{base.rstrip('/')}/?client={urllib.parse.quote(cid)}&token={make_token(cid)}")
