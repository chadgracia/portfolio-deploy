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
from botocore.exceptions import ClientError

# ── Config ────────────────────────────────────────────────────────────────────
BUCKET       = "gracia-portfolios"                       # per-client portfolio storage
HMAC_SECRET  = os.environ.get("HMAC_SECRET", "change-me-in-env")  # set in Lambda env
COOKIE_NAME  = "gg_session"
SESSION_DAYS = 30

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
    structure = form.get("structure", "None")
    if structure not in STRUCTURES:
        structure = "None"
    txn = (form.get("transaction_date") or "").strip() or None
    now = datetime.now(timezone.utc).isoformat()
    portfolio["holdings"].append({
        "holding_id": "hld_" + uuid.uuid4().hex[:8],
        "company_id": company_id,
        "company_name": tracked_companies()[company_id],
        "shares": _to_float(form.get("shares")),
        "pps_cost": _to_float(form.get("pps_cost")),   # Gross PPS the client paid
        "structure": structure,
        "transaction_date": txn,                       # optional, manual
        "created_at": now,
        "updated_at": now,
    })


def remove_holding(portfolio, holding_id):
    portfolio["holdings"] = [
        h for h in portfolio["holdings"] if h.get("holding_id") != holding_id
    ]


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


def _edit_cell(holding_id, field, value, display, title=None):
    t = f' title="{html.escape(title)}"' if title else ""
    return (
        f'<td class="num"{t}><span class="editable" '
        f'data-holding-id="{html.escape(holding_id)}" '
        f'data-field="{field}" data-value="{html.escape(_raw(value))}">{display}</span></td>'
    )


# ── Inline-edit script (click a Shares or Cost cell; Enter saves, Esc cancels) ─────
EDIT_SCRIPT = """<script>
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
</script>"""


# ── Render ───────────────────────────────────────────────────────────────────────
def render_portfolio(portfolio):
    holdings = portfolio.get("holdings", [])
    title = portfolio.get("display_name") or "Your portfolio"
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
          {_edit_cell(h.get("holding_id", ""), "shares", h.get("shares"), _shares(h.get("shares")))}
          {_edit_cell(h.get("holding_id", ""), "pps_cost", h.get("pps_cost"), _money(h.get("pps_cost")), title=cost_title)}
          {_hover_cell(_money(v["last_round"]), lr_title)}
          {_hover_cell(_money(v["hiive_price"]), price_title)}
          <td class="num">{value_cell}</td>
          <td class="num {_gl_class(v["gl"])}">{_money(v["gl"])}</td>
          {cat_cell}
          <td class="rm">
            <form method="post" onsubmit="return confirm('Remove this holding?')">
              <input type="hidden" name="action" value="remove">
              <input type="hidden" name="holding_id" value="{html.escape(h.get("holding_id",""))}">
              <button type="submit" title="Remove">&times;</button>
            </form>
          </td>
        </tr>"""

    if not holdings:
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
    structure_opts = "".join(f'<option>{s}</option>' for s in STRUCTURES)

    body = f"""
    <h1>{html.escape(title)}</h1>
    <p class="subtitle">Indicative valuations against the latest market-price estimate.</p>

    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Company</th><th class="num">Shares</th><th class="num">Cost / sh</th>
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

    <div class="add">
      <h2>Add a holding</h2>
      <form method="post" class="addform">
        <input type="hidden" name="action" value="add">
        <div class="grid">
          <div class="field">
            <label>Company</label>
            <input name="company" list="company-list" required autocomplete="off"
                   placeholder="Start typing a company…">
            <datalist id="company-list">{options}</datalist>
          </div>
          <div class="field">
            <label>Structure</label>
            <select name="structure">{structure_opts}</select>
          </div>
          <div class="field">
            <label>Shares</label>
            <input type="number" name="shares" step="any" min="0" placeholder="e.g. 1500">
          </div>
          <div class="field">
            <label>Cost per share (Gross)</label>
            <input type="number" name="pps_cost" step="any" min="0" placeholder="e.g. 37.86">
          </div>
          <div class="field">
            <label>Transaction date <span class="opt">(optional)</span></label>
            <input type="date" name="transaction_date">
          </div>
        </div>
        <button type="submit" class="btn-primary">Add holding</button>
      </form>
    </div>"""
    return html_response(body + EDIT_SCRIPT)


# ── HTML shell ───────────────────────────────────────────────────────────────────
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
      padding: 40px; max-width: 940px; margin: 0 auto;
    }}
    .logo {{
      font-size: 12px; font-weight: 600; letter-spacing: 0.14em;
      text-transform: uppercase; color: var(--muted); margin-bottom: 24px;
    }}
    h1 {{ font-family: 'Fraunces', Georgia, serif; font-size: 30px; font-weight: 600; letter-spacing: -0.01em; }}
    h2 {{ font-family: 'Fraunces', Georgia, serif; font-size: 19px; font-weight: 600; margin-bottom: 16px; }}
    .subtitle {{ font-size: 14px; color: var(--muted); margin: 6px 0 26px; }}
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
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">Private Portfolio Snapshot &amp; Tracker</div>
    {body_html}
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

    # 2) Everything else requires a valid session; scope strictly to that client.
    client_id = read_session(get_cookie(event, COOKIE_NAME))
    if not client_id:
        return html_response(login_required("Please open your personal portfolio link."), 401)

    if method == "POST":
        form = _parse_body(event)
        portfolio = load_portfolio(client_id)
        action = form.get("action")
        if action == "remove":
            remove_holding(portfolio, form.get("holding_id", ""))
        elif action == "update":
            update_holding(portfolio, form.get("holding_id", ""), form)
        else:
            add_holding(portfolio, form)
        save_portfolio(portfolio)
        # Post/Redirect/Get so a refresh doesn't resubmit the form.
        return {"statusCode": 303, "headers": {"Location": raw_path}, "body": ""}

    return render_portfolio(load_portfolio(client_id))


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
