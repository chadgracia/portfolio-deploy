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
import re
import time
import base64
import hmac
import hashlib
import html
import urllib.parse
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

# ── Config ────────────────────────────────────────────────────────────────────
BUCKET       = "gracia-portfolios"                       # per-client portfolio storage
HMAC_SECRET  = os.environ.get("HMAC_SECRET", "change-me-in-env")  # set in Lambda env
IDENTITY_SECRET = os.environ.get("IDENTITY_SECRET", "")  # shared with trades-gracia-web; verifies the SSO handoff
LOI_TOKEN_SECRET = os.environ.get("LOI_TOKEN_SECRET", "")  # shared with the LOI signing lambda; signs its deal links
COOKIE_NAME  = "gg_session"
SESSION_DAYS = 365

# The public front door. CloudFront serves this name and routes to the same set of
# Lambdas on a path prefix (/bid/, /update/, /loi/, /deal/), so every link handed to
# a client is built from here rather than from a raw Function URL — including the
# self-referencing ones, which would otherwise inherit whichever host the admin who
# generated them happened to be browsing. The trailing slash on each prefix is load-
# bearing: the behaviours match /bid/* , so /bid?name=... would miss them.
DESK_URL = "https://desk.graciagroup.com"

# Admin gate: the client_ids allowed to invite others. Set in the Lambda env as a
# comma-separated list ("123" or "123,456"); blank entries and stray spaces are ignored.
ADMIN_CLIENT_IDS = {p.strip() for p in os.environ.get("ADMIN_CLIENT_ID", "").split(",")
                    if p.strip()}

# A second, independent cookie recording that THIS BROWSER belongs to an admin.
# The session cookie says which client's data you're looking at and gets replaced
# every time a magic link is opened; this one says who you are and survives that,
# so opening a client's link no longer signs the admin out of their own tools.
ADMIN_COOKIE_NAME = "gg_admin"
ADMIN_DAYS        = 365

# Pipeline (PD) person page; the admin roll-up links each Client ID here (new tab).
PD_PERSON_URL = "https://app.pipelinecrm.com/people/"

# The Lambda that rebuilds interest_people.json (buy/sell interest by company). It
# runs on a daily schedule; the invites page can also drive it on demand, which
# needs lambda:InvokeFunction on this function in the portfolio's execution role.
HOLDER_COUNTS_FUNCTION = "holder-counts"
HOLDER_COUNTS_REGION   = "us-east-1"

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

# Holding `status` values written by the app (add_holding / convert_holding / the
# add-form radios). Records written before this field existed lack it entirely;
# _holding_status() below supplies the value and infers a default for those.
VALID_STATUSES = {"holding", "watchlist"}


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

# ── Pipeline CRM write path (the Build Watchlist dual write) ──────────────────────
# Constants + helpers lifted verbatim from interest-update-form/lambda_function.py,
# whose JWT (pipeline-token/pipeline-jwt.json) already has person-update scope. The
# payload shapes below mirror that Lambda's proven person-update call exactly.
PIPELINE_JWT_BUCKET = "pipeline-token"
PIPELINE_JWT_KEY    = "pipeline-jwt.json"
BUY_INTEREST_FIELD  = "custom_label_3322093"
SELL_INTEREST_FIELD = "custom_label_3759156"
BROADCAST_FIELD     = "custom_label_3774841"   # YES = 6535328, NO = 6535329
BROADCAST_YES       = 6535328
BROADCAST_NO        = 6535329
BUY_INTEREST_LABEL_ID  = 3322093   # dropdown-definition ids for load_security_maps()
SELL_INTEREST_LABEL_ID = 3759156
# S3-only preference options (per the prefs split: structure + fees never go to CRM).
WL_STRUCTURES = ["Direct", "Fund", "Forward"]
WL_FEES       = ["Management", "Carry"]

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


def display_name(client_id):
    """Best-effort human name for a client id, for the "viewing as" bar. Falls back
    to the id itself so the bar always renders. Never raises."""
    try:
        rec = _people_index().get("by_id", {}).get(str(client_id)) or {}
        name = (rec.get("name") or rec.get("first_name") or "").strip()
        if name:
            return name
    except Exception as e:
        print(f"display_name failed: {e}")
    return f"client {client_id}"


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
    # side (buy/sell) only applies to watchlist entries; holdings leave it None.
    side = form.get("side") if (status == "watchlist" and form.get("side") in ("buy", "sell")) else None
    txn = (form.get("transaction_date") or "").strip() or None
    now = datetime.now(timezone.utc).isoformat()
    # Mark at add time, so we can later show movement since the item was added.
    info = company_prices().get(company_id)
    portfolio["holdings"].append({
        "holding_id": "hld_" + uuid.uuid4().hex[:8],
        "company_id": company_id,
        "company_name": tracked_companies()[company_id],
        "status": status,                              # "holding" or "watchlist"
        "side": side,                                  # "buy"/"sell" for watchlist, else None
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
        # Capture the entry mark at the move-to-holdings step if we never got one at
        # add time (e.g. the company had no Hiive Price when it was first watchlisted).
        # Don't clobber an existing snapshot.
        if h.get("price_at_add") is None:
            info = company_prices().get(h.get("company_id"))
            h["price_at_add"] = info["hiive_price"] if info else None
        h["updated_at"] = datetime.now(timezone.utc).isoformat()
        break


def _holding_status(h):
    """The holding's status, tolerant of records written before the field existed.
    Explicit valid value wins; otherwise infer — a position with shares is a
    "holding", one without is a "watchlist" entry. Never raises / never returns an
    unexpected value, so legacy files render instead of dropping or throwing."""
    s = h.get("status")
    if s in VALID_STATUSES:
        return s
    return "holding" if h.get("shares") is not None else "watchlist"


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


# ── Pipeline CRM helpers (lifted verbatim from interest-update-form) ──────────────
_pipeline_security_cache = None   # load_security_maps() result, cached on the warm instance


def get_jwt():
    s3 = boto3.client("s3")
    obj = s3.get_object(Bucket=PIPELINE_JWT_BUCKET, Key=PIPELINE_JWT_KEY)
    return json.loads(obj["Body"].read())["jwt"]


def call_pipeline_api(method, endpoint, payload=None, jwt=None):
    base = "https://api.pipelinecrm.com/api/v3"
    url = f"{base}{endpoint}"
    headers = {"Authorization": f"Bearer {jwt}", "Content-Type": "application/json"}
    data = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return {"status": r.status, "data": json.loads(r.read().decode())}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "data": e.read().decode()}
    except Exception as e:
        return {"status": 500, "data": str(e)}


def load_security_maps(jwt):
    """{'buy'|'sell': {'id_to_name': {option_id: name}, 'name_to_id': {lower_name: option_id}}}.
    The interest fields store dropdown option ids, not names; this is the only source
    of the valid/writable company set, so the Build Watchlist chips come from here."""
    global _pipeline_security_cache
    if _pipeline_security_cache is not None:
        return _pipeline_security_cache
    out = {}
    for key, label_id in [("buy", BUY_INTEREST_LABEL_ID), ("sell", SELL_INTEREST_LABEL_ID)]:
        result = call_pipeline_api(
            "GET", f"/admin/person_custom_field_labels/{label_id}.json", jwt=jwt)
        entries = []
        if result["status"] == 200:
            data = result["data"]
            entries = (data.get("entry") or data).get("custom_field_label_dropdown_entries", [])
        id_to_name = {int(e["id"]): e["name"] for e in entries}
        name_to_id = {e["name"].strip().lower(): int(e["id"]) for e in entries}
        out[key] = {"id_to_name": id_to_name, "name_to_id": name_to_id}
    _pipeline_security_cache = out
    return out


def cf_id_list(cf_value):
    """Normalise a multi-select custom_field value into a list of ints (lifted)."""
    if cf_value is None or cf_value == "":
        return []
    if isinstance(cf_value, list):
        out = []
        for v in cf_value:
            try:
                out.append(int(v))
            except (ValueError, TypeError):
                pass
        return out
    try:
        return [int(cf_value)]
    except (ValueError, TypeError):
        return []


# ── Build Watchlist dual write (CRM interest + S3 watchlist) ──────────────────────
def _company_id_by_name():
    """{lower(name): company_id} from tracked_companies(), to join a security-interest
    OPTION (name-keyed in load_security_maps) to a CRM company_id for S3 + pricing.
    The interest options carry no company_id, so the join is deliberately by name."""
    return {name.strip().lower(): cid for cid, name in tracked_companies().items()}


def _dedup_ints(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _crm_set_interest(person_id, side, option_ids, notify, jwt, mode="replace"):
    """Shared CRM primitive — the ONLY place a person's interest is written, so the
    grid and the one-off can't diverge. Sets the side's buy/sell interest field (mode
    "replace" = exactly option_ids; "merge" = union with current) and optionally
    Broadcast, via the exact lifted payload: PUT /people/{id}.json with
    {"person": {"custom_fields": {FIELD: [ids], BROADCAST_FIELD: id}}}. The other side
    is never included, so it stays untouched. Returns the call_pipeline_api result."""
    field = BUY_INTEREST_FIELD if side == "buy" else SELL_INTEREST_FIELD
    want = _dedup_ints(int(o) for o in option_ids)
    if mode == "merge":
        cur = call_pipeline_api("GET", f"/people/{person_id}.json", jwt=jwt)
        cur_cf = cur["data"].get("custom_fields", {}) if cur.get("status") == 200 and isinstance(cur.get("data"), dict) else {}
        new_ids = _dedup_ints(cf_id_list(cur_cf.get(field)) + want)
    else:
        new_ids = want
    custom = {field: new_ids}
    if notify is not None:
        custom[BROADCAST_FIELD] = BROADCAST_YES if notify else BROADCAST_NO
    res = call_pipeline_api("PUT", f"/people/{person_id}.json",
                            {"person": {"custom_fields": custom}}, jwt=jwt)
    if res.get("status") != 200:
        print(f"CRM interest write failed: side={side} status={res.get('status')} {res.get('data')}")
    return res


def save_watchlist_selection(portfolio, person_id, side, option_ids, structures, fees,
                             notify, jwt, mode="replace", target_price=None):
    """The single CRM+S3 write both the Build Watchlist grid and the per-holding
    one-off route through, so the two entry points can't diverge.

    side: "buy" | "sell". option_ids: CRM interest OPTION ids (ints) for that side.
    mode "replace" sets the side's interest to exactly option_ids (the grid is
    pre-filled, so the checked set is the complete intended list); "merge" unions with
    the current set (one-off adds). The OTHER side is never touched.

      CRM: via _crm_set_interest (Broadcast only when notify is not None).
      S3:  reconcile this side's watchlist rows to the resolved companies, tagged with
           side/structures/fees (new rows carry target_price as pps_cost). A pick
           already held annotates the holding (no dup row); a pick with no company_id
           is CRM-only and reported under "gaps".

    Returns {"crm_ok", "crm_status", "added", "removed", "annotated", "gaps"}."""
    sec = load_security_maps(jwt)
    id_to_name = sec.get(side, {}).get("id_to_name", {})
    name_to_cid = _company_id_by_name()

    want = _dedup_ints(int(o) for o in option_ids)
    crm_want = want
    if mode == "replace":
        # "$"-suffix options are public-market entries: the grid never offers them, so
        # `want` can never include one. Without this, "replace" would wipe any such
        # interest the client already has in CRM the moment they save anything else on
        # this side — it must pass through completely untouched.
        public_ids = {oid for oid, nm in id_to_name.items() if nm.strip().endswith("$")}
        if public_ids:
            cur_person = call_pipeline_api("GET", f"/people/{person_id}.json", jwt=jwt)
            cur_cf = (cur_person["data"].get("custom_fields", {})
                      if cur_person.get("status") == 200 and isinstance(cur_person.get("data"), dict)
                      else {})
            field = BUY_INTEREST_FIELD if side == "buy" else SELL_INTEREST_FIELD
            preserved_public = [i for i in cf_id_list(cur_cf.get(field)) if i in public_ids]
            crm_want = _dedup_ints(want + preserved_public)

    res = _crm_set_interest(person_id, side, crm_want, notify, jwt, mode)
    crm_ok = res.get("status") == 200

    # ---- S3: resolve picks to company_ids, reconcile this side's watchlist rows ----
    now = datetime.now(timezone.utc).isoformat()
    holdings = portfolio.setdefault("holdings", [])

    picks = {}   # company_id(str) -> {name, option_id}
    gaps = []    # option names with no tracked company_id (CRM written, no S3 row)
    for oid in want:
        name = id_to_name.get(oid, f"#{oid}")
        cid = name_to_cid.get(name.strip().lower())
        if cid is None:
            gaps.append(name)
        else:
            picks[str(cid)] = {"name": name, "option_id": oid}

    added, removed, annotated = [], [], []

    def _annotate(h, info):
        h["interest_side"] = side
        h["interest_structures"] = structures
        h["interest_fees"] = fees
        h["interest_option_id"] = info["option_id"]
        h["updated_at"] = now

    seen = set()
    for h in holdings:
        cid = str(h.get("company_id"))
        st = _holding_status(h)
        if st == "holding" and cid in picks:
            _annotate(h, picks[cid]); seen.add(cid); annotated.append(picks[cid]["name"])
        elif st == "watchlist" and h.get("side") == side:
            if cid in picks and cid not in seen:
                _annotate(h, picks[cid]); seen.add(cid)   # keep + refresh prefs
            elif (h.get("company_name") or "").strip().endswith("$"):
                pass  # public-market row: invisible to this grid, never dropped
            elif mode == "replace" and cid not in picks:
                h["_drop"] = True; removed.append(h.get("company_name") or cid)

    portfolio["holdings"] = [h for h in holdings if not h.get("_drop")]

    for cid, info in picks.items():
        if cid in seen:
            continue
        mark = company_prices().get(cid)
        portfolio["holdings"].append({
            "holding_id": "hld_" + uuid.uuid4().hex[:8],
            "company_id": cid,
            "company_name": info["name"],
            "status": "watchlist",
            "side": side,
            "structures": structures,
            "fees": fees,
            "interest_option_id": info["option_id"],
            "shares": None,
            "pps_cost": target_price,
            "price_at_add": mark["hiive_price"] if mark else None,
            "created_at": now,
            "updated_at": now,
        })
        added.append(info["name"])

    return {"crm_ok": crm_ok, "crm_status": res.get("status"),
            "added": added, "removed": removed, "annotated": annotated, "gaps": gaps}


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
    """Add a holding. Watchlist/buy-sell interest is handled separately on the Build
    Watchlist page, so this form is holdings-only — pps_cost is the cost basis.
    target_id (admin roll-up) scopes the write to that client; None = own portfolio.
    The company datalist (id 'company-list') is emitted once per page by the caller."""
    structure_opts = "".join(f'<option>{s}</option>' for s in STRUCTURES)
    target_hidden = (f'<input type="hidden" name="target_client_id" value="{html.escape(str(target_id))}">'
                     if target_id else "")
    return f"""
    <div class="add">
      <form method="post" class="addform">
        <input type="hidden" name="action" value="add">
        {target_hidden}
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
        <div class="add-actions">
          <button type="submit" class="btn-primary">Add holding</button>
        </div>
      </form>
    </div>"""


def _watchlist_table(items, target_id=None, show_client_actions=True, with_head=True):
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
    head = ("""
    <h2 class="wl-head">Watchlist</h2>
    <p class="subtitle">Companies you're tracking to buy — the market price turns green when it reaches your target.</p>"""
            if with_head else "")
    return f"""{head}
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


def render_portfolio(portfolio, is_admin=False, client_id=None):
    client_id = client_id or portfolio.get("client_id")
    all_items = portfolio.get("holdings", [])
    held = [h for h in all_items if _holding_status(h) != "watchlist"]
    watch = [h for h in all_items if _holding_status(h) == "watchlist"]
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
    build_btn = '<a class="btn-secondary" href="?view=watchlist">+ Build / edit watchlist</a>'
    if watch:
        wl_body = _watchlist_table(watch, show_client_actions=True, with_head=False)
    else:
        wl_body = ('<p class="empty-state">You\'re not tracking any companies yet. '
                   'Build a watchlist to get buy/sell market updates and tell us what you\'re looking for.</p>')
    watchlist_section = f"""
    <div class="section-head">
      <h2>Watchlist</h2>
      {build_btn}
    </div>
    <p class="subtitle">Companies you're tracking to buy — the market price turns green when it reaches your target.</p>
    {wl_body}"""

    body = f"""
    <h1>{html.escape(title)}</h1>
    <p class="subtitle">Indicative valuations against the latest market-price estimate.</p>

    <h2 class="sec">Holdings</h2>
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

    <datalist id="company-list">{options}</datalist>
    <details class="add-holding">
      <summary class="btn-secondary add-toggle">+ Add a holding</summary>
      {_add_form()}
    </details>

    {watchlist_section}

    <div class="feedback">
      <h2>Feature Request</h2>
      <textarea id="fr-text" rows="3" placeholder="Let us know what would make this more useful for you."></textarea>
      <div><button type="button" id="fr-send" class="btn-primary">Send</button>
      <span id="fr-msg" class="fr-msg"></span></div>
    </div>
    {invite_panel}"""
    return html_response(body + EDIT_SCRIPT, client_id=client_id)


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
    holdings = [h for h in portfolio.get("holdings", []) if _holding_status(h) != "watchlist"]
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
        held = [h for h in items if _holding_status(h) != "watchlist"]
        watch = [h for h in items if _holding_status(h) == "watchlist"]
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


# ── Build Watchlist grid (multi-select → CRM interest + S3 watchlist) ─────────────
# Toggle the visible company group with the Buy/Sell radio; show a working overlay on
# submit (the dual write does a couple of CRM round-trips).
WL_SCRIPT = """<script>
(function () {
  var groups = {buy: document.getElementById('wl-group-buy'),
                sell: document.getElementById('wl-group-sell')};
  document.querySelectorAll('input[name="side"]').forEach(function (r) {
    r.addEventListener('change', function () {
      if (groups.buy)  groups.buy.style.display  = this.value === 'buy'  ? '' : 'none';
      if (groups.sell) groups.sell.style.display = this.value === 'sell' ? '' : 'none';
    });
  });
  // Per side: default to highlighted (recent-activity) companies; the search box
  // reveals matches across ALL companies, and "Show all" drops the filter. Checked
  // companies always stay visible so a selection can't be hidden out of the form.
  function setupSide(side) {
    var row = document.getElementById('wl-chips-' + side);
    if (!row) return;
    var chips = Array.prototype.slice.call(row.querySelectorAll('.wchip'));
    var search = document.querySelector('.wl-search[data-side="' + side + '"]');
    var btn = document.querySelector('.wl-showall[data-side="' + side + '"]');
    var hint = document.querySelector('.wl-hint[data-side="' + side + '"]');
    var showAll = false;
    function apply() {
      var q = search ? search.value.trim().toLowerCase() : '';
      chips.forEach(function (chip) {
        var cb = chip.querySelector('input');
        var match = chip.getAttribute('data-name').indexOf(q) !== -1;
        var show = cb.checked || (q ? match : (showAll || chip.getAttribute('data-hl') === '1'));
        chip.style.display = show ? '' : 'none';
      });
      if (hint) hint.style.display = (q || showAll) ? 'none' : '';
    }
    if (search) search.addEventListener('input', apply);
    if (btn) btn.addEventListener('click', function () {
      showAll = !showAll;
      btn.textContent = showAll ? 'Show highlighted' : 'Show all';
      apply();
    });
    row.addEventListener('change', apply);
    apply();
  }
  setupSide('buy');
  setupSide('sell');

  var form = document.querySelector('form.wl-form');
  if (form) form.addEventListener('submit', function () {
    var b = form.querySelector('button[type="submit"]');
    if (b) { b.disabled = true; b.textContent = 'Sending…'; }
    var ov = document.createElement('div');
    ov.className = 'working-overlay';
    ov.innerHTML = '<div class="working-box"><div class="spinner"></div>'
      + '<p>Saving your watchlist — this can take a moment. Please keep this page open.</p></div>';
    document.body.appendChild(ov);
  });

  // Cancel: confirm before discarding, then announce the return to the watchlist.
  var cancel = document.querySelector('.wl-cancel');
  if (cancel) cancel.addEventListener('click', function () {
    var ov = document.createElement('div');
    ov.className = 'working-overlay';
    ov.innerHTML = '<div class="working-box wl-modal">'
      + '<p class="wl-modal-h">Returning to your watchlist</p>'
      + '<p class="wl-modal-sub">Any picks you have not added yet will not be kept.</p>'
      + '<div class="wl-modal-acts">'
      + '<button type="button" class="btn-primary" id="wl-go">Return to watchlist</button>'
      + '<button type="button" class="navbtn" id="wl-stay">Keep editing</button>'
      + '</div></div>';
    document.body.appendChild(ov);
    document.getElementById('wl-go').addEventListener('click', function () { window.location.href = '?'; });
    document.getElementById('wl-stay').addEventListener('click', function () { ov.parentNode.removeChild(ov); });
    ov.addEventListener('click', function (e) { if (e.target === ov) ov.parentNode.removeChild(ov); });
  });
})();
</script>"""


def render_watchlist_builder(client_id):
    """Build Watchlist grid. Runs inside the authed portfolio session (client_id ==
    CRM person_id), so it edits the logged-in client's own interest. Company chips come
    from load_security_maps (the only writable set), pre-ticked from the client's
    current CRM interest; the notify toggle reflects their Broadcast value. Degrades to
    an empty, explained state if the CRM JWT / API can't be reached."""
    sec = {"buy": {"id_to_name": {}}, "sell": {"id_to_name": {}}}
    cf = {}
    loaded = False
    try:
        jwt = get_jwt()
        sec = load_security_maps(jwt)
        person = call_pipeline_api("GET", f"/people/{client_id}.json", jwt=jwt)
        if person.get("status") == 200 and isinstance(person.get("data"), dict):
            cf = person["data"].get("custom_fields", {}) or {}
        loaded = bool(sec.get("buy", {}).get("id_to_name") or sec.get("sell", {}).get("id_to_name"))
    except Exception as e:
        print(f"watchlist builder load failed: {e}")

    cur = {"buy": set(cf_id_list(cf.get(BUY_INTEREST_FIELD))),
           "sell": set(cf_id_list(cf.get(SELL_INTEREST_FIELD)))}
    bc = cf_id_list(cf.get(BROADCAST_FIELD))
    notify_on = bool(bc) and bc[0] == BROADCAST_YES
    cats = company_catalysts()            # company_ids with a Catalyst = "highlighted"
    name_to_cid = _company_id_by_name()

    def chips(side):
        opts = sorted(sec.get(side, {}).get("id_to_name", {}).items(), key=lambda kv: kv[1].lower())
        rows, n_hl = [], 0
        for oid, name in opts:
            # "$" tags a company that already went public — never offered here. The
            # save handler treats these as invisible too, so an existing "$" interest
            # can never be picked up (added) or dropped (removed) by this form.
            if name.strip().endswith("$"):
                continue
            picked = oid in cur[side]
            cid = name_to_cid.get(name.strip().lower())
            hl = bool(cid and cid in cats)
            if hl:
                n_hl += 1
            rows.append(
                f'<label class="wchip" data-name="{html.escape(name.lower(), quote=True)}" '
                f'data-hl="{1 if hl else 0}"><input type="checkbox" name="keep_{side}" '
                f'value="{oid}"{" checked" if picked else ""}><span>{html.escape(name)}</span></label>')
        if not rows:
            return ('<p class="empty">The company list couldn’t be loaded right now. '
                    'Please try again shortly.</p>')
        chips_html = "".join(rows)
        return (
            # Proof that this side's grid rendered its full option set. The save writes
            # a side only when its marker comes back, so a side whose options failed to
            # load (the branch above) posts nothing and is left alone, rather than being
            # replaced with the empty set the missing checkboxes would look like.
            f'<input type="hidden" name="grid_side" value="{side}">'
            f'<div class="wl-tools">'
            f'<input type="text" class="wl-search" data-side="{side}" autocomplete="off" '
            f'placeholder="Search all companies…">'
            f'<button type="button" class="wl-showall" data-side="{side}">Show all</button>'
            f'</div>'
            f'<p class="wl-hint" data-side="{side}">Showing {n_hl} companies with recent activity — '
            f'search or “Show all” for the full list.</p>'
            f'<div class="wchip-row" id="wl-chips-{side}">{chips_html}</div>')

    def boxes(group, opts, pre=()):
        return "".join(
            f'<label class="wbox"><input type="checkbox" name="{group}" value="{html.escape(o)}"'
            f'{" checked" if o in pre else ""}><span>{html.escape(o)}</span></label>' for o in opts)

    notify_attr = " checked" if notify_on else ""
    body = f"""
    <h1>Build your watchlist</h1>
    <p class="subtitle">Pick the companies you're interested in — this updates your buy/sell
    indications and your private watchlist in one step. Ticking a company adds it;
    unticking one removes it when you save.</p>
    <p class="wl-back"><a class="cname" href="?">&larr; Back to watchlist</a></p>

    <form method="post" class="wl-form">
      <input type="hidden" name="action" value="watchlist_save">

      <div class="section">
        <p class="section-label">I'm looking to</p>
        <div class="seg" role="radiogroup" aria-label="Buy or sell side">
          <input type="radio" id="wl-side-buy" name="side" value="buy" checked>
          <label for="wl-side-buy">Buy</label>
          <input type="radio" id="wl-side-sell" name="side" value="sell">
          <label for="wl-side-sell">Sell</label>
        </div>
      </div>

      <div class="section">
        <div class="wl-pref-row">
          <div class="wl-pref">
            <p class="section-label">Structure</p>
            <div class="wbox-row">{boxes("structure", WL_STRUCTURES, pre={"Direct", "Fund"})}</div>
          </div>
          <div class="wl-pref">
            <p class="section-label">Fees</p>
            <div class="wbox-row">{boxes("fee", WL_FEES)}</div>
          </div>
        </div>
      </div>

      <div class="section wl-side-group" id="wl-group-buy">
        <p class="section-label">Companies — looking to buy</p>
        {chips("buy")}
      </div>
      <div class="section wl-side-group" id="wl-group-sell" style="display:none">
        <p class="section-label">Companies — looking to sell</p>
        {chips("sell")}
      </div>

      <label class="wl-notify">
        <input type="checkbox" name="notify" value="yes"{notify_attr}>
        <span class="wl-notify-text">
          <strong>Email me about matching deals</strong>
          <small>We'll let you know when a buyer or seller turns up for one of your picks.</small>
        </span>
      </label>

      <p class="wl-save-note">Saving updates both your <strong>Buy</strong> and
      <strong>Sell</strong> lists: the companies ticked in each are kept, and anything
      unticked is removed.</p>

      <div class="add-actions">
        <button type="submit" class="btn-primary">Update watchlist</button>
        <button type="button" class="navbtn wl-cancel">Cancel</button>
      </div>
    </form>"""
    return html_response(body + WL_SCRIPT, client_id=client_id)


# ── HTML shell ───────────────────────────────────────────────────────────────────
# Quiet top nav back to the main Gracia Group properties. Same-tab links; the
# session cookie persists, so a client can leave and return without re-auth.
TOPNAV_HTML = """
    <nav class="topnav">
      <div class="navgroup">
        <a class="navbtn brand" href="https://www.graciagroup.com">Gracia Group</a>
      </div>
      <div class="navgroup">
        <a class="navbtn" href="?">Watchlist</a>
        <a class="navbtn" href="?view=watchlist">Update watchlist</a>
        <a class="navbtn" href="?view=holdings">Holdings</a>
        <a class="navbtn" href="https://trades.graciagroup.com/">Indications</a>
      </div>
    </nav>"""

# Same nav with one extra button into the internal tools index. Derived from
# TOPNAV_HTML so the shared links only ever have to be edited in one place; only
# pages that pass is_admin=True to html_response render this variant.
TOPNAV_ADMIN_HTML = TOPNAV_HTML.replace(
    '<a class="navbtn" href="https://trades.graciagroup.com/">Indications</a>',
    '<a class="navbtn" href="https://trades.graciagroup.com/">Indications</a>\n'
    '        <a class="navbtn" href="?view=admin">Admin</a>')

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


# Per-view favicon emoji + <title> for the shared shell below. Any view not
# listed here (watchlist, holdings, indications, portfolio, ...) keeps the
# general desk default.
_VIEW_META = {
    "admin": ("🎛️", "Admin Portal · GG"),
    "auctions": ("⏱️", "Auctions · Gracia Group"),
    "auction": ("⏱️", "Auctions · Gracia Group"),
    "sendlink": ("🚀", "Send a Link · GG Admin"),
}

# ── Unified top nav (same structure/styling as chadgracia/trades and
# chadgracia/CRMDealDetails) ──────────────────────────────────────────────────────
_syndicate_tenant_cache = {"emails": None}


def _syndicate_eligible_emails():
    """Lowercased emails eligible for the Syndicate Dashboard, fetched once per
    warm container from syndicate-dash's own admin-gated ?tenants=list route --
    the same endpoint chadgracia/trades reads for its My Dashboard nav tab.
    Fail-soft: any error caches an empty set so the tab just doesn't render."""
    if _syndicate_tenant_cache["emails"] is not None:
        return _syndicate_tenant_cache["emails"]
    emails = set()
    try:
        req = urllib.request.Request(SYNDICATE_DASH_URL + "&tenants=list")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        emails = {(t.get("email") or "").strip().lower()
                  for t in (data.get("tenants") or []) if t.get("email")}
    except Exception as e:
        print(f"Unified nav: syndicate tenants fetch failed (non-fatal): {e}")
    _syndicate_tenant_cache["emails"] = emails
    return emails


def _render_unified_nav(client_id):
    """The shared client-facing top nav, rendered above the existing desk
    header buttons on every client-facing view. Any failure building an
    optional piece (Auctions, My Dashboard, the viewer's email) must not
    break the rest of the nav or the page."""
    email = ""
    try:
        rec = lookup_person(client_id)
        if rec.get("found"):
            email = (rec.get("email") or "").strip()
    except Exception as e:
        print(f"Unified nav: person lookup failed (non-fatal): {e}")
    who = html.escape(email) if email else html.escape(display_name(client_id))

    auctions_tab = ""
    try:
        today = datetime.now(timezone.utc).date()
        live_ids = []
        for aid, auc in (_load_auctions() or {}).items():
            close_date = (auc.get("close_date") or "").strip()
            if not close_date:
                live_ids.append(aid)
                continue
            try:
                is_past = datetime.strptime(close_date, "%Y-%m-%d").date() < today
            except ValueError:
                is_past = False
            if not is_past:
                live_ids.append(aid)
        if live_ids:
            auctions_tab = (
                f'<a href="?view=auction&id={urllib.parse.quote(str(live_ids[0]))}" '
                f'class="nav-tab">Auctions ({len(live_ids)})</a>'
            )
    except Exception as e:
        print(f"Unified nav: Auctions tab failed (non-fatal): {e}")
        auctions_tab = ""

    dashboard_tab = ""
    try:
        if email and email.lower() in _syndicate_eligible_emails():
            dashboard_tab = (
                f'<a href="{html.escape(SYNDICATE_DASH_URL, quote=True)}" '
                'target="_blank" rel="noopener" class="nav-tab">My Dashboard</a>'
            )
    except Exception as e:
        print(f"Unified nav: My Dashboard tab failed (non-fatal): {e}")
        dashboard_tab = ""

    account_html = (
        '<div class="navacct" tabindex="0">'
        '<span class="navacct-trigger">My Account &#9662;</span>'
        '<div class="navacct-menu">'
        f'<div class="navacct-item navacct-static">Signed in as {who}</div>'
        '<div class="navacct-item navacct-disabled" title="Coming soon">Profile &mdash; coming soon</div>'
        '<a class="navacct-item" href="?signout=1">Sign out</a>'
        '</div></div>'
    )

    return (
        '<nav class="gg-unav">'
        '<a href="https://www.graciagroup.com" class="nav-brand">Gracia Group</a>'
        '<div class="nav-tabs">'
        '<a href="https://trades.graciagroup.com/" class="nav-tab">Indications</a>'
        '<a href="?" class="nav-tab">Portfolio &amp; Watchlist</a>'
        '<span class="nav-tab nav-tab-disabled" title="Coming soon">Introductions</span>'
        '<span class="nav-tab nav-tab-disabled" title="Coming soon">Demand Board</span>'
        + auctions_tab
        + dashboard_tab
        + '</div>'
        + account_html
        + '</nav>'
    )


def html_response(body_html, status=200, eyebrow="Private Secondaries Watchlist",
                  is_admin=False, view=None, client_id=None):
    # Every page shares this shell, so the only thing is_admin changes is which nav
    # constant gets injected. It defaults to False: any caller that doesn't opt in
    # keeps the client-facing nav exactly as before.
    topnav = TOPNAV_ADMIN_HTML if is_admin else TOPNAV_HTML
    favicon_emoji, page_title = _VIEW_META.get(view, ("🗂️", "Desk · Gracia Group"))
    # The unified nav only renders when a caller passes client_id -- i.e. only on
    # the client-facing views that opted in above. Any failure inside it must
    # never break the page, so it's built defensively (see _render_unified_nav).
    unified_nav_html = ""
    if client_id:
        try:
            unified_nav_html = _render_unified_nav(client_id)
        except Exception as e:
            print(f"Unified nav: render failed (non-fatal): {e}")
            unified_nav_html = ""
    return {
        "statusCode": status,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{page_title}</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>{favicon_emoji}</text></svg>">
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
    .gg-unav {{
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      padding: 10px 0;
      margin-bottom: 10px;
      border-bottom: 1px solid #ddd;
    }}
    .nav-brand {{
      font-weight: 700;
      font-size: 17px;
      color: var(--ink);
      text-decoration: none;
      white-space: nowrap;
    }}
    .nav-tabs {{
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 18px;
      flex: 1;
    }}
    .nav-tab {{
      display: inline-block;
      background-color: #fff;
      border: 1px solid #ddd;
      border-radius: 999px;
      padding: 8px 16px;
      font-size: 14px;
      font-weight: 600;
      color: var(--ink);
      text-decoration: none;
      white-space: nowrap;
    }}
    .nav-tab:hover {{
      background-color: #f0f0f0;
    }}
    .nav-tab-disabled {{
      color: #999;
      cursor: default;
    }}
    .nav-tab-disabled:hover {{
      background-color: #fff;
    }}
    .navacct {{
      position: relative;
      margin-left: auto;
    }}
    .navacct-trigger {{
      display: inline-block;
      background-color: #fff;
      border: 1px solid #ddd;
      border-radius: 999px;
      padding: 8px 16px;
      font-size: 14px;
      font-weight: 600;
      color: var(--ink);
      cursor: pointer;
      white-space: nowrap;
    }}
    .navacct-trigger:hover {{
      background-color: #f0f0f0;
    }}
    .navacct-menu {{
      display: none;
      position: absolute;
      right: 0;
      top: 100%;
      margin-top: 6px;
      background: #fff;
      border-radius: 6px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      min-width: 220px;
      padding: 6px 0;
      z-index: 50;
    }}
    .navacct:hover .navacct-menu, .navacct:focus-within .navacct-menu {{
      display: block;
    }}
    .navacct-item {{
      display: block;
      padding: 9px 16px;
      font-size: 13px;
      color: var(--ink);
      text-decoration: none;
      white-space: nowrap;
    }}
    .navacct-item:hover {{
      background: #f4f4f4;
    }}
    .navacct-static {{
      color: var(--text-secondary, #666);
      font-weight: 600;
      cursor: default;
    }}
    .navacct-static:hover {{
      background: none;
    }}
    .navacct-disabled {{
      color: #999;
      cursor: default;
    }}
    .navacct-disabled:hover {{
      background: none;
    }}
    .viewbar {{
      display: flex; gap: 6px; align-items: center; flex-wrap: wrap;
      margin-bottom: 18px; padding: 9px 13px; border-radius: 8px;
      border: 1px solid #e6d8ac; background: #fdf7e6;
      font-size: 12px; font-weight: 600; color: #7a5c14;
    }}
    .viewbar a {{ color: #7a5c14; }}
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
    /* Segmented Holding|Watchlist toggle, sat next to the Add button. */
    .add-actions {{ display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }}
    .seg {{ display: inline-flex; border: 1px solid var(--line); border-radius: 9px; overflow: hidden; }}
    .seg input {{ position: absolute; opacity: 0; pointer-events: none; }}
    .seg label {{ padding: 8px 18px; font-size: 13px; font-weight: 600; color: var(--muted); cursor: pointer; background: #fff; }}
    .seg label + input + label {{ border-left: 1px solid var(--line); }}
    .seg input:checked + label {{ background: var(--accent); color: #fff; }}
    /* Watchlist section + "at/below target" highlight. */
    .wl-head {{ margin-top: 34px; }}
    td.wl-hit {{ color: var(--pos); font-weight: 700; }}
    /* Build Watchlist grid */
    .wl-form .section {{ margin-bottom: 22px; }}
    .wl-back {{ margin: -10px 0 20px; font-size: 13px; }}
    .section-label {{ font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin-bottom: 10px; }}
    .wbox-row {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .wchip-row {{ display: flex; flex-wrap: wrap; gap: 5px; }}
    .wbox {{ display: inline-flex; align-items: center; gap: 7px; width: auto; white-space: nowrap; padding: 7px 13px; border: 1px solid var(--line); border-radius: 999px; font-size: 13px; color: var(--muted); background: #fff; cursor: pointer; user-select: none; }}
    .wchip {{ display: inline-flex; align-items: center; gap: 5px; padding: 3px 9px; border: 1px solid var(--line); border-radius: 999px; font-size: 12px; line-height: 1.5; color: var(--muted); background: #fff; cursor: pointer; user-select: none; }}
    .wchip input {{ accent-color: var(--accent); margin: 0; width: 12px; height: 12px; flex: none; }}
    .wbox input {{ accent-color: var(--accent); margin: 0; width: 12px; height: 12px; flex: none; }}
    .wchip:has(input:checked), .wbox:has(input:checked) {{ border-color: var(--accent); color: var(--ink); background: var(--bg); }}
    .wl-tools {{ display: flex; gap: 8px; margin-bottom: 8px; }}
    .wl-search {{ flex: 1; padding: 7px 11px; border: 1px solid var(--line); border-radius: 8px; font-size: 13px; }}
    .wl-showall {{ border: 1px solid var(--line); background: #fff; color: var(--muted); border-radius: 8px; padding: 7px 12px; font-size: 12px; cursor: pointer; white-space: nowrap; }}
    .wl-hint {{ font-size: 12px; color: var(--muted); margin: 0 0 8px; }}
    /* What the save button will do, next to the button that does it. Body size, not
       the 12px of .wl-hint: unticking removes a company, which is not fine print. */
    .wl-save-note {{ font-size: 14px; color: var(--ink); line-height: 1.5;
                     margin: 26px 0 14px; max-width: 60ch; }}
    /* Structure + Fees side by side on one line */
    .wl-pref-row {{ display: flex; flex-wrap: wrap; gap: 16px 48px; }}
    .wl-pref {{ flex: 1 1 auto; }}
    /* Notify, as a tidy toggle card just above the actions */
    .wl-notify {{ display: flex; align-items: flex-start; gap: 11px; padding: 14px 16px; margin: 4px 0 6px;
      border: 1px solid var(--line); border-radius: 10px; background: var(--bg); cursor: pointer; }}
    .wl-notify input {{ accent-color: var(--accent); margin-top: 2px; width: 16px; height: 16px; flex: none; }}
    .wl-notify-text {{ display: flex; flex-direction: column; gap: 2px; }}
    .wl-notify-text strong {{ font-size: 14px; color: var(--ink); font-weight: 600; }}
    .wl-notify-text small {{ font-size: 12px; color: var(--muted); }}
    .wl-notify:has(input:checked) {{ border-color: var(--accent); background: #fff; }}
    /* Cancel confirmation popup */
    .wl-modal {{ max-width: 380px; text-align: center; }}
    .wl-modal-h {{ font-family: 'Fraunces', Georgia, serif; font-size: 18px; font-weight: 600; margin-bottom: 6px; }}
    .wl-modal-sub {{ font-size: 13px; color: var(--muted); margin-bottom: 18px; line-height: 1.5; }}
    .wl-modal-acts {{ display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }}
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
    /* Clear section structure: Holdings / Watchlist / Add a holding */
    h2.sec {{ margin-top: 40px; }}
    .section-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 40px; margin-bottom: 4px; }}
    .section-head h2 {{ margin-bottom: 0; }}
    .btn-secondary {{
      display: inline-block; background: var(--bg); color: var(--ink); text-decoration: none;
      border: 1px solid var(--line); padding: 8px 14px; border-radius: 8px;
      font-size: 13px; font-weight: 600; white-space: nowrap;
    }}
    .btn-secondary:hover {{ border-color: var(--accent); color: var(--accent); }}
    .empty-state {{
      border: 1px dashed var(--line); border-radius: 10px; padding: 20px;
      color: var(--muted); font-size: 14px; line-height: 1.5; background: var(--bg);
    }}
    /* Collapsed add-holding: the summary IS the button; fields reveal on click. */
    .add-holding {{ margin-top: 28px; }}
    .add-holding > summary {{ list-style: none; cursor: pointer; width: auto; }}
    .add-holding > summary::-webkit-details-marker {{ display: none; }}
    .add-holding > summary::marker {{ content: ""; }}
    .add-holding[open] > summary {{ margin-bottom: 16px; }}
    .add-holding .add {{ margin-top: 0; }}
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
    {unified_nav_html}
    {topnav}
    <div class="logo">{html.escape(eyebrow)}</div>
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


def sign_id(secret, ident):
    """The token shape every signed link here uses: unpadded base64url of
    HMAC-SHA256(secret, id). Only the key differs between the sibling lambdas."""
    return _b64u(hmac.new(secret.encode(), str(ident).encode(), hashlib.sha256).digest())


def make_token(client_id):
    """Permanent magic-link token: HMAC over the client_id."""
    return sign_id(HMAC_SECRET, client_id)


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


def make_admin_cookie(admin_id):
    """Signed, expiring admin marker:  base64url("admin"|admin_id|exp).base64url(sig).

    Exactly the make_session construction — HMAC-SHA256 over the base64url payload,
    keyed by the same HMAC_SECRET — so this cookie is no more forgeable than a
    session is. The literal "admin" first field is domain separation: it keeps the
    two cookie types from being swapped for one another. A session value fed to
    read_admin_cookie fails the kind check, and an admin value fed to read_session
    fails its int(exp) parse, even though both verify under the same key."""
    payload = f"admin|{admin_id}|{int(time.time()) + ADMIN_DAYS * 86400}"
    p = _b64u(payload.encode())
    sig = hmac.new(HMAC_SECRET.encode(), p.encode(), hashlib.sha256).digest()
    return f"{p}.{_b64u(sig)}"


def read_admin_cookie(value):
    """Return the admin's own client_id if the cookie is validly signed, unexpired
    AND still listed in ADMIN_CLIENT_IDS, else None. The membership re-check means
    removing someone from the env var revokes their stickiness immediately, instead
    of leaving a year-long cookie standing."""
    try:
        p, s = (value or "").split(".", 1)
        expected = hmac.new(HMAC_SECRET.encode(), p.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64u(expected), s):
            return None
        parts = _b64u_decode(p).decode().split("|")
        if len(parts) != 3 or parts[0] != "admin":
            return None
        admin_id, exp = parts[1], parts[2]
        if int(exp) < int(time.time()):
            return None
        return admin_id if admin_id in ADMIN_CLIENT_IDS else None
    except Exception:
        return None


def _cookie(name, value, days):
    return (f"{name}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; "
            f"Max-Age={days * 86400}")


def session_cookie(client_id):
    return _cookie(COOKIE_NAME, make_session(client_id), SESSION_DAYS)


def admin_cookie(admin_id):
    return _cookie(ADMIN_COOKIE_NAME, make_admin_cookie(admin_id), ADMIN_DAYS)


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


def _parse_body_multi(event):
    """parse_qs without collapsing repeats — for the Build Watchlist grid, whose
    checkbox groups submit many keep_buy / keep_sell / structure / fee values."""
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    return urllib.parse.parse_qs(body)


WL_DEALS_BUCKET = "pipeline-public-deal-data"
WL_DEALS_KEY = "pipeline_deals.json"

# Person-level Ticket Size multi-select and its dollar tiers (mirrors deal-notifier).
WL_TICKET_FIELD = "custom_label_3052210"
WL_TICKET_SIZE_MAP = {
    6870210: (100_000,     250_000),
    6631962: (100_000,     250_000),
    5014552: (251_000,     999_000),
    5014555: (1_000_000,   5_000_000),
    5014558: (5_000_000,   10_000_000),
    5014561: (10_000_000,  25_000_000),
    5014564: (25_000_000,  50_000_000),
    5014567: (50_000_000,  100_000_000),
    5014570: (100_000_000, None),
}


def _wl_structure_label(d):
    """Structure cell for a watchlist deal row, annotated with layers and fees:
    'Fund (1L - 5/0/10)' = structure (layers - seller_fee/management_fee/carry).
    Fees show only when at least one of the three is recorded; layers only when
    recognized. Falls back to the bare structure string."""
    base = (d.get("structure") or "").strip()
    layers_val = (d.get("layers") or "").strip()
    layer = {"spv on cap table": "1L", "2-layer spv": "2L",
             "3-layer spv": "3L"}.get(layers_val.lower(), "")

    def _fee(v):
        try:
            f = float(str(v).replace("%", "").strip())
        except (TypeError, ValueError):
            return None
        return int(f) if f == int(f) else f
    fees = [_fee(d.get("seller_fee")), _fee(d.get("management_fee")),
            _fee(d.get("carry"))]
    fee_str = ("/".join("0" if f is None else str(f) for f in fees)
               if any(f is not None for f in fees) else "")

    if layer and fee_str:
        note = f"{layer} - {fee_str}"
    else:
        note = layer or fee_str
    return f"{base} ({note})" if (base and note) else (base or note)


# Seller Role ("seller_role", a flattened display-string field) on the sell-side
# deal record. When the seller is a GP forming/syndicating a new vehicle rather
# than a holder waiting on buy-side bids, the no-price cell reads "Current round
# price" instead of "Awaiting bids". Any other role, or a missing field, falls
# back to "Awaiting bids" unchanged.
def _wl_no_price_label(d):
    role = (d.get("seller_role") or "").strip().lower()
    if "syndicating" in role:
        return "Current round price"
    return "Awaiting bids"


def _wl_ticket_range(cf):
    """(low, high) in dollars across the person's Ticket Size tiers.
    (None, None) when the field is empty or unknown — no size filtering then.
    A tier with no upper bound leaves high as None (nothing is 'too big')."""
    lo = hi = None
    unbounded = False
    for oid in cf_id_list((cf or {}).get(WL_TICKET_FIELD)):
        tier = WL_TICKET_SIZE_MAP.get(int(oid))
        if not tier:
            continue
        t_lo, t_hi = tier
        lo = t_lo if lo is None else min(lo, t_lo)
        if t_hi is None:
            unbounded = True
        elif hi is None or t_hi > hi:
            hi = t_hi
    if unbounded:
        hi = None
    return lo, hi
WL_HOLDERS_KEY = "holder_counts.json"
WL_WEBBID_URL = DESK_URL + "/bid/"
WL_DEAL_URL = DESK_URL + "/deal/"


def _wl_json(bucket, key, default):
    try:
        obj = boto3.client("s3").get_object(Bucket=bucket, Key=key)
        return json.loads(obj["Body"].read())
    except Exception as e:
        print(f"watchlist: could not load {bucket}/{key}: {e}")
        return default


def _wl_buyers(name):
    """People carrying this company in their Buy Interest field, from holder_counts.json."""
    data = _wl_json(COMPANIES_BUCKET, WL_HOLDERS_KEY, {})
    if isinstance(data, dict):
        counts = data.get("buy_counts") or {}
        for k, v in counts.items():
            if str(k).strip().lower() == (name or "").strip().lower():
                try:
                    return int(v)
                except (TypeError, ValueError):
                    return 0
    return 0


def _wl_holders(name):
    data = _wl_json(COMPANIES_BUCKET, WL_HOLDERS_KEY, {})
    if isinstance(data, dict):
        counts = data.get("counts") or {}
        for k, v in counts.items():
            if str(k).strip().lower() == (name or "").strip().lower():
                try:
                    return int(v)
                except (TypeError, ValueError):
                    return 0
    return 0


def _wl_money(v):
    try:
        n = float(str(v).replace("$", "").replace(",", "").strip())
    except (TypeError, ValueError):
        return ""
    if n >= 1_000_000:
        return f"${n/1_000_000:,.1f}M"
    if n >= 1_000:
        return f"${n/1_000:,.0f}K"
    return f"${n:,.0f}"


def _wl_pps(v):
    """Per-share prices keep cents, so the premium column reconciles."""
    try:
        n = float(str(v).replace("$", "").replace(",", "").strip())
    except (TypeError, ValueError):
        return "&ndash;"
    return f"${n:,.2f}"


WL_TRANSFER_FIELD = "custom_label_3900670"
WL_CATALYST_FIELD = "custom_label_3999603"
WL_DIRECT_BLOCKED = 6888893
WL_MAX_COMPANY_FETCH = 40


def _wl_company_meta(names, jwt):
    """{lower(name): {"blocked": bool, "catalyst": str}} for watchlisted companies."""
    out = {}
    if not jwt or not names:
        return out
    by_name = _company_id_by_name()
    for nm in list(names)[:WL_MAX_COMPANY_FETCH]:
        cid = by_name.get(nm.strip().lower())
        if not cid:
            continue
        try:
            res = call_pipeline_api("GET", f"/companies/{cid}.json", jwt=jwt)
            if res.get("status") != 200 or not isinstance(res.get("data"), dict):
                continue
            cf = res["data"].get("custom_fields") or {}
            out[nm.strip().lower()] = {
                "blocked": WL_DIRECT_BLOCKED in cf_id_list(cf.get(WL_TRANSFER_FIELD)),
                "catalyst": (cf.get(WL_CATALYST_FIELD) or "").strip(),
            }
        except Exception as e:
            print(f"watchlist: company meta lookup failed for {nm}: {e}")
    return out


TRADE_UPDATE_BASE = DESK_URL + "/update/"
LOI_SIGN_BASE = DESK_URL + "/loi/"
WEB_BID_BASE = DESK_URL + "/bid/"
TRADE_UPDATE_SECRET = "trade-update"   # the update form's key is fixed, not a secret


def _deal_name(deal_id):
    """The deal's "name" field, or "" if Pipeline doesn't know that id. Never raises:
    a failed lookup only costs the confirmation line, not the links."""
    try:
        res = call_pipeline_api("GET", f"/deals/{deal_id}.json", jwt=get_jwt())
        if res.get("status") == 200 and isinstance(res.get("data"), dict):
            return (res["data"].get("name") or "").strip()
    except Exception as e:
        print(f"send_link: deal lookup failed for {deal_id}: {e}")
    return ""


def render_send_link():
    """Admin-only: the one page every outbound link comes from. Three sections —
    a client's sign-in link, a deal's update/LOI links, a company's bid/offer links.
    They used to be two pages (?view=link and ?view=deallinks) whose titles gave no
    hint which was which; both routes now redirect here."""
    # web-bid resolves pricing and holder counts by matching this name against
    # Pipeline, so the picker has to offer the CRM's own casing. _company_id_by_name()
    # lowercases its keys for joining, so read tracked_companies() directly — its
    # values are the untouched names. A failed S3 read only costs the picker: the
    # field stays free-text and the note below it says the name must match exactly.
    try:
        wb_names = sorted(set(tracked_companies().values()), key=str.lower)
    except Exception as e:
        print(f"send_link: company list unavailable: {e}")
        wb_names = []
    wb_options = "".join(
        f'<option value="{html.escape(n, quote=True)}"></option>' for n in wb_names)
    wb_hint = ("Pick a tracked company, or type the name exactly as Pipeline spells it."
               if wb_names else
               "Type the company name exactly as Pipeline spells it — the company list "
               "could not be loaded, and web-bid can't resolve pricing or holder counts "
               "from a name that doesn't match.")
    return html_response("""
    <style>
      .sl-sec { border:1px solid var(--line); border-radius:10px;
                padding:20px 22px 22px; margin-top:20px; background:#fff; }
      .sl-head { display:flex; align-items:baseline; gap:10px; }
      .sl-num { flex:none; width:22px; height:22px; border-radius:50%;
                background:var(--ink); color:#fff; font-size:12px; font-weight:600;
                line-height:22px; text-align:center; align-self:center; }
      .sl-h2 { font-size:19px; }
      .sl-who { font-size:13.5px; color:var(--muted); margin:6px 0 0;
                line-height:1.5; }
      .sl-form { display:flex; gap:8px; flex-wrap:wrap; margin:14px 0 4px; }
      .sl-form input { padding:9px 12px; font-family:inherit; font-size:14px;
                       border:1px solid var(--line); border-radius:6px; min-width:240px; }
      .sl-form button { padding:9px 18px; font-family:inherit; font-size:14px;
                        font-weight:600; border:none; border-radius:6px;
                        background:var(--ink); color:#fff; cursor:pointer; }
      .sl-out { display:none; margin-top:10px; }
      .sl-block { margin-top:16px; }
      .sl-label { font-weight:600; font-size:14px; margin-bottom:6px; }
      .sl-url { width:100%; padding:10px 12px; font-family:ui-monospace,monospace;
                font-size:13px; border:1px solid var(--line); border-radius:6px; }
      .sl-row { display:flex; gap:8px; align-items:center; margin-top:8px; }
      .sl-row button { padding:6px 14px; font-family:inherit; font-size:13px;
                       border:1px solid var(--line); border-radius:6px;
                       background:#fff; cursor:pointer; }
      .sl-note { font-size:13px; color:#b45309; margin-top:10px; line-height:1.45; }
      .sl-open { font-size:13px; color:var(--muted); margin-top:10px; line-height:1.45; }
      .sl-off .sl-url { background:#f3f4f6; color:#9ca3af; }
      .sl-off .sl-row { display:none; }
      .sl-hint { font-size:13px; color:var(--muted); margin:6px 0 0; }
    </style>
    <h1>Send a link</h1>
    <p class="sub">Every link you send a client, a counterparty or a company contact is
      generated here. Three kinds — pick the one that matches who is receiving it.</p>

    <section class="sl-sec">
      <div class="sl-head"><span class="sl-num">1</span>
        <h2 class="sl-h2">Watchlist Link</h2></div>
      <p class="sl-who">Takes a Pipeline <strong>person ID</strong> and returns that
        client's permanent link into their own watchlist — for that one client only.</p>
      <div class="sl-note">This link signs whoever opens it in as that client, so it
        must not be forwarded.</div>
      <div class="sl-form">
        <input id="lk-id" type="text" inputmode="numeric" placeholder="e.g. 1309687264">
        <button type="button" onclick="lkGo()">Get their link</button>
        <button type="button" onclick="lkView()">View as them</button>
      </div>
      <div id="lk-out" class="sl-out">
        <div id="lk-who" style="font-weight:600; margin-bottom:6px;"></div>
        <input id="lk-url" class="sl-url" readonly onclick="this.select()">
        <div class="sl-row">
          <button type="button" onclick="slCopy('lk-url')">Copy</button>
          <a id="lk-open" href="#" target="_blank" rel="noopener">Open in new tab &rarr;</a>
        </div>
      </div>
    </section>

    <section class="sl-sec">
      <div class="sl-head"><span class="sl-num">2</span>
        <h2 class="sl-h2">Deal links</h2></div>
      <p class="sl-who">Takes a Pipeline <strong>deal ID</strong> and returns that deal's
        update-request form and LOI signing link — for the parties to that deal.</p>
      <div class="sl-form">
        <input id="dl-id" type="text" inputmode="numeric" placeholder="e.g. 12345678">
        <button type="button" onclick="dlGo()">Get links</button>
      </div>
      <div id="dl-out" class="sl-out">
        <div id="dl-who" style="font-weight:600; margin-bottom:6px;"></div>
        <div class="sl-block">
          <div class="sl-label">Update request form</div>
          <input id="dl-update" class="sl-url" readonly onclick="this.select()">
          <div class="sl-row">
            <button type="button" onclick="slCopy('dl-update')">Copy</button>
            <a id="dl-update-open" href="#" target="_blank" rel="noopener">Open in new tab &rarr;</a>
          </div>
        </div>
        <div class="sl-block" id="dl-loi-block">
          <div class="sl-label">LOI signing link</div>
          <input id="dl-loi" class="sl-url" readonly onclick="this.select()">
          <div class="sl-row">
            <button type="button" onclick="slCopy('dl-loi')">Copy</button>
            <a id="dl-loi-open" href="#" target="_blank" rel="noopener">Open in new tab &rarr;</a>
          </div>
          <div id="dl-loi-note" class="sl-note"></div>
        </div>
      </div>
    </section>

    <section class="sl-sec">
      <div class="sl-head"><span class="sl-num">3</span>
        <h2 class="sl-h2">Company links</h2></div>
      <p class="sl-who">Takes a <strong>company name</strong> and returns that company's
        buyer bid form and seller offer form — for anyone you want an indication from.</p>
      <div class="sl-form">
        <input id="wb-name" type="text" list="wb-companies" autocomplete="off"
               placeholder="Start typing a company name">
        <button type="button" onclick="wbGo()">Get links</button>
      </div>
      <datalist id="wb-companies">""" + wb_options + """</datalist>
      <p class="sl-hint">""" + html.escape(wb_hint) + """</p>
      <div id="wb-out" class="sl-out">
        <div class="sl-block">
          <div class="sl-label">Bid form (buyer)</div>
          <input id="wb-buy" class="sl-url" readonly onclick="this.select()">
          <div class="sl-row">
            <button type="button" onclick="slCopy('wb-buy')">Copy</button>
            <a id="wb-buy-open" href="#" target="_blank" rel="noopener">Open in new tab &rarr;</a>
          </div>
        </div>
        <div class="sl-block">
          <div class="sl-label">Offer form (seller)</div>
          <input id="wb-sell" class="sl-url" readonly onclick="this.select()">
          <div class="sl-row">
            <button type="button" onclick="slCopy('wb-sell')">Copy</button>
            <a id="wb-sell-open" href="#" target="_blank" rel="noopener">Open in new tab &rarr;</a>
          </div>
        </div>
        <div class="sl-open">These are open links — they carry no token and need no
          sign-in. Anyone with the link can open the form, and it collects name and
          email from anyone not already signed in.</div>
      </div>
    </section>

    <section class="sl-sec">
      <div class="sl-head"><span class="sl-num">4</span>
        <h2 class="sl-h2">Mailer list</h2></div>
      <p class="sl-who">Takes a Pipeline <strong>saved-search ID</strong> and opens that
        search's mailer list — the recipients for a weekly send.</p>
      <div class="sl-form">
        <input id="ml-search" type="text" inputmode="numeric" value="19530439">
        <button type="button" onclick="mlGo()">Open mailer list</button>
      </div>
      <p class="sl-hint">Weekly Mailer Leads is 19530439 — paste any saved search ID.</p>
    </section>
    <script>
      function slCopy(elId) {
        var el = document.getElementById(elId);
        el.select();
        document.execCommand('copy');
      }
      function lkGo() {
        var id = (document.getElementById('lk-id').value || '').trim();
        if (!id) { return; }
        fetch('?view=link_token&id=' + encodeURIComponent(id))
          .then(function (r) { return r.json(); })
          .then(function (d) {
            if (!d || !d.url) { alert('Could not generate a link.'); return; }
            document.getElementById('lk-url').value = d.url;
            document.getElementById('lk-open').href = d.url;
            var who = document.getElementById('lk-who');
            if (d.name) {
              who.textContent = 'Link for ' + d.name;
              who.style.color = '';
            } else {
              who.textContent = 'No person found with that ID — check before sending.';
              who.style.color = '#b45309';
            }
            document.getElementById('lk-out').style.display = 'block';
          })
          .catch(function (e) { alert('Error: ' + e); });
      }
      function lkView() {
        var id = (document.getElementById('lk-id').value || '').trim();
        if (!id) { return; }
        window.open('?as=' + encodeURIComponent(id), '_blank');
      }
      function dlGo() {
        var id = (document.getElementById('dl-id').value || '').trim();
        if (!id) { return; }
        fetch('?view=deal_link_tokens&id=' + encodeURIComponent(id))
          .then(function (r) { return r.json(); })
          .then(function (d) {
            if (!d || !d.update_url) { alert('Could not generate links.'); return; }
            var who = document.getElementById('dl-who');
            if (d.name) {
              who.textContent = d.name;
              who.style.color = '';
            } else {
              who.textContent = 'No deal found with that ID — check before sending.';
              who.style.color = '#b45309';
            }
            document.getElementById('dl-update').value = d.update_url;
            document.getElementById('dl-update-open').href = d.update_url;
            // No LOI secret on this Lambda means no signature we could trust, so the
            // row goes dead rather than handing over a link that would be rejected.
            var block = document.getElementById('dl-loi-block');
            var note = document.getElementById('dl-loi-note');
            if (d.loi_url) {
              block.classList.remove('sl-off');
              document.getElementById('dl-loi').value = d.loi_url;
              document.getElementById('dl-loi-open').href = d.loi_url;
              note.textContent = '';
            } else {
              block.classList.add('sl-off');
              document.getElementById('dl-loi').value = '';
              document.getElementById('dl-loi-open').href = '#';
              note.textContent = d.loi_error || 'LOI links are unavailable.';
            }
            document.getElementById('dl-out').style.display = 'block';
          })
          .catch(function (e) { alert('Error: ' + e); });
      }
      var WB_BASE = """ + json.dumps(WEB_BID_BASE) + """;
      // Open by design: no token to fetch, so the links are built right here.
      function wbGo() {
        var name = (document.getElementById('wb-name').value || '').trim();
        if (!name) { return; }
        var base = WB_BASE + '?name=' + encodeURIComponent(name) + '&side=';
        document.getElementById('wb-buy').value = base + 'buy';
        document.getElementById('wb-buy-open').href = base + 'buy';
        document.getElementById('wb-sell').value = base + 'sell';
        document.getElementById('wb-sell-open').href = base + 'sell';
        document.getElementById('wb-out').style.display = 'block';
      }
      function mlGo() {
        var id = (document.getElementById('ml-search').value || '').trim();
        if (!/^[0-9]+$/.test(id)) { return; }
        var url = 'https://bddpwqsqvt32ritxpjqlqwhaim0ykbol.lambda-url.us-east-1.on.aws/'
          + '?key=alkj%2A707q235-qjdf&view=mailer&list=1&search=' + id;
        window.open(url, '_blank');
      }
    </script>
    """, is_admin=True, view="sendlink")


AUCTIONS_KEY = "auctions.json"


def _load_auctions():
    try:
        obj = boto3.client("s3").get_object(Bucket=COMPANIES_BUCKET, Key=AUCTIONS_KEY)
        data = json.loads(obj["Body"].read())
        return data.get("auctions") or {}
    except Exception as e:
        print(f"auctions: load failed: {e}")
        return {}


def _save_auctions(auctions):
    boto3.client("s3").put_object(
        Bucket=COMPANIES_BUCKET, Key=AUCTIONS_KEY,
        Body=json.dumps({"auctions": auctions}, ensure_ascii=False).encode("utf-8"),
        ContentType="application/json",
    )


def _auc_num(v):
    try:
        s = str(v).replace("$", "").replace(",", "").strip()
        return float(s) if s else None
    except (TypeError, ValueError):
        return None


ADMIN_BRIEF_URL = "https://bddpwqsqvt32ritxpjqlqwhaim0ykbol.lambda-url.us-east-1.on.aws/?key=alkj%2A707q235-qjdf"
ADMIN_MAILER_URL = ADMIN_BRIEF_URL + "&view=mailer"
ADMIN_PRICING_URL = "https://jw2kk4a73jbft32yf5lr7u22bm0bgkiy.lambda-url.us-east-1.on.aws/"
ADMIN_ALERTS_URL = ("https://3m3tx5bqrdvddzsyjitnjiipjy0hftoe.lambda-url.us-east-1.on.aws/"
                    "?key=JK8h5Pq2L9aZ7rT3mN6bX")
SYNDICATE_DASH_URL = ("https://ws4stw4iul75a7yx5dra2wmnq40kipav.lambda-url.us-east-1.on.aws/"
                      "?key=JK8h5Pq2L9aZ7rT3mN6bX")
DEALS_KEY = "deals.json"
SELL_ORDER_FIELD = "custom_label_1958"
SELL_ORDER_OPTION_ID = 5011675


def _deal_cf_option_ids(deal, field):
    v = (deal.get("custom_fields") or {}).get(field)
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


def _deal_linked_person_ids(deal):
    people = deal.get("people")
    if isinstance(people, list):
        return [p.get("id") for p in people if isinstance(p, dict) and p.get("id") is not None]
    return [pid for pid in (deal.get("person_ids") or []) if pid is not None]


def syndicator_eligible_sellers():
    """Sellers eligible for the Syndicator Dashboard: any person linked to a
    Sell Order deal (custom_label_1958 contains 5011675). Reads deals.json
    fresh from the shared CRM snapshot (short timeout, fail-closed -- an
    empty list on any error, same convention as _people_index()) and looks
    up each linked person's name/email via the existing people_index.json
    (never the raw 113 MB people.json -- see _people_index's own docstring
    on why that file is never loaded directly here). company_name comes
    from the deal's own "company" object, matching Pipeline's own linkage.
    Missing/unresolvable fields are skipped silently, per spec."""
    try:
        cfg = BotoConfig(connect_timeout=5, read_timeout=5, retries={"max_attempts": 1})
        s3 = boto3.client("s3", config=cfg)
        obj = s3.get_object(Bucket=COMPANIES_BUCKET, Key=DEALS_KEY)
        deals = json.loads(obj["Body"].read()).get("deals", [])
    except Exception:
        return []
    try:
        idx = _people_index().get("by_id", {})
    except Exception:
        idx = {}
    out = {}
    for deal in deals:
        if SELL_ORDER_OPTION_ID not in _deal_cf_option_ids(deal, SELL_ORDER_FIELD):
            continue
        company_name = ((deal.get("company") or {}).get("name") or "").strip()
        if not company_name:
            continue
        for pid in _deal_linked_person_ids(deal):
            if pid in out:
                continue
            rec = idx.get(str(pid))
            if not rec:
                continue
            full_name = (rec.get("name") or "").strip()
            email = (rec.get("email") or "").strip()
            if not full_name or not email:
                continue
            out[pid] = {"full_name": full_name, "company_name": company_name, "email": email}
    return sorted(out.values(), key=lambda r: r["company_name"].lower())


def render_admin_hub():
    """Admin-only index of every internal tool."""
    tiles = [
        ("Daily brief", "Your queue: invoices, closes, crossed trades, warm leads.",
         ADMIN_BRIEF_URL),
        ("Weekly mailer recipients", "First name and email for the SharePoint flow.",
         ADMIN_MAILER_URL),
        ("Third-party pricing", "Update Hiive bid, ask and mark for tracked names.",
         ADMIN_PRICING_URL),
        ("Auctions", "Create an auction, view the order book, invite buyers.",
         "?view=auctions"),
        ("Send a link", "Sign-in links for clients, update and LOI links for deals, "
                        "bid and offer links for companies.",
         "?view=sendlink"),
        ("All portfolios", "Every client's holdings in one roll-up.",
         "?view=portfolios"),
        ("Deal alerts", "Active deals with live counterparty match counts, and a "
                        "button to alert them.",
         ADMIN_ALERTS_URL),
        ("Deal matcher", "Paste an inbound inquiry, match it against the book, draft "
                         "the intro email.",
         "https://izahxskgeee5mihwi7y62v333q0ajkji.lambda-url.us-east-1.on.aws/?key=Vq83RkPnZ2wYhT6d"),
        ("News mailer composer", "Compose and send the company news mailer.",
         "https://bddpwqsqvt32ritxpjqlqwhaim0ykbol.lambda-url.us-east-1.on.aws/?view=news&key=alkj%2A707q235-qjdf"),
    ]
    # Every tool opens in its own tab, so the hub stays put behind them.
    cards = ""
    for title, desc, href in tiles:
        cards += (f'<a class="hub-card" href="{html.escape(href, quote=True)}"'
                  f' target="_blank" rel="noopener">'
                  f'<div class="hub-title">{html.escape(title)}</div>'
                  f'<div class="hub-desc">{html.escape(desc)}</div></a>')

    sellers = syndicator_eligible_sellers()
    seller_rows = ""
    for r in sellers[:50]:
        my_deals_href = f"{SYNDICATE_DASH_URL}&view_as={urllib.parse.quote(r['email'])}"
        intros_href = my_deals_href + "&tab=intros"
        seller_rows += (
            '<li class="syn-row">'
            f'<span class="syn-name">{html.escape(r["full_name"])}</span>'
            f' &middot; <span class="syn-co">{html.escape(r["company_name"])}</span>'
            f' &middot; <a href="{html.escape(my_deals_href, quote=True)}" target="_blank" rel="noopener">My Deals</a>'
            f' &middot; <a href="{html.escape(intros_href, quote=True)}" target="_blank" rel="noopener">Intros</a>'
            '</li>'
        )
    syn_card = (
        '<div class="hub-card syn-card">'
        '<div class="hub-title">Syndicator Dashboard</div>'
        f'<a href="{html.escape(SYNDICATE_DASH_URL, quote=True)}" target="_blank" rel="noopener">Open admin view</a>'
        f'<p class="syn-count">{len(sellers)} sellers eligible</p>'
        f'<ul class="syn-list">{seller_rows}</ul>'
        '</div>'
    )

    return html_response(f"""
    <style>
      .hub-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr));
                   gap:14px; margin-top:18px; }}
      .hub-card {{ display:block; border:1px solid var(--line); border-radius:8px;
                   padding:16px 18px; text-decoration:none; color:inherit;
                   background:#fff; transition:border-color .15s, background .15s; }}
      .hub-card:hover {{ border-color:var(--ink); background:#faf8f3; }}
      .hub-title {{ font-weight:600; font-size:16px; margin-bottom:5px; }}
      .hub-desc {{ font-size:13px; color:#6b7280; line-height:1.45; }}
      .syn-card {{ grid-column: 1 / -1; }}
      .syn-count {{ font-size:12px; color:#6b7280; margin:10px 0 6px; }}
      .syn-list {{ list-style:none; max-height:280px; overflow-y:auto; }}
      .syn-row {{ font-size:13px; padding:5px 0; border-top:1px solid var(--line); }}
      .syn-row:first-child {{ border-top:none; }}
      .syn-name {{ font-weight:600; }}
      .syn-co {{ color:#6b7280; }}
      .syn-row a {{ color:var(--ink); }}
    </style>
    <h1>Admin</h1>
    <p class="sub">Internal tools. Nothing here is visible to clients.</p>
    <div class="hub-grid">{cards}{syn_card}</div>
    """, eyebrow="Admin", is_admin=True, view="admin")


def _auc_deadline_cell(aid, close_date):
    """Deadline display (red 'Closed' once past) plus the inline edit form."""
    close_date = (close_date or "").strip()
    if not close_date:
        display = '<span class="wl-soft">No deadline</span>'
    else:
        try:
            is_past = datetime.strptime(close_date, "%Y-%m-%d").date() < datetime.now(timezone.utc).date()
        except ValueError:
            is_past = False
        pretty = html.escape(_auc_date(close_date))
        if is_past:
            display = (f'<span class="auc-deadline-past">{pretty} Closed</span>')
        else:
            display = pretty
    return (
        f'<td>{display}'
        f'<form method="POST" action="?view=auctions" class="auc-deadline-form">'
        f'<input type="hidden" name="action" value="auction_set_deadline">'
        f'<input type="hidden" name="auction_id" value="{html.escape(aid, quote=True)}">'
        f'<input type="date" name="close_date" value="{html.escape(close_date, quote=True)}">'
        f'<button type="submit" class="auc-btn-sm">Update</button>'
        f'</form></td>'
    )


def render_auctions_admin(msg=""):
    rows = ""
    for aid, a in sorted(_load_auctions().items(),
                         key=lambda kv: kv[1].get("created_at") or "", reverse=True):
        _bids = _load_auction_bids(aid)
        _ranked = sorted(_bids.values(),
                         key=lambda b: -(_auc_num(b.get("gross")) or 0))
        _topb = _ranked[0] if _ranked else None
        _topv = _auc_num(_topb.get("gross")) if _topb else None
        # Precomputed: a nested "shares" lookup inside the f-string below would
        # collide with the quotes already delimiting it.
        _shares = a.get("shares")
        _shares_cell = f"{int(_shares):,}" if _shares else "&mdash;"
        rows += (
            "<tr>"
            f'<td><strong>{html.escape(a.get("company") or "")}</strong></td>'
            f'<td>{_wl_pps(a.get("ask")) if a.get("ask") else "&mdash;"}</td>'
            f'<td>{_wl_pps(_topv) if _topv else "&mdash;"}</td>'
            f'<td>{html.escape((_topb.get("name") or _topb.get("email") or "")) if _topb else "&mdash;"}</td>'
            f'<td>{_wl_money(a.get("min_size")) if a.get("min_size") else "&mdash;"} &ndash; '
            f'{_wl_money(a.get("max_size")) if a.get("max_size") else "&mdash;"}</td>'
            f'<td>{_shares_cell}</td>'
            f'{_auc_deadline_cell(aid, a.get("close_date"))}'
            f'<td class="auc-id">{html.escape(aid)}'
            f'<button type="button" class="auc-copy" onclick="aucCopy(\'{html.escape(aid, quote=True)}\')"'
            f' title="Copy auction ID">&#10697;</button></td>'
            f'<td><a href="?view=auction&amp;id={html.escape(aid, quote=True)}">View</a>'
            f' &middot; <a href="?view=invites&amp;id={html.escape(aid, quote=True)}">Invite</a>'
            f' &middot; <form method="POST" action="?view=auctions" style="display:inline;"'
            f' onsubmit="return confirm(\'Delete this auction? Bids are kept in S3 but '
            f'will no longer be reachable.\');">'
            f'<input type="hidden" name="action" value="auction_delete">'
            f'<input type="hidden" name="auction_id" value="{html.escape(aid, quote=True)}">'
            f'<button type="submit" class="auc-del">Delete</button></form></td>'
            "</tr>"
        )
    if not rows:
        rows = '<tr><td colspan="9" class="wl-soft">No auctions yet.</td></tr>'
    banner = f'<p style="color:#1f7a4d; font-weight:600;">{html.escape(msg)}</p>' if msg else ""
    return html_response(f"""
    <style>
      .auc-grid {{ display:grid; grid-template-columns:repeat(2,minmax(200px,1fr));
                   gap:12px 16px; max-width:720px; margin:14px 0 18px; }}
      .auc-grid label {{ display:block; font-size:13px; font-weight:600; margin-bottom:4px; }}
      .auc-grid input {{ width:100%; padding:9px 12px; font-family:inherit; font-size:14px;
                         border:1px solid var(--line); border-radius:6px; }}
      .auc-full {{ grid-column:1 / -1; }}
      .auc-id {{ font-family:ui-monospace,monospace; font-size:12px; white-space:nowrap; }}
      .auc-copy {{ border:none; background:none; cursor:pointer; color:#6b7280;
                   font-size:13px; padding:0 4px; }}
      .auc-del {{ border:none; background:none; padding:0; cursor:pointer;
                  font-family:inherit; font-size:inherit; color:#b45309;
                  text-decoration:underline; }}
      .auc-btn {{ padding:10px 20px; font-family:inherit; font-size:14px; font-weight:600;
                  border:none; border-radius:6px; background:var(--ink); color:#fff;
                  cursor:pointer; }}
      table.auc {{ width:100%; border-collapse:collapse; font-size:14px; margin-top:8px; }}
      table.auc th, table.auc td {{ border:1px solid #ddd; padding:10px 12px; text-align:left; }}
      table.auc th {{ font-size:12px; letter-spacing:.06em; text-transform:uppercase; }}
      .wl-h2 {{ font-size:17px; margin:22px 0 10px; }}
      .wl-soft {{ color:#6b7280; }}
      .auc-deadline-past {{ color:#b00020; font-weight:700; }}
      .auc-deadline-form {{ display:flex; align-items:center; gap:6px; margin-top:6px; }}
      .auc-deadline-form input[type=date] {{ padding:5px 8px; font-family:inherit; font-size:13px;
                   border:1px solid var(--line); border-radius:6px; }}
      .auc-btn-sm {{ padding:5px 10px; font-family:inherit; font-size:12px; font-weight:600;
                     border:none; border-radius:6px; background:var(--ink); color:#fff;
                     cursor:pointer; }}
    </style>
    <h1>Auctions</h1>
    <p class="sub">Create an auction, then share its link with interested buyers.</p>
    {banner}
    <form method="POST" action="?view=auctions">
      <input type="hidden" name="action" value="auction_create">
      <div class="auc-grid">
        <div><label>Company</label><input name="company" required placeholder="Hadrian"></div>
        <div><label>Seed deal ID (optional)</label><input name="deal_id" placeholder="55266875"></div>
        <div><label>Reserve price per share</label><input name="ask" placeholder="110"></div>
        <div><label>Shares (optional)</label><input name="shares" placeholder="100000"></div>
        <div><label>Structure</label><input name="structure" placeholder="Direct Transfer"></div>
        <div><label>Bids close (blank = open-ended)</label><input name="close_date" type="date"></div>
        <div><label>Min size ($)</label><input name="min_size" placeholder="250000"></div>
        <div><label>Max size ($)</label><input name="max_size" placeholder="10000000"></div>
        <div class="auc-full"><label>Note to buyers (optional)</label>
          <input name="note" placeholder="Seller reviewing bids week of the 15th."></div>
        <div class="auc-full"><button class="auc-btn" type="submit">Create auction</button></div>
      </div>
    </form>
    <h2 class="wl-h2">Live auctions</h2>
    <table class="auc">
      <thead><tr><th>Company</th><th>Reserve</th><th>Top bid</th><th>Top bidder</th>
        <th>Size</th><th>Shares</th><th>Deadline</th><th>Auction ID</th><th></th></tr></thead>
      <tbody>{rows}</tbody></table>
    <script>
      function aucCopy(t) {{ navigator.clipboard.writeText(t); }}
    </script>
    """, is_admin=True, view="auctions")


def _auction_bids_key(auction_id):
    return f"bids/auction_{auction_id}.json"


def _load_auction_bids(auction_id):
    """Bid book for one auction, keyed by lowercased email. Never raises."""
    try:
        obj = boto3.client("s3").get_object(Bucket=COMPANIES_BUCKET,
                                            Key=_auction_bids_key(auction_id))
        data = json.loads(obj["Body"].read())
        return data.get("bids") or {}
    except Exception:
        return {}


def _load_auction_alerts(auction_id):
    """Alert subscribers for one auction, keyed by lowercased email. Never raises."""
    try:
        obj = boto3.client("s3").get_object(Bucket=COMPANIES_BUCKET,
                                            Key=_auction_bids_key(auction_id))
        data = json.loads(obj["Body"].read())
        return data.get("alerts") or {}
    except Exception:
        return {}


def _set_auction_alert(auction_id, email, person_id, name, on):
    """Turn top-bid alerts on/off for one person. Lives in the same bids file."""
    key = _auction_bids_key(auction_id)
    s3 = boto3.client("s3")
    try:
        obj = s3.get_object(Bucket=COMPANIES_BUCKET, Key=key)
        book = json.loads(obj["Body"].read())
    except Exception:
        book = {}
    alerts = book.get("alerts") or {}
    ekey = (email or "").strip().lower()
    if not ekey:
        return
    if on:
        alerts[ekey] = {"pid": str(person_id), "name": name or ""}
    else:
        alerts.pop(ekey, None)
    book["alerts"] = alerts
    s3.put_object(Bucket=COMPANIES_BUCKET, Key=key,
                  Body=json.dumps(book, ensure_ascii=False).encode("utf-8"),
                  ContentType="application/json")


def _auction_bid_notifications(auction_id, bidder_email, bidder_name, gross,
                               prior_top, base_url):
    """After a saved bid: always tell Chad; if the top bid rose, email subscribers."""
    auc = (_load_auctions() or {}).get(str(auction_id)) or {}
    company = auc.get("company") or "the company"
    _notify_chad(
        f"[Auction] New bid - {company} - {_wl_pps(gross)}",
        (f"Bidder:  {bidder_name} <{bidder_email}>\n"
         f"Bid:     {_wl_pps(gross)}/share\n"
         f"Company: {company}\n"
         f"Auction: {auction_id}\n"
         f"Prior top bid: {_wl_pps(prior_top) if prior_top else 'none'}\n"),
    )
    if not (gross and gross > (prior_top or 0)):
        return
    aid_q = urllib.parse.quote(str(auction_id))
    for ekey, sub in (_load_auction_alerts(auction_id) or {}).items():
        if ekey == (bidder_email or "").strip().lower():
            continue
        pid = (sub or {}).get("pid") or ""
        if not pid:
            continue
        link = (f"{base_url}/?client={pid}&token={make_token(str(pid))}"
                f"&view=auction&id={aid_q}")
        first = ((sub or {}).get("name") or "").strip().split(" ")[0] or "there"
        _send_email(
            ekey,
            f"New top bid on {company}: {_wl_pps(gross)}/share",
            (f"Hi {first},\n\n"
             f"The top bid on {company} just moved to {_wl_pps(gross)} per share.\n\n"
             "If you want the block, you can raise your bid here:\n"
             f"{link}\n\n"
             "You're receiving this because you asked to be alerted when the top "
             "bid changes. You can turn alerts off on the same page.\n\n"
             "Chad Gracia\nRainmaker Securities\n"),
        )


AUC_IQF_FIELD = "custom_label_3763008"
AUC_IQF_OK = {6496840, 6596073}          # Yes, Unnecessary
AUC_TRANSACTOR_FIELD = "custom_label_3759163"
AUC_NATURAL_PERSON = 6484810
IQF_ENTITY_URL = "https://www.rainmakersecurities.com/investor-qualification-form-for-entity-persons"
IQF_NATURAL_URL = "https://www.rainmakersecurities.com/investor-qualification-form-for-natural-persons"


def _auction_iqf(person_id):
    """(is_cleared, form_url) for one person. Falls back to the entity form."""
    try:
        jwt = get_jwt()
        res = call_pipeline_api("GET", f"/people/{person_id}.json", jwt=jwt)
        if res.get("status") != 200 or not isinstance(res.get("data"), dict):
            return False, IQF_ENTITY_URL
        cf = res["data"].get("custom_fields") or {}
        cleared = bool(set(cf_id_list(cf.get(AUC_IQF_FIELD))) & AUC_IQF_OK)
        natural = AUC_NATURAL_PERSON in cf_id_list(cf.get(AUC_TRANSACTOR_FIELD))
        return cleared, (IQF_NATURAL_URL if natural else IQF_ENTITY_URL)
    except Exception as e:
        print(f"auction: IQF lookup failed for {person_id}: {e}")
        return False, IQF_ENTITY_URL


def _save_auction_bid(auction_id, email, name, bid):
    """Record one bid, keyed by lowercased email so a resubmission replaces it."""
    key = f"bids/auction_{auction_id}.json"
    s3 = boto3.client("s3")
    try:
        obj = s3.get_object(Bucket=COMPANIES_BUCKET, Key=key)
        book = json.loads(obj["Body"].read())
    except Exception:
        book = {}
    bids = book.get("bids") or {}
    ekey = (email or "").strip().lower()
    if not ekey:
        return
    prior = bids.get(ekey) or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bid["email"] = ekey
    bid["name"] = name or prior.get("name") or ""
    bid["updated_at"] = now
    bid["first_seen"] = prior.get("first_seen") or now
    bid["revisions"] = int(prior.get("revisions") or 0) + 1
    bids[ekey] = bid
    book["bids"] = bids
    s3.put_object(Bucket=COMPANIES_BUCKET, Key=key,
                  Body=json.dumps(book, ensure_ascii=False).encode("utf-8"),
                  ContentType="application/json")


def _delete_auction_bid(auction_id, email):
    """Drop one bid from the book. Alerts and every other bid are left alone.
    Returns True only when a bid was actually removed."""
    key = _auction_bids_key(auction_id)
    s3 = boto3.client("s3")
    try:
        obj = s3.get_object(Bucket=COMPANIES_BUCKET, Key=key)
        book = json.loads(obj["Body"].read())
    except Exception:
        return False
    bids = book.get("bids") or {}
    ekey = (email or "").strip().lower()
    if ekey not in bids:
        return False
    del bids[ekey]
    book["bids"] = bids
    s3.put_object(Bucket=COMPANIES_BUCKET, Key=key,
                  Body=json.dumps(book, ensure_ascii=False).encode("utf-8"),
                  ContentType="application/json")
    return True


def _js_lit(s):
    """Body of a single-quoted JS string, safe inside a double-quoted HTML attribute.
    Everything outside a small allowlist becomes a \\uXXXX escape, so a quote or an
    ampersand in a bidder's name can't close the attribute or start an entity."""
    safe = " .,:;!?@#$%^*()-_+=/|[]{}"
    out = []
    for ch in str(s or ""):
        if ch.isalnum() or ch in safe:
            out.append(ch)
        elif ord(ch) < 0x10000:
            out.append("\\u%04x" % ord(ch))
    return "".join(out)


AUC_CLASS_FIELD = "custom_label_3064330"
AUC_SHARES_FIELD = "custom_label_3070843"
AUC_CLASS_LABELS = {5077831: "Common", 5077834: "Preferred",
                    5077912: "Mixed", 5077915: "Any"}


def _auc_date(raw):
    """2026/07/28 or 2026-07-28 -> July 28, 2026. Returns the input on failure."""
    s = (raw or "").strip().replace("/", "-")
    for fmt in ("%Y-%m-%d", "%m-%d-%Y"):
        try:
            return datetime.strptime(s, fmt).strftime("%B %-d, %Y")
        except ValueError:
            continue
    return raw or ""


def _auction_deal_facts(deal_id, company_name):
    """Key data points for the seeded deal plus its company. Never raises."""
    out = {"logo": "", "description": "", "catalyst": "", "share_class": "",
           "shares": None, "notes": "", "lr_pps": None, "lr_val": None,
           "lr_series": "", "lr_date": "", "seller": ""}
    try:
        norm = re.sub(r"[^a-zA-Z0-9]", "", company_name or "")
        if norm:
            out["logo"] = f"https://bannerlogos.s3.us-east-1.amazonaws.com/{norm}.png"
    except Exception:
        pass
    if not deal_id:
        return out
    try:
        jwt = get_jwt()
        res = call_pipeline_api("GET", f"/deals/{deal_id}.json", jwt=jwt)
        if res.get("status") != 200 or not isinstance(res.get("data"), dict):
            return out
        deal = res["data"]
        cf = deal.get("custom_fields") or {}
        out["notes"] = (deal.get("summary") or "").strip()
        for oid in cf_id_list(cf.get(AUC_CLASS_FIELD)):
            if oid in AUC_CLASS_LABELS:
                out["share_class"] = AUC_CLASS_LABELS[oid]
                break
        out["shares"] = _auc_num(cf.get(AUC_SHARES_FIELD))
        co_id = (deal.get("company") or {}).get("id")
        if co_id:
            cres = call_pipeline_api("GET", f"/companies/{co_id}.json", jwt=jwt)
            if cres.get("status") == 200 and isinstance(cres.get("data"), dict):
                co = cres["data"]
                ccf = co.get("custom_fields") or {}
                out["description"] = (co.get("description") or "").strip()
                out["catalyst"] = (ccf.get("custom_label_3999603") or "").strip()
                out["lr_pps"] = _auc_num(ccf.get("custom_label_3064363"))
                out["lr_val"] = _auc_num(ccf.get("custom_label_3790429"))
                out["lr_series"] = (ccf.get("custom_label_3914626") or "").strip()
                out["lr_date"] = (ccf.get("custom_label_3826032") or "").strip()
    except Exception as e:
        print(f"auction: deal facts failed for {deal_id}: {e}")
    return out


def _interest_built_text(raw):
    """Prose for interest_people.json's last_updated, e.g.
    "Buyer list built August 7, 2026 at 15:33 UTC."

    The file is written by another Lambda, so the value's exact shape isn't ours to
    assume: ISO-8601 (with or without T, Z, offset or microseconds), a bare date, and
    a unix epoch all parse. Anything else is shown verbatim rather than swallowed, and
    a missing key says so outright instead of implying the list is fresh."""
    s = str(raw or "").strip()
    if not s:
        return "Buyer list build time unknown &mdash; interest_people.json has no last_updated key."
    dt, has_time = None, False
    if re.fullmatch(r"\d{9,13}", s):                     # unix epoch, seconds or millis
        try:
            _ts = int(s)
            dt = datetime.fromtimestamp(_ts / 1000 if len(s) > 10 else _ts, timezone.utc)
            has_time = True
        except (ValueError, OSError, OverflowError):
            dt = None
    if dt is None:
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T", 1))
            has_time = ":" in s                           # a bare date has no clock
        except ValueError:
            dt = None
    if dt is None:
        pretty = _auc_date(s)                             # bare date -> prose, else raw
        if pretty != s:
            return f"Buyer list built {html.escape(pretty)}."
        return f"Buyer list built &mdash; unrecognised timestamp {html.escape(s)}."
    dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    if not has_time:
        return f"Buyer list built {html.escape(_auc_date(dt.strftime('%Y-%m-%d')))}."
    return (f"Buyer list built {html.escape(_auc_date(dt.strftime('%Y-%m-%d')))} "
            f"at {dt.strftime('%H:%M')} UTC.")


def render_auction_invites(auction_id, base_url, err=""):
    """Admin-only: name, email and magic link for every buyer of this company."""
    auc = (_load_auctions() or {}).get(str(auction_id))
    if not auc:
        return html_response("<h1>Auction not found</h1>")
    company = auc.get("company") or ""
    _built_raw = ""
    try:
        obj = boto3.client("s3").get_object(Bucket=COMPANIES_BUCKET,
                                            Key="interest_people.json")
        _people = json.loads(obj["Body"].read())
        pids = (_people.get("buy") or {}).get(company) or []
        _built_raw = _people.get("last_updated") or ""
    except Exception as e:
        print(f"invites: could not load interest_people.json: {e}")
        pids = []

    idx = (_people_index().get("by_id", {}) or {})
    rows = ""
    for pid in pids:
        rec = idx.get(str(pid)) or {}
        nm = html.escape((rec.get("name") or rec.get("first_name") or "").strip())
        em = html.escape((rec.get("email") or "").strip())
        _aid = urllib.parse.quote(str(auction_id))
        link = (f"{base_url}/?client={pid}&token={make_token(str(pid))}"
                f"&view=auction&id={_aid}")
        preview = f"{base_url}/?as={pid}&view=auction&id={_aid}"
        rows += ("<tr>"
                 f"<td>{nm}</td><td>{em}</td>"
                 f'<td><input class="inv-url" readonly value="{html.escape(link, quote=True)}"'
                 ' onclick="this.select()"></td>'
                 f'<td><a href="{html.escape(preview, quote=True)}" target="_blank">'
                 'Preview</a></td>'
                 "</tr>")
    if not rows:
        rows = ('<tr><td colspan="4" class="wl-soft">No buyers found for this company '
                'in interest_people.json.</td></tr>')

    _aid_q = html.escape(str(auction_id), quote=True)
    built_html = f'<p class="inv-built">{_interest_built_text(_built_raw)}</p>'
    # err arrives via the redirect after a failed refresh, so it is attacker-influenced
    # only by an admin's own URL bar; escape it anyway before reflecting it.
    err_html = f'<p class="inv-err">{html.escape(err)}</p>' if err else ""
    refresh_html = f"""
    <form class="inv-refresh" method="POST" action="?view=invites&amp;id={_aid_q}"
          onsubmit="return invRefresh(this);">
      <input type="hidden" name="action" value="interest_refresh">
      <input type="hidden" name="auction_id" value="{_aid_q}">
      <button type="submit" class="inv-btn">Refresh buyer list</button>
      <span class="wl-soft inv-hint">Rebuilds from Pipeline &mdash; takes about eight seconds.</span>
    </form>"""
    return html_response(f"""
    <style>
      table.inv {{ width:100%; border-collapse:collapse; font-size:14px; }}
      table.inv th, table.inv td {{ border:1px solid #ddd; padding:9px 11px;
                                    text-align:left; vertical-align:middle; }}
      table.inv th {{ font-size:12px; letter-spacing:.06em; text-transform:uppercase; }}
      .inv-url {{ width:100%; font-family:ui-monospace,monospace; font-size:11px;
                  border:none; background:none; }}
      .wl-soft {{ color:#6b7280; }}
      .inv-built {{ font-size:13px; color:#6b7280; margin:0 0 14px; }}
      .inv-err {{ font-size:13px; color:#b45309; font-weight:600; margin:0 0 14px; }}
      .inv-refresh {{ display:flex; align-items:center; gap:12px;
                      flex-wrap:wrap; margin:0 0 18px; }}
      .inv-btn {{ padding:9px 16px; font-family:inherit; font-size:14px; font-weight:600;
                  border:1px solid var(--line); border-radius:6px; background:#fff;
                  color:inherit; cursor:pointer; }}
      .inv-btn:hover:enabled {{ border-color:var(--ink); }}
      .inv-btn:disabled {{ opacity:.55; cursor:default; }}
      .inv-hint {{ font-size:12px; }}
    </style>
    <h1>Invite buyers &mdash; {html.escape(company)}</h1>
    <p class="sub">{len(pids)} buyer{'' if len(pids) == 1 else 's'} carry this company in
    Buy Interest. Each link signs that person in; do not forward them.</p>
    {built_html}
    {err_html}
    {refresh_html}
    <table class="inv"><thead><tr><th>Name</th><th>Email</th><th>Link</th><th></th></tr></thead>
      <tbody>{rows}</tbody></table>
    <script>
      function invRefresh(f) {{
        var b = f.querySelector("button");
        var h = f.querySelector(".inv-hint");
        b.textContent = "Refreshing\\u2026";
        if (h) {{ h.textContent = "Rebuilding the buyer list; this takes about eight seconds."; }}
        // Disable after the submit is under way: a button disabled synchronously in
        // onsubmit is dropped from the POST body by some browsers.
        setTimeout(function () {{ b.disabled = true; }}, 0);
        return true;
      }}
    </script>
    """, eyebrow="Invite buyers", is_admin=True)


# Why an in-place edit of the order book didn't stick. Shown above the table.
AUC_BOOK_ERRS = {
    "bidedit": "That change wasn't saved &mdash; a bid needs a price greater than 0.",
    "bidstale": "That bid changed somewhere else while this page was open, so nothing "
                "was written. The book below is current &mdash; make the change again.",
    "bidgone": "That bid is no longer in the book &mdash; it may have just been removed.",
    "bidsave": "That change could not be written to the bid book. Please try again.",
}


def render_auction(auction_id, client_id, is_admin, err=""):
    auc = (_load_auctions() or {}).get(str(auction_id))
    if not auc:
        return html_response("<h1>Auction not found</h1>"
                             "<p class='wl-soft'>This link may have expired.</p>",
                             view="auction", client_id=client_id)

    company = auc.get("company") or ""
    bids = _load_auction_bids(auction_id)
    ranked = sorted(bids.values(),
                    key=lambda b: (-(_auc_num(b.get("gross")) or 0),
                                   b.get("updated_at") or ""))

    me = None
    try:
        _idx = (_people_index().get("by_id", {}) or {}).get(str(client_id)) or {}
        my_email = (_idx.get("email") or "").strip().lower()
        if my_email:
            me = bids.get(my_email)
    except Exception as e:
        print(f"auction: could not resolve viewer email: {e}")

    top = _auc_num(ranked[0].get("gross")) if ranked else None
    low = _auc_num(ranked[-1].get("gross")) if ranked else None

    _buyers = _wl_buyers(company) or int(auc.get("buyers") or 0)
    bid_stats = ""
    if top:
        bid_stats += (f'<div class="au-bstat"><span class="au-lrlbl">Top bid</span>'
                      f'<span class="au-bval">{_wl_pps(top)}</span></div>')
    if _buyers:
        bid_stats += (f'<div class="au-bstat"><span class="au-lrlbl">Buyers</span>'
                      f'<span class="au-bval">{_buyers:,}</span></div>')
    bid_stats = f'<div class="au-bstats">{bid_stats}</div>' if bid_stats else ""

    facts = _auction_deal_facts(auc.get("deal_id"), company)
    _f = []
    if auc.get("structure"):
        _f.append(("Structure", html.escape(auc["structure"])))
    if facts["share_class"]:
        _f.append(("Share class", html.escape(facts["share_class"])))
    if auc.get("min_size"):
        _f.append(("Size", f'{_wl_money(auc.get("min_size"))} &ndash; '
                           f'{_wl_money(auc.get("max_size"))}'))
    if facts["shares"]:
        _f.append(("Shares", f"{int(facts['shares']):,}"))
    _resv = _auc_num(auc.get("ask"))
    if _resv and is_admin:
        _rmet = bool(top and top >= _resv)
        _rhtml = (f'<strong>{_wl_pps(_resv)}</strong> '
                  f'<span class="{"au-ok" if _rmet else "au-unmet"}">'
                  f'&middot; {"Met" if _rmet else "Unmet"}</span>')
        _seller = (facts.get("seller") or "").strip()
        if _seller:
            _rhtml += (f' <span class="au-seller">&middot; '
                       f'{html.escape(_seller.split()[-1])}</span>')
        _f.append(("Reserve", _rhtml))
    _lr = []
    if facts["lr_date"]:
        _lr.append(("Date", html.escape(_auc_date(facts["lr_date"]))))
    if facts["lr_series"]:
        _lr.append(("Series", html.escape(facts["lr_series"])))
    if facts["lr_pps"]:
        _lr.append(("Price per share", _wl_pps(facts["lr_pps"])))
    if facts["lr_val"]:
        _lr.append(("Valuation", f"${facts['lr_val']:,.2f}B"))
    lr_html = ""
    if _lr or facts["catalyst"]:
        _left = ""
        if _lr:
            _left = ('<div class="au-lrhead">Last round</div><div class="au-lrgrid">'
                     + "".join(f'<div><span class="au-lrlbl">{l}</span>'
                               f'<span class="au-lrval">{v}</span></div>' for l, v in _lr)
                     + "</div>")
        _right = ""
        if facts["catalyst"]:
            _right = ('<div class="au-lrhead">Recent development</div>'
                      f'<div class="au-lrdev">{html.escape(facts["catalyst"])}</div>')
        lr_html = (f'<div class="au-lr"><div class="au-lrcols">'
                   f'<div class="au-lrleft">{_left}</div>'
                   f'<div class="au-lrright">{_right}</div></div></div>')
    _cells = ""
    for _i in range(0, len(_f), 2):
        _pair = _f[_i:_i + 2]
        _cells += "<tr>"
        for _lbl, _val in _pair:
            _cells += f'<th class="au-th">{_lbl}</th><td class="au-td">{_val}</td>'
        if len(_pair) == 1:
            _cells += '<th class="au-th"></th><td class="au-td"></td>'
        _cells += "</tr>"
    facts_rows = f'<table class="au-ftable">{_cells}</table>' if _f else ""
    logo_html = (f'<img class="au-logo" src="{html.escape(facts["logo"], quote=True)}" '
                 f'alt="" onerror="this.style.display=\'none\'">'
                 if facts["logo"] else "")
    desc_html = (f'<p class="au-desc">{html.escape(facts["description"])}</p>'
                 if facts["description"] else "")
    cat_html = ""
    notes_html = (f'<div class="au-cat"><div class="au-catlbl">Seller notes</div>'
                  f'<div>{html.escape(facts["notes"])}</div></div>'
                  if facts["notes"] else "")
    _did = str(auc.get("deal_id") or "")
    _aid_s = str(auction_id)
    _bits = ""
    if _did:
        _bits += (f'<span class="au-idbit">Deal ID: '
                  f'<a href="https://app.pipelinedeals.com/deals/{html.escape(_did, quote=True)}"'
                  f' target="_blank">{html.escape(_did)}</a>'
                  f'<button type="button" class="au-copy" onclick="auCopy(\'{html.escape(_did, quote=True)}\')"'
                  f' title="Copy deal ID">&#10697;</button></span>')
    _bits += (f'<span class="au-idbit">Auction ID: {html.escape(_aid_s)}'
              f'<button type="button" class="au-copy" onclick="auCopy(\'{html.escape(_aid_s, quote=True)}\')"'
              f' title="Copy auction ID">&#10697;</button></span>')
    id_html = f'<div class="au-did">{_bits}</div>'
    header_html = (f'<div class="au-head">{logo_html}'
                   f'<div class="au-headtext"><h1>{html.escape(company)}'
                   f'{(" &mdash; " + html.escape(auc.get("structure"))) if auc.get("structure") else ""}</h1>'
                   f'{desc_html}{id_html}</div></div>')
    details_html = (f'<div class="au-details"><div class="au-boxhead">Deal details</div>'
                    f'{facts_rows}{cat_html}{notes_html}{lr_html}</div>'
                    if (facts_rows or cat_html or notes_html or lr_html) else "")

    deadline_html = (f'<p class="au-deadline">Bids close '
                     f'{html.escape(_auc_date(auc.get("close_date")))}.</p>'
                     if auc.get("close_date") else "")

    side_panel = ""
    if is_admin:
        # The book is editable in place: clients call and text with new numbers, and
        # an admin needs to move a bid without impersonating the bidder. Each row's
        # inputs live in the cells but belong to a form further down the page (the
        # HTML5 form= attribute), because a <form> can't legally wrap a row's cells.
        _aid_q = html.escape(str(auction_id), quote=True)

        def _amt(v):
            n = _auc_num(v)
            return f"{int(n):,}" if n else ""

        rows = ""
        row_forms = ""
        demand = 0.0
        for i, b in enumerate(ranked, 1):
            mx = _auc_num(b.get("max_size")) or 0
            demand += mx
            if b.get("person_id"):
                cleared, _ = _auction_iqf(b["person_id"])
            else:
                cleared = False
            iqf_cell = ('<span class="au-ok">&#10003;</span>' if cleared
                        else '<span class="au-bad">&#10007;</span>')
            _bmail = (b.get("email") or "")
            _bname = (b.get("name") or "")
            _fid = f"aubid{i}"
            _coh = (b.get("cash_on_hand") or "")
            _gross = _auc_num(b.get("gross"))
            _gross_s = f"{_gross:,.2f}" if _gross is not None else ""
            _sel = ('' if _coh in ("yes", "no") else ' selected',
                    ' selected' if _coh == "yes" else '',
                    ' selected' if _coh == "no" else '')
            rows += (
                "<tr>"
                f"<td>{i}</td>"
                f'<td>{html.escape(_bname)}</td>'
                f'<td>{html.escape(_bmail)}</td>'
                f'<td><input class="au-rin au-rprice" form="{_fid}" name="gross"'
                f' type="text" inputmode="decimal" aria-label="Bid per share"'
                f' value="{html.escape(_gross_s, quote=True)}"></td>'
                f'<td class="au-rsize">'
                f'<input class="au-rin" form="{_fid}" name="min_size" type="text"'
                f' inputmode="numeric" aria-label="Min size"'
                f' value="{_amt(b.get("min_size"))}">'
                '<span class="au-rdash">&ndash;</span>'
                f'<input class="au-rin" form="{_fid}" name="max_size" type="text"'
                f' inputmode="numeric" aria-label="Max size"'
                f' value="{_amt(b.get("max_size"))}">'
                "</td>"
                f"<td>{iqf_cell}</td>"
                f'<td><select class="au-rin{" au-bad" if _coh == "no" else ""}"'
                f' form="{_fid}" name="cash_on_hand" aria-label="Cash on hand">'
                f'<option value=""{_sel[0]}>&mdash;</option>'
                f'<option value="yes"{_sel[1]}>Funded</option>'
                f'<option value="no"{_sel[2]}>Syndicating</option>'
                "</select></td>"
                f'<td><input class="au-rin" form="{_fid}" name="note" type="text"'
                f' aria-label="Note" value="{html.escape(b.get("note") or "", quote=True)}">'
                "</td>"
                f'<td>{html.escape((b.get("updated_at") or "")[:10])}</td>'
                f'<td class="au-racts">'
                f'<button class="au-rsave" type="submit" form="{_fid}">Save</button>'
                f'<button class="au-rdel" type="submit" form="{_fid}x">Remove</button>'
                "</td>"
                "</tr>"
            )
            # prev_updated_at is the optimistic-concurrency check: the save is
            # refused if this bid moved after the page was drawn.
            _who = _js_lit(_bname or _bmail or "this bidder")
            row_forms += (
                f'<form id="{_fid}" method="POST"'
                f' action="?view=auction&amp;id={_aid_q}">'
                '<input type="hidden" name="action" value="auction_bid_edit">'
                f'<input type="hidden" name="auction_id" value="{_aid_q}">'
                f'<input type="hidden" name="email"'
                f' value="{html.escape(_bmail, quote=True)}">'
                f'<input type="hidden" name="prev_updated_at"'
                f' value="{html.escape(b.get("updated_at") or "", quote=True)}">'
                "</form>"
                f'<form id="{_fid}x" method="POST"'
                f' action="?view=auction&amp;id={_aid_q}"'
                f" onsubmit=\"return confirm('Remove the bid from {_who}?"
                f" This deletes it from the book and cannot be undone.')\">"
                '<input type="hidden" name="action" value="auction_bid_remove">'
                f'<input type="hidden" name="auction_id" value="{_aid_q}">'
                f'<input type="hidden" name="email"'
                f' value="{html.escape(_bmail, quote=True)}">'
                "</form>"
            )
        if not rows:
            rows = '<tr><td colspan="10" class="wl-soft">No bids yet.</td></tr>'
        dem_line = (f'<p class="wl-soft">Total demand at max size: '
                    f'<strong>{_wl_money(demand)}</strong> across {len(ranked)} '
                    f'bid{"" if len(ranked) == 1 else "s"}.</p>') if ranked else ""
        edit_hint = ('<p class="wl-soft au-bookhint">Price, size, funding and notes are '
                     'editable here &mdash; Save writes the change back to the bid book '
                     'and re-ranks it.</p>') if ranked else ""
        err_line = (f'<p class="au-bad au-bookerr">{AUC_BOOK_ERRS[err]}</p>'
                    if err in AUC_BOOK_ERRS else "")
        book = ('<h2 class="wl-h2">Order book</h2>'
                + err_line + dem_line + edit_hint +
                '<table class="auc"><thead><tr><th>#</th><th>Name</th><th>Email</th>'
                '<th>Bid ($/sh)</th><th>Size ($)</th><th>IQF</th><th>Funding</th>'
                '<th>Notes</th><th>Updated</th><th></th></tr></thead>'
                f'<tbody>{rows}</tbody></table>'
                f'<div class="au-rowforms">{row_forms}</div>')
    else:
        if me:
            my_rank = next((i for i, b in enumerate(ranked, 1)
                            if (b.get("email") or "") == (me.get("email") or "")), None)
            _mine = _auc_num(me.get("gross")) or 0
            if my_rank == 1:
                standing = (f'<p class="au-standing au-lead">You hold the top bid at '
                            f'<strong>{_wl_pps(me.get("gross"))}</strong> '
                            f'of {len(ranked)} bid{"" if len(ranked) == 1 else "s"}.</p>')
            else:
                standing = (f'<p class="au-standing au-bad">You have been outbid. Your bid is '
                            f'{_wl_pps(me.get("gross"))}, ranked {my_rank} of {len(ranked)}. '
                            f'The top bid is {_wl_pps(top)}.</p>')
        elif ranked:
            standing = ""
        else:
            standing = ('<p class="au-standing wl-soft">No bids have been placed yet. '
                        'Be the first.</p>')

        # Cleared is reassurance, so it sits at the foot of the bid box next to the
        # button. Not cleared is a prompt for someone who has already bid, so it stays
        # in the main column where it carries weight.
        cleared, iqf_url = _auction_iqf(client_id)
        iqf_ok_html = ""
        if cleared:
            iqf_html = ""
            iqf_ok_html = ('<p class="au-iqfok">&#10003; We have your Investor '
                           'Qualification Form, you are ready to proceed.</p>')
        elif me:
            iqf_html = ('<p class="au-iqf">Your bid is in. We can only present bids from '
                        'verified accredited investors, so the next step is your Investor '
                        f'Qualification Form. <a href="{iqf_url}" target="_blank">'
                        'Complete it here</a> &mdash; it takes a few minutes and clears you '
                        'for this and any future allocation.</p>')
        else:
            iqf_html = ""

        _pv = me.get("gross") if me else ""
        _mn = me.get("min_size") if me else auc.get("min_size")
        _mx = me.get("max_size") if me else auc.get("max_size")
        _nt = html.escape(str(me.get("note") or ""), quote=True) if me else ""
        _coh = (me or {}).get("cash_on_hand")
        _err_html = ('<p class="au-bad">That bid wasn\'t saved &mdash; enter a number '
                     'greater than 0, e.g. 118.50.</p>') if err == "bid" else ""
        try:
            _alert_on = bool(my_email) and my_email in (_load_auction_alerts(auction_id) or {})
        except Exception:
            _alert_on = False
        _alert_html = (
            '<div class="au-alertrow">'
            '<label class="au-switch">'
            f'<input type="checkbox" id="au-alertbox"{" checked" if _alert_on else ""}>'
            '<span class="au-slider"></span></label>'
            '<span class="au-alerttxt" id="au-alerttxt">'
            f'{"Alerts on &mdash; email me when the top bid changes" if _alert_on else "Alert me when the top bid changes"}'
            '</span></div>')
        book = f"""
        {standing}
        {iqf_html}
        """
        side_panel = f"""
        <div class="au-box">
          <div class="au-boxhead">{'Your bid' if me else 'Place a bid'}</div>
          {bid_stats}
          {_err_html}
          <form method="POST" action="?view=auction&amp;id={html.escape(str(auction_id), quote=True)}">
            <input type="hidden" name="action" value="auction_bid">
            <input type="hidden" name="auction_id" value="{html.escape(str(auction_id), quote=True)}">
            <input type="hidden" name="as" value="{html.escape(str(client_id), quote=True)}">
            <div class="au-grid">
              <div class="au-full"><label>Your bid ($/share)</label>
                <input id="au-price" class="au-price" name="gross" type="text"
                       inputmode="decimal" placeholder="0.00"
                       value="{html.escape(str(_pv or ''), quote=True)}" required></div>
              <div><label>Min size ($)</label>
                <input name="min_size" type="text" inputmode="numeric"
                       value="{html.escape(str(int(_mn)) if _mn else '', quote=True)}"></div>
              <div><label>Max size ($)</label>
                <input name="max_size" type="text" inputmode="numeric"
                       value="{html.escape(str(int(_mx)) if _mx else '', quote=True)}"></div>
              <div><label title="If you plan to syndicate this allocation rather than fund it yourself, select No.">Cash on hand</label>
                <select name="cash_on_hand">
                  <option value="yes"{' selected' if _coh == 'yes' else ''}>Yes &mdash; funded</option>
                  <option value="no"{' selected' if _coh == 'no' else ''}>No &mdash; will syndicate</option>
                </select></div>
              <div class="au-full"><label>Notes (optional)</label>
                <input name="note" type="text" value="{_nt}"
                       placeholder="e.g. can go higher for the full block"></div>
              <div class="au-full">
                <div id="au-implied" class="au-implied" style="display:none;"></div>
                <div id="au-warn" class="au-bad" style="display:none;"></div>
                {_alert_html}
                <button class="au-beat" type="button" onclick="auBeat()"
                        style="{'' if (top and (not me or (_auc_num(me.get('gross')) or 0) < top)) else 'display:none;'}">
                  Beat the top bid
                </button>
                <button class="au-btn" type="submit">{'Update bid' if me else 'Submit bid'}</button>
              </div>
            </div>
          </form>
          {iqf_ok_html}
        </div>
        {deadline_html}
        <script>
          (function () {{
            // Live thousands separators on the size fields — six-figure sizes are
            // unreadable otherwise. The server strips commas, so the value still posts.
            function commafy(box) {{
              var before = (box.value || '').slice(0, box.selectionStart || 0)
                             .replace(/[^0-9]/g, '').length;
              var raw = (box.value || '').replace(/[^0-9]/g, '');
              var out = raw ? Number(raw).toLocaleString('en-US') : '';
              if (out === box.value) {{ return; }}
              box.value = out;
              var seen = 0, pos = 0;
              while (pos < out.length && seen < before) {{
                var c = out.charCodeAt(pos);
                if (c >= 48 && c <= 57) {{ seen++; }}
                pos++;
              }}
              try {{ box.setSelectionRange(pos, pos); }} catch (e) {{}}
            }}
            Array.prototype.forEach.call(
              document.querySelectorAll('.au-grid input[name="min_size"], '
                                        + '.au-grid input[name="max_size"]'),
              function (box) {{
                box.addEventListener('input', function () {{ commafy(box); }});
                commafy(box);
              }});

            var TOP = {top or 0};
            var el = document.getElementById('au-price');
            var warn = document.getElementById('au-warn');
            if (!el) {{ return; }}
            var LRP = {facts["lr_pps"] or 0};
            var LRV = {facts["lr_val"] or 0};
            function check() {{
              var v = parseFloat((el.value || '').replace(/[^0-9.]/g, ''));
              var imp = document.getElementById('au-implied');
              if (LRP > 0 && LRV > 0 && v > 0) {{
                var b = LRV * (v / LRP);
                imp.textContent = '≈ $' + (b >= 1 ? b.toFixed(2) + 'B' :
                  Math.round(b * 1000) + 'M') + ' implied valuation · based on last round, estimate only';
                imp.style.display = 'block';
              }} else if (imp) {{
                imp.style.display = 'none';
              }}
              if (TOP > 0 && v > 0 && v < TOP) {{
                el.style.borderColor = '#b45309';
                warn.textContent = 'This is below the current top bid of ' +
                  TOP.toLocaleString('en-US', {{style:'currency', currency:'USD'}}) + '.';
                warn.style.display = 'block';
              }} else {{
                el.style.borderColor = '';
                warn.style.display = 'none';
              }}
            }}
            el.addEventListener('input', check);
            check();
            var ab = document.getElementById('au-alertbox');
            if (ab) {{
              ab.addEventListener('change', function () {{
                var on = ab.checked;
                var txt = document.getElementById('au-alerttxt');
                if (txt) {{ txt.textContent = on
                  ? 'Alerts on — email me when the top bid changes'
                  : 'Alert me when the top bid changes'; }}
                fetch('?view=auction&id={html.escape(str(auction_id), quote=True)}', {{
                  method: 'POST',
                  headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
                  body: 'action=auction_alert&auction_id={urllib.parse.quote(str(auction_id))}'
                        + '&as={urllib.parse.quote(str(client_id))}'
                        + '&alerts=' + (on ? 'on' : 'off')
                }}).catch(function () {{ ab.checked = !on; }});
              }});
            }}
            window.auBeat = function () {{
              if (TOP > 0) {{ el.value = (TOP + 1).toFixed(2); check(); el.focus(); }}
            }};
          }})();
        </script>
        """

    note = (f'<p class="au-note">{html.escape(auc.get("note") or "")}</p>'
            if auc.get("note") else "")

    edit_html = ""
    if is_admin:
        def _v(k):
            x = auc.get(k)
            if x in (None, ""):
                return ""
            if isinstance(x, float) and x == int(x):
                x = int(x)
            return html.escape(str(x), quote=True)
        edit_html = f"""
        <details class="au-edit">
          <summary>Edit auction</summary>
          <form method="POST" action="?view=auction&amp;id={html.escape(str(auction_id), quote=True)}">
            <input type="hidden" name="action" value="auction_update">
            <input type="hidden" name="auction_id" value="{html.escape(str(auction_id), quote=True)}">
            <div class="au-egrid">
              <div><label>Structure</label><input name="structure" value="{_v('structure')}"></div>
              <div><label>Shares</label><input name="shares" value="{_v('shares')}"></div>
              <div><label>Min size ($)</label><input name="min_size" value="{_v('min_size')}"></div>
              <div><label>Max size ($)</label><input name="max_size" value="{_v('max_size')}"></div>
              <div><label>Reserve ($/share)</label><input name="ask" value="{_v('ask')}"></div>
              <div><label>Bids close</label><input name="close_date" type="date" value="{_v('close_date')}"></div>
              <div class="au-full"><label>Note to buyers</label>
                <input name="note" value="{_v('note')}"></div>
              <div class="au-full"><button class="au-btn" type="submit">Save changes</button></div>
            </div>
          </form>
        </details>
        """

    return html_response(f"""
    <style>
      .au-note {{ font-style:italic; color:#6b7280; margin:0 0 16px; }}
      .au-ok {{ color:#1f7a4d; font-weight:600; }}
      .au-bad {{ color:#b45309; font-weight:600; }}
      .au-unmet {{ color:#b91c1c; font-weight:600; }}
      .au-seller {{ color:#6b7280; font-weight:400; }}
      .au-lead {{ color:#1f7a4d; font-weight:600; }}
      .au-deadline {{ font-weight:600; margin:10px 0 0; }}
      .au-alertrow {{ display:flex; align-items:center; gap:10px; margin:2px 0 12px; }}
      .au-switch {{ position:relative; display:inline-block; width:40px; height:22px; flex:none; }}
      .au-switch input {{ opacity:0; width:0; height:0; }}
      .au-slider {{ position:absolute; inset:0; background:#d1d5db; border-radius:11px;
                    transition:background .15s; cursor:pointer; }}
      .au-slider:before {{ content:""; position:absolute; height:18px; width:18px;
                           left:2px; top:2px; background:#fff; border-radius:50%;
                           transition:transform .15s; }}
      .au-switch input:checked + .au-slider {{ background:#1f7a4d; }}
      .au-switch input:checked + .au-slider:before {{ transform:translateX(18px); }}
      .au-alerttxt {{ font-size:13px; font-weight:600; color:#374151; }}
      .au-beat {{ margin-right:10px; padding:10px 18px; font-family:inherit;
                  font-size:14px; font-weight:600; border:1px solid var(--ink);
                  border-radius:6px; background:#fff; color:var(--ink); cursor:pointer; }}
      .au-box {{ border:1px solid var(--line); border-radius:8px; padding:16px 18px;
                 margin-top:18px; }}
      .au-grid {{ display:grid; grid-template-columns:repeat(2,minmax(180px,1fr));
                  gap:12px 16px; }}
      .au-grid label {{ display:block; font-size:13px; font-weight:600; margin-bottom:4px; }}
      .au-grid input, .au-grid select {{ width:100%; padding:9px 12px; font-family:inherit;
                                         font-size:14px; border:1px solid var(--line);
                                         border-radius:6px; }}
      .au-full {{ grid-column:1 / -1; }}
      .au-edit {{ border:1px solid var(--line); border-radius:8px; padding:12px 16px;
                  margin:0 0 18px; background:#fff; }}
      .au-edit summary {{ cursor:pointer; font-size:11px; letter-spacing:.06em;
                          text-transform:uppercase; color:#6b7280; font-weight:600; }}
      .au-egrid {{ display:grid; grid-template-columns:repeat(2,minmax(160px,1fr));
                   gap:12px 16px; margin-top:14px; }}
      .au-egrid label {{ display:block; font-size:13px; font-weight:600; margin-bottom:4px; }}
      .au-egrid input {{ width:100%; padding:9px 12px; font-family:inherit; font-size:14px;
                         border:1px solid var(--line); border-radius:6px; }}
      .au-btn {{ padding:11px 24px; font-family:inherit; font-size:15px; font-weight:600;
                 border:none; border-radius:6px; background:var(--ink); color:#fff;
                 cursor:pointer; }}
      .au-price {{ font-size:22px !important; font-weight:600; padding:12px 14px !important; }}
      .au-cols {{ display:flex; gap:22px; align-items:flex-start; }}
      .au-cols .au-main {{ flex:1 1 auto; min-width:0; }}
      .au-cols .au-side {{ flex:0 0 380px; position:sticky; top:18px; }}
      .au-cols .au-box {{ margin-top:0; }}
      .au-cols .au-grid {{ grid-template-columns:1fr 1fr; }}
      .au-cols .au-grid .au-full {{ grid-column:1 / -1; }}
      @media (max-width: 900px) {{
        .au-cols {{ display:block; }}
        .au-cols .au-side {{ position:static; margin-top:18px; }}
      }}
      .au-details {{ border:1px solid var(--line); border-radius:8px; padding:16px 18px;
                     margin:0 0 18px; }}
      .au-logo {{ max-width:110px; max-height:70px; object-fit:contain; order:2;
                  flex:0 0 auto; }}
      .au-desc {{ margin:0 0 16px; color:#6b7280; font-style:italic; font-size:15px;
                  line-height:1.55; }}
      .au-ftable {{ width:100%; border-collapse:collapse; clear:both; }}
      .au-ftable tr {{ border-bottom:1px solid var(--line); }}
      .au-ftable tr:last-child {{ border-bottom:none; }}
      .au-th {{ width:22%; text-align:left; vertical-align:middle; padding:12px 12px 12px 0;
                font-size:11px; letter-spacing:.05em; text-transform:uppercase;
                color:#6b7280; font-weight:600; white-space:nowrap; }}
      .au-td {{ width:28%; text-align:left; vertical-align:middle; padding:12px 28px 12px 0;
                font-size:15px; font-weight:500; }}
      .au-cat {{ margin-top:16px; font-size:15px; }}
      .au-catlbl {{ font-size:11px; letter-spacing:.05em; text-transform:uppercase;
                    color:#6b7280; font-weight:600; margin-bottom:4px; }}
      .au-head {{ display:flex; gap:20px; align-items:flex-start; margin-bottom:18px; }}
      .au-headtext {{ flex:1; min-width:0; }}
      .au-headtext h1 {{ margin:0 0 6px; }}
      .au-did {{ font-size:13px; color:#6b7280; margin-top:8px; }}
      .au-copy {{ border:none; background:none; cursor:pointer; color:#6b7280;
                  font-size:14px; padding:0 4px; }}
      .au-lr {{ background:#f4f1ea; border-left:3px solid var(--ink); border-radius:4px;
                padding:12px 16px; margin-top:18px; }}
      .au-lrhead {{ font-size:11px; letter-spacing:.06em; text-transform:uppercase;
                    color:#6b7280; font-weight:600; margin-bottom:8px; }}
      .au-lrgrid {{ display:flex; flex-wrap:wrap; gap:8px 28px; }}
      .au-lrgrid > div {{ display:flex; flex-direction:column; }}
      .au-idbit {{ margin-right:18px; white-space:nowrap; }}
      .au-lrcols {{ display:flex; gap:26px; align-items:flex-start; flex-wrap:wrap; }}
      .au-lrleft {{ flex:1 1 300px; min-width:0; }}
      .au-lrright {{ flex:1 1 220px; min-width:0; }}
      .au-lrdev {{ font-size:14px; line-height:1.45; }}
      .au-boxhead {{ font-size:11px; letter-spacing:.07em; text-transform:uppercase;
                     color:#6b7280; font-weight:600; margin-bottom:12px; }}
      .au-bstats {{ display:flex; gap:26px; padding-bottom:14px; margin-bottom:14px;
                    border-bottom:1px solid var(--line); }}
      .au-bstat {{ display:flex; flex-direction:column; }}
      .au-bval {{ font-size:19px; font-weight:600; }}
      .au-lrlbl {{ font-size:11px; color:#6b7280; }}
      .au-lrval {{ font-size:15px; font-weight:600; }}
      .au-box {{ margin-top:0; }}
      .au-cols .au-side .au-box {{ background:#faf8f3; border:1px solid var(--line);
                                   font-size:13px; }}
      .au-implied {{ color:#1f7a4d; font-size:13px; margin-bottom:8px; }}
      .au-iqf {{ background:#fdf6e7; border:1px solid #f0dfae; border-radius:6px;
                 padding:11px 14px; margin:18px 0 0; font-size:14px; }}
      /* The global reset zeroes p margins, so the standing line needs its own gap
         or it runs straight into whatever follows it. */
      .au-standing {{ margin:0 0 18px; }}
      .au-iqfok {{ margin:14px 0 0; padding-top:12px; border-top:1px solid var(--line);
                   font-size:12px; line-height:1.5; color:#1f7a4d; }}
      .wl-h2 {{ font-size:17px; margin:22px 0 10px; }}
      .wl-soft {{ color:#6b7280; }}
      table.auc {{ width:100%; border-collapse:collapse; font-size:14px; }}
      table.auc th, table.auc td {{ border:1px solid #ddd; padding:10px 12px;
                                    text-align:left; }}
      table.auc th {{ font-size:12px; letter-spacing:.06em; text-transform:uppercase; }}
      /* Editable order book. Cells hold the inputs; the forms they post through sit
         in .au-rowforms below the table, so nothing here changes the row layout. */
      table.auc td:has(.au-rin) {{ padding:6px 8px; vertical-align:middle; }}
      .au-rin {{ width:100%; box-sizing:border-box; padding:6px 8px; font-family:inherit;
                 font-size:13px; border:1px solid var(--line); border-radius:4px;
                 background:#fff; color:inherit; }}
      .au-rprice {{ font-weight:600; }}
      .au-rsize {{ white-space:nowrap; min-width:170px; }}
      .au-rsize .au-rin {{ width:calc(50% - 10px); display:inline-block; }}
      .au-rdash {{ color:#6b7280; padding:0 3px; }}
      .au-racts {{ white-space:nowrap; }}
      .au-rsave {{ padding:6px 12px; font-family:inherit; font-size:12px; font-weight:600;
                   border:none; border-radius:4px; background:var(--ink); color:#fff;
                   cursor:pointer; }}
      .au-rdel {{ margin-left:6px; padding:6px 10px; font-family:inherit; font-size:12px;
                  border:1px solid var(--line); border-radius:4px; background:#fff;
                  color:#b91c1c; cursor:pointer; }}
      .au-rowforms {{ display:none; }}
      .au-bookhint {{ font-size:13px; margin:0 0 10px; }}
      .au-bookerr {{ margin:0 0 10px; }}
    </style>
    {header_html}
    {note}
    <div class="{'au-cols' if side_panel else ''}">
      <div class="au-main">{details_html}{edit_html}{book}</div>
      {f'<div class="au-side">{side_panel}</div>' if side_panel else ""}
    </div>
    <script>
      function auCopy(t) {{
        navigator.clipboard.writeText(t);
      }}
    </script>
    """, eyebrow=("Auction: " + company +
                  ((" — " + auc.get("structure")) if auc.get("structure") else "")),
       is_admin=is_admin, view="auction", client_id=client_id)


def render_watchlist_status(client_id, is_admin=False):
    """Client-facing watchlist: their interests with actionable status. No name shown.
    is_admin only controls whether the shell renders the Admin nav button; it never
    changes what the page shows, so previewing a client with ?as= stays faithful."""
    try:
        jwt = get_jwt()
    except Exception as e:
        print(f"watchlist status: jwt failed: {e}")
        jwt = None

    sides = {"buy": [], "sell": []}
    wl_oid = {}
    ticket_lo = ticket_hi = None
    if jwt:
        res = call_pipeline_api("GET", f"/people/{client_id}.json", jwt=jwt)
        cf = res["data"].get("custom_fields", {}) if res.get("status") == 200 and isinstance(res.get("data"), dict) else {}
        ticket_lo, ticket_hi = _wl_ticket_range(cf)
        sec = load_security_maps(jwt)
        for side, field in (("buy", BUY_INTEREST_FIELD), ("sell", SELL_INTEREST_FIELD)):
            id_to_name = sec.get(side, {}).get("id_to_name", {})
            for oid in cf_id_list(cf.get(field)):
                nm = id_to_name.get(int(oid))
                if nm:
                    sides[side].append(nm)
                    wl_oid[(side, nm.strip().lower())] = int(oid)

    deals = _wl_json(WL_DEALS_BUCKET, WL_DEALS_KEY, [])
    if not isinstance(deals, list):
        deals = []

    _wl_seen, _wl_uniq = set(), []
    for _n in sides["buy"] + sides["sell"]:
        _k = _n.strip().lower()
        if _k not in _wl_seen:
            _wl_seen.add(_k)
            _wl_uniq.append(_n)
    meta = _wl_company_meta(_wl_uniq, jwt)

    def _num(v):
        try:
            return float(str(v).replace("$", "").replace(",", "").strip())
        except (TypeError, ValueError):
            return None

    def block(side, names):
        want_type = "Sell Order" if side == "buy" else "Buy Order"
        label = "Companies you're looking to buy" if side == "buy" else "Companies you're looking to sell"
        # Public companies ride in the same two interest fields as the private names,
        # marked with a "$" in the security name (e.g. "xAI$"). Nothing on this page
        # applies to them — there is no private deal to view and no bid to submit — so
        # they are dropped here, at render time only. The person's stored watchlist is
        # untouched, and so are the matching and holder counts computed above.
        names = [n for n in names if "$" not in (n or "")]
        if not names:
            return ""

        def _live_for(n):
            return [d for d in deals
                    if (d.get("company") or "").strip().lower() == n.strip().lower()
                    and d.get("type") == want_type]

        names = sorted(names, key=lambda n: (0 if _live_for(n) else 1, n.lower()))
        rows = ""
        for nm in names:
            live = _live_for(nm)
            _m = meta.get(nm.strip().lower()) or {}
            safe = html.escape(nm)
            _inner = f'<span class="wl-name">{safe}</span>'
            _oid = wl_oid.get((side, nm.strip().lower()))
            if _oid:
                _inner += (
                    f'<button type="button" class="wl-rm" data-side="{side}" '
                    f'data-oid="{_oid}" data-name="{html.escape(nm, quote=True)}" '
                    f'title="Remove from watchlist">&times;</button>'
                )
            safe_cell = f'<div class="wl-corow">{_inner}</div>'
            if _m.get("blocked"):
                safe_cell += '<div class="wl-blocked">Company blocks direct transfers</div>'
            if _m.get("catalyst"):
                safe_cell += f'<div class="wl-cat">{html.escape(_m["catalyst"])}</div>'
            bid = f'{WL_WEBBID_URL}?name={urllib.parse.quote(nm)}'
            if live:
                def _fit_note(d):
                    if side != "buy":
                        return None
                    dmin = _num(d.get("min_deal_size"))
                    dmax = _num(d.get("max_deal_size"))
                    if ticket_hi is not None and dmin is not None and dmin > ticket_hi:
                        return (f"min {_wl_money(dmin)} &mdash; above your indicated "
                                "size range. Reply if you'd like to discuss.")
                    if ticket_lo is not None and dmax is not None and dmax < ticket_lo:
                        return (f"max {_wl_money(dmax)} &mdash; below your indicated "
                                "size range.")
                    return None
                live = sorted(live, key=lambda d: 1 if _fit_note(d) else 0)
                first = True
                for d in live:
                    note = _fit_note(d)
                    if note:
                        rows += (
                            "<tr>"
                            + (f'<td class="wl-co" rowspan="{len(live)}">{safe_cell}</td>' if first else "")
                            + f'<td colspan="5" class="wl-soft">'
                            + f'{html.escape(d.get("structure") or "")} indication live &mdash; {note}</td>'
                            + f'<td><a class="wl-act wl-soft" href="{WL_DEAL_URL}?deal_id='
                            + f'{html.escape(str(d.get("id") or ""), quote=True)}">View deal &rarr;</a></td>'
                            + "</tr>"
                        )
                        first = False
                        continue
                    did = html.escape(str(d.get("id") or ""), quote=True)
                    price = _num(d.get("net")) or _num(d.get("gross"))
                    price_cell = (_wl_pps(price) if price
                                  else f'<span class="wl-soft">{_wl_no_price_label(d)}</span>')
                    lr_pps = _num(d.get("company_lr_pps"))
                    lr_cell = _wl_pps(lr_pps) if lr_pps else "&ndash;"
                    if price and lr_pps and lr_pps > 0:
                        prem = (price / lr_pps - 1.0) * 100.0
                        cls = "wl-prem-up" if prem >= 0 else "wl-prem-down"
                        prem_cell = f'<span class="{cls}">{prem:+.0f}%</span>'
                    else:
                        prem_cell = "&ndash;"
                    rows += (
                        "<tr>"
                        + (f'<td class="wl-co" rowspan="{len(live)}">{safe_cell}</td>' if first else "")
                        + f'<td>{html.escape(_wl_structure_label(d))}</td>'
                        + f'<td>{price_cell}</td>'
                        + f'<td>{lr_cell}</td>'
                        + f'<td>{prem_cell}</td>'
                        + f'<td>{_wl_money(d.get("min_deal_size"))} &ndash; {_wl_money(d.get("max_deal_size"))}</td>'
                        + f'<td><a class="wl-act" href="{WL_DEAL_URL}?deal_id={did}">View deal &rarr;</a></td>'
                        + "</tr>"
                    )
                    first = False
            else:
                if side == "sell":
                    msg = (f"We don't currently have a live bid on {safe}. Send us your firm "
                           f"ask and we'll circulate it to buyers in our network.")
                    act_txt = "Submit an offer &rarr;"
                else:
                    h = _wl_holders(nm)
                    if h > 0:
                        msg = (f"We don't currently have an active seller for {safe}, but "
                               f"<strong>{h:,} holders</strong> in our system have shares. "
                               f"Send your firm bid and we'll let you know if any of them accept it.")
                    else:
                        msg = (f"We don't currently have an active seller for {safe}, but we're "
                               f"in touch with holders. Send your firm bid and we'll let you know "
                               f"if any of them accept it.")
                    act_txt = "Submit a bid &rarr;"
                rows += (f'<tr><td class="wl-co">{safe_cell}</td>'
                         f'<td colspan="5" class="wl-soft">{msg}</td>'
                         f'<td><a class="wl-act" href="{bid}">{act_txt}</a></td></tr>')
        return (f'<h2 class="wl-h2">{label}</h2><div class="wl-wrap"><table class="wl-table">'
                '<thead><tr><th>Company</th><th>Structure</th><th>Price</th>'
                '<th>LR PPS</th><th>vs LR</th><th>Size</th><th></th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div>'
                '<p class="wl-soft" style="font-size:12px; margin-top:6px;">'
                'Use &times; to remove a company from your watchlist.</p>')

    body = block("buy", sides["buy"]) + block("sell", sides["sell"])
    # Adding a company lives behind the "Update watchlist" nav button, which clients
    # read straight past — the page explains how to remove a name but never how to add
    # one. So the foot of the page asks for it in words and offers the same route as a
    # button. Once for the whole page, not once per block: the two tables sit directly
    # above it, and repeating the prompt under each would only dilute it.
    if body:
        body += ('<div class="wl-add"><span>Want to follow more companies?</span>'
                 '<a class="btn-secondary" href="?view=watchlist">Update your watchlist</a>'
                 '</div>')
    else:
        # Nothing to remove and nothing to read: an empty watchlist is the one page
        # whose only useful action is this one, so it carries the button on its own.
        body = ('<p class="empty-state">Your watchlist is empty. Choose the companies you '
                "want to follow and we'll show you live bids, offers and pricing for "
                'each of them.</p>'
                '<div class="wl-add">'
                '<a class="btn-secondary" href="?view=watchlist">+ Build your watchlist</a>'
                '</div>')

    return html_response(f"""
    <style>
      .wl-wrap {{ overflow-x: auto; }}
      .wl-table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
      .wl-table th, .wl-table td {{ border: 1px solid #ddd; padding: 11px 12px;
                                    text-align: left; vertical-align: top; }}
      .wl-table th {{ font-size: 12px; letter-spacing: .06em; text-transform: uppercase; }}
      .wl-co {{ font-weight: 600; white-space: nowrap; }}
      .wl-h2 {{ font-size: 17px; margin: 22px 0 10px; }}
      .wl-soft {{ color: #6b7280; }}
      .wl-blocked {{ font-style: italic; font-weight: 400; font-size: 12px;
                     color: #6b7280; margin-top: 3px; white-space: normal; }}
      .wl-act {{ font-weight: 600; text-decoration: none; white-space: nowrap; }}
      .wl-prem-up {{ color: #b45309; }}
      .wl-prem-down {{ color: #1f7a4d; }}
      .wl-corow {{ display: flex; align-items: baseline; justify-content: space-between;
                   gap: 14px; }}
      .wl-name {{ white-space: normal; }}
      .wl-cat {{ font-size: 12px; font-weight: 400; color: #6b7280; margin-top: 4px;
                 white-space: normal; }}
      .wl-rm {{ border: none; background: none; color: #dc2626; font-size: 17px;
                line-height: 1; cursor: pointer; padding: 0 2px; flex: 0 0 auto; }}
      .wl-rm:hover {{ color: #b91c1c; }}
      /* The add prompt: sits below the tables, reads at body size rather than as the
         12px fine print the remove hint uses, and wraps to two lines on a phone. */
      .wl-add {{ display: flex; flex-wrap: wrap; align-items: center; gap: 12px;
                 margin-top: 22px; font-size: 14px; color: var(--ink); }}
    </style>
    <script>
      document.addEventListener("DOMContentLoaded", function () {{
        document.querySelectorAll(".wl-rm").forEach(function (b) {{
          b.addEventListener("click", function () {{
            var nm = b.getAttribute("data-name");
            if (!confirm("Remove " + nm + " from your watchlist?")) {{ return; }}
            b.disabled = true;
            var f = document.createElement("form");
            f.method = "POST";
            f.action = window.location.pathname + window.location.search;
            [["action", "wl_remove"],
             ["side", b.getAttribute("data-side")],
             ["option_id", b.getAttribute("data-oid")]].forEach(function (kv) {{
              var i = document.createElement("input");
              i.type = "hidden"; i.name = kv[0]; i.value = kv[1];
              f.appendChild(i);
            }});
            document.body.appendChild(f);
            f.submit();
          }});
        }});
      }});
    </script>
    <style>
      .wl-spacer {{ display: none; }}
    </style>
    {body}
    """, is_admin=is_admin, client_id=client_id)


def _route(event, context):
    method = (event.get("requestContext", {}).get("http", {}).get("method") or "GET").upper()
    raw_path = event.get("rawPath", "/")
    qs = event.get("queryStringParameters") or {}

    # 0) Sign out: expire the desk session cookie (same attributes it was set
    #    with) and bounce to trades' own signout route so both sites' cookies
    #    clear in one click from the unified nav's Sign out link.
    if qs.get("signout") == "1":
        return {"statusCode": 303,
                "headers": {"Location": "https://trades.graciagroup.com/?signout=1"},
                "cookies": [_cookie(COOKIE_NAME, "", 0)], "body": ""}

    # 1) Magic-link arrival: verify, set session cookie, redirect to a clean URL.
    if qs.get("client") and qs.get("token"):
        if verify_token(qs["client"], qs["token"]):
            # An admin's own link additionally stamps this browser as admin. That
            # second cookie is what later survives opening a CLIENT's magic link:
            # the session below gets overwritten, the admin identity does not.
            cookies = [session_cookie(qs["client"])]
            if qs["client"] in ADMIN_CLIENT_IDS:
                cookies.append(admin_cookie(qs["client"]))
            _rest = {k: v for k, v in qs.items() if k not in ("client", "token")}
            _dest = raw_path + ("?" + urllib.parse.urlencode(_rest) if _rest else "")
            return {"statusCode": 303, "headers": {"Location": _dest},
                    "cookies": cookies, "body": ""}
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
        cookies = [session_cookie(cid)]
        if cid in ADMIN_CLIENT_IDS:            # same stickiness via the SSO door
            cookies.append(admin_cookie(cid))
        _rest = {k: v for k, v in qs.items() if k != "sso"}
        _dest = raw_path + ("?" + urllib.parse.urlencode(_rest) if _rest else "")
        return {"statusCode": 303, "headers": {"Location": _dest},
                "cookies": cookies, "body": ""}

    # 2) Everything else requires a valid session; scope strictly to that client.
    client_id = read_session(get_cookie(event, COOKIE_NAME))
    if not client_id:
        return html_response(login_required("Please open your personal portfolio link."), 401)

    # Server-side admin gate: only these client_ids may mint invites to any portfolio.
    # Identity is now sticky and independent of the session: you are an admin if the
    # session you're browsing under is an admin id, OR if this browser carries a
    # validly signed, unexpired admin cookie. The second half is what keeps the admin
    # routes, the Admin button and ?as= previews alive while the session cookie points
    # at a client — opening a client's magic link changes what you see, not who you are.
    admin_id = read_admin_cookie(get_cookie(event, ADMIN_COOKIE_NAME))
    is_admin = client_id in ADMIN_CLIENT_IDS or bool(admin_id)

    # is_admin above answers "does this browser hold admin privilege" — the right
    # question for route access and action gates. It's the wrong question for what
    # the *viewed* identity should see: under a magic-link cookie swap, client_id is
    # the client but the sticky admin cookie keeps is_admin True, and under ?as=
    # client_id is still the admin. effective_admin answers "is the identity actually
    # being rendered the admin's own" — False in both impersonation modes — and is
    # what render functions should use to decide viewer-facing UI.
    effective_admin = (client_id in ADMIN_CLIENT_IDS) and not qs.get("as")

    # The way back: restore the admin's own session from the sticky cookie, and
    # re-stamp the admin cookie so it rolls forward rather than aging out.
    if qs.get("view") == "resume_admin":
        own = admin_id or (client_id if client_id in ADMIN_CLIENT_IDS else None)
        if not own:
            return html_response(login_required(
                "This browser isn't signed in as an admin."), 403)
        return {"statusCode": 303, "headers": {"Location": raw_path},
                "cookies": [session_cookie(own), admin_cookie(own)], "body": ""}

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
            send_invite(target_id, email, form.get("first_name", ""), DESK_URL)
            # Stamp the client's portfolio so a later lookup can warn on resend.
            invited = load_portfolio(target_id)
            invited["invited_at"] = datetime.now(timezone.utc).isoformat()
            invited["invited_email"] = email
            save_portfolio(invited)
            return _json_ok()
        if action == "auction_bid":
            _aid = (form.get("auction_id") or "").strip()
            _as = (form.get("as") or qs.get("as") or "").strip()
            _owner = _as if (is_admin and _as) else client_id
            _rec = (_people_index().get("by_id", {}) or {}).get(str(_owner)) or {}
            _email = (_rec.get("email") or "").strip().lower()
            _name = (_rec.get("name") or _rec.get("first_name") or "").strip()
            if form.get("toggle_alerts"):
                if _aid and _email:
                    try:
                        _set_auction_alert(_aid, _email, str(_owner), _name,
                                           form.get("toggle_alerts") == "on")
                    except Exception as e:
                        print(f"auction_alert: save failed: {e}")
                _back = raw_path + "?view=auction&id=" + urllib.parse.quote(_aid)
                if is_admin and qs.get("as"):
                    _back += "&as=" + urllib.parse.quote(qs["as"])
                return {"statusCode": 303, "headers": {"Location": _back}, "body": ""}
            # A bid must parse to a positive number, or the book would carry a null
            # that sorts to the bottom and renders as a dash. Reject rather than store.
            _gross = _auc_num(form.get("gross"))
            _bad_bid = _gross is None or _gross <= 0
            if _aid and _email and not _bad_bid:
                _bid = {
                    "gross": _gross,
                    "min_size": _auc_num(form.get("min_size")),
                    "max_size": _auc_num(form.get("max_size")),
                    "cash_on_hand": "no" if (form.get("cash_on_hand") == "no") else "yes",
                    "note": (form.get("note") or "").strip(),
                    "person_id": str(_owner),
                }
                _prior_bids = _load_auction_bids(_aid)
                _prior_top = max((_auc_num(b.get("gross")) or 0
                                  for b in _prior_bids.values()), default=0)
                try:
                    _save_auction_bid(_aid, _email, _name, _bid)
                except Exception as e:
                    print(f"auction_bid: save failed: {e}")
                try:
                    _auction_bid_notifications(_aid, _email, _name, _gross,
                                               _prior_top, DESK_URL)
                except Exception as e:
                    print(f"auction_bid: notifications failed: {e}")
            _back = raw_path + "?view=auction&id=" + urllib.parse.quote(_aid)
            if is_admin and qs.get("as"):
                _back += "&as=" + urllib.parse.quote(qs["as"])
            if _bad_bid:
                _back += "&err=bid"
            return {"statusCode": 303, "headers": {"Location": _back}, "body": ""}

        if action == "auction_alert":
            _aid = (form.get("auction_id") or "").strip()
            _as = (form.get("as") or qs.get("as") or "").strip()
            _owner = _as if (is_admin and _as) else client_id
            _rec = (_people_index().get("by_id", {}) or {}).get(str(_owner)) or {}
            _email = (_rec.get("email") or "").strip().lower()
            _name = (_rec.get("name") or _rec.get("first_name") or "").strip()
            _on = (form.get("alerts") == "on")
            if _aid and _email:
                try:
                    _set_auction_alert(_aid, _email, str(_owner), _name, _on)
                except Exception as e:
                    print(f"auction_alert: save failed: {e}")
            _back = raw_path + "?view=auction&id=" + urllib.parse.quote(_aid)
            if is_admin and qs.get("as"):
                _back += "&as=" + urllib.parse.quote(qs["as"])
            return {"statusCode": 303, "headers": {"Location": _back}, "body": ""}

        # In-place edits to the order book. Admin only, POST only: a non-admin is
        # refused here rather than falling through to another action, because these
        # rewrite another person's bid.
        if action == "auction_bid_edit":
            if not is_admin:
                return {"statusCode": 403,
                        "headers": {"Content-Type": "text/plain"},
                        "body": "forbidden"}
            _be_id = (form.get("auction_id") or "").strip()
            _be_email = (form.get("email") or "").strip().lower()
            _be_back = raw_path + "?view=auction&id=" + urllib.parse.quote(_be_id)

            def _be_bounce(code=""):
                return {"statusCode": 303,
                        "headers": {"Location": _be_back + ("&err=" + code if code else "")},
                        "body": ""}

            if not (_be_id and _be_email):
                return _be_bounce("bidedit")
            _be_gross = _auc_num(form.get("gross"))
            if _be_gross is None or _be_gross <= 0:
                return _be_bounce("bidedit")
            _be_cur = (_load_auction_bids(_be_id) or {}).get(_be_email)
            if not _be_cur:
                return _be_bounce("bidgone")
            # Optimistic concurrency: the row carried the updated_at it was drawn
            # with. If the bidder (or another admin) has moved this bid since, the
            # edit is refused rather than silently overwriting the newer number.
            _be_seen = (form.get("prev_updated_at") or "").strip()
            if _be_seen and (_be_cur.get("updated_at") or "") != _be_seen:
                return _be_bounce("bidstale")
            # Start from the stored record so person_id, first_seen, any IQF keys
            # and anything else on it survive an edit that never saw those fields.
            _be_rec = dict(_be_cur)
            _be_rec["gross"] = _be_gross
            _be_rec["min_size"] = _auc_num(form.get("min_size"))
            _be_rec["max_size"] = _auc_num(form.get("max_size"))
            _be_rec["note"] = (form.get("note") or "").strip()
            _be_coh = (form.get("cash_on_hand") or "").strip().lower()
            if _be_coh in ("yes", "no"):
                _be_rec["cash_on_hand"] = _be_coh
            else:
                _be_rec.pop("cash_on_hand", None)     # blank stays blank
            try:
                # Same path a client-submitted bid takes, so updated_at and
                # revisions move exactly as they would on a self-service change.
                _save_auction_bid(_be_id, _be_email, _be_rec.get("name") or "", _be_rec)
            except Exception as e:
                print(f"auction_bid_edit: save failed: {e}")
                return _be_bounce("bidsave")
            return _be_bounce()

        if action == "auction_bid_remove":
            if not is_admin:
                return {"statusCode": 403,
                        "headers": {"Content-Type": "text/plain"},
                        "body": "forbidden"}
            _br_id = (form.get("auction_id") or "").strip()
            _br_email = (form.get("email") or "").strip().lower()
            _br_err = ""
            if _br_id and _br_email:
                try:
                    if not _delete_auction_bid(_br_id, _br_email):
                        _br_err = "bidgone"
                except Exception as e:
                    print(f"auction_bid_remove: delete failed: {e}")
                    _br_err = "bidsave"
            _br_back = raw_path + "?view=auction&id=" + urllib.parse.quote(_br_id)
            if _br_err:
                _br_back += "&err=" + _br_err
            return {"statusCode": 303, "headers": {"Location": _br_back}, "body": ""}

        if action == "interest_refresh":
            if not is_admin:
                return {"statusCode": 403,
                        "headers": {"Content-Type": "text/plain"},
                        "body": "forbidden"}
            _ir_id = (form.get("auction_id") or "").strip()
            _ir_err = ""
            try:
                # RequestResponse blocks until holder-counts finishes (~8s), so the
                # rebuilt interest_people.json is already in S3 by the time we redirect.
                # max_attempts=1 disables botocore's retries: a retried invoke would run
                # the rebuild twice rather than fail cleanly.
                _ir_cfg = BotoConfig(connect_timeout=5, read_timeout=120,
                                     retries={"max_attempts": 1})
                _ir_res = boto3.client("lambda", region_name=HOLDER_COUNTS_REGION,
                                       config=_ir_cfg).invoke(
                    FunctionName=HOLDER_COUNTS_FUNCTION,
                    InvocationType="RequestResponse")
                if _ir_res.get("FunctionError"):
                    _ir_body = ""
                    try:
                        _ir_body = (_ir_res["Payload"].read() or b"").decode("utf-8", "replace")
                    except Exception:
                        pass
                    _ir_err = (f"{HOLDER_COUNTS_FUNCTION} ran but returned an error "
                               f"({_ir_res['FunctionError']}): {_ir_body[:300]}")
            except ClientError as e:
                _code = (e.response.get("Error") or {}).get("Code") or ""
                if _code in ("AccessDeniedException", "AccessDenied"):
                    _ir_err = (f"Not permitted to run {HOLDER_COUNTS_FUNCTION}. This "
                               f"function's execution role needs lambda:InvokeFunction on "
                               f"arn:aws:lambda:{HOLDER_COUNTS_REGION}:*:function:"
                               f"{HOLDER_COUNTS_FUNCTION}.")
                elif _code == "ResourceNotFoundException":
                    _ir_err = (f"No Lambda named {HOLDER_COUNTS_FUNCTION} in "
                               f"{HOLDER_COUNTS_REGION}.")
                else:
                    _ir_err = f"Could not run {HOLDER_COUNTS_FUNCTION} ({_code or e})."
            except Exception as e:
                _ir_err = f"Could not run {HOLDER_COUNTS_FUNCTION}: {e}"
            if _ir_err:
                print(f"interest_refresh: {_ir_err}")
            _back = raw_path + "?view=invites&id=" + urllib.parse.quote(_ir_id)
            if _ir_err:
                _back += "&err=" + urllib.parse.quote(_ir_err[:300])
            return {"statusCode": 303, "headers": {"Location": _back}, "body": ""}

        if action == "auction_update":
            if not is_admin:
                return {"statusCode": 403,
                        "headers": {"Content-Type": "text/plain"},
                        "body": "forbidden"}
            _up_id = (form.get("auction_id") or "").strip()
            _aucs = _load_auctions()
            _rec = _aucs.get(_up_id)
            if _rec is not None:
                _rec["structure"] = (form.get("structure") or "").strip()
                _rec["note"] = (form.get("note") or "").strip()
                _rec["close_date"] = (form.get("close_date") or "").strip()
                for _k in ("shares", "min_size", "max_size", "ask"):
                    _rec[_k] = _auc_num(form.get(_k))
                _aucs[_up_id] = _rec
                _save_auctions(_aucs)
            _back = raw_path + "?view=auction&id=" + urllib.parse.quote(_up_id)
            return {"statusCode": 303, "headers": {"Location": _back}, "body": ""}

        if action == "auction_set_deadline":
            if not is_admin:
                return {"statusCode": 403,
                        "headers": {"Content-Type": "text/plain"},
                        "body": "forbidden"}
            _dl_back = raw_path + "?view=auctions"
            _dl_id = (form.get("auction_id") or "").strip()
            _aucs = _load_auctions()
            _rec = _aucs.get(_dl_id) if _dl_id else None
            if _rec is not None:
                _rec["close_date"] = (form.get("close_date") or "").strip()
                _aucs[_dl_id] = _rec
                _save_auctions(_aucs)
            return {"statusCode": 303, "headers": {"Location": _dl_back}, "body": ""}

        if action == "auction_delete":
            if not is_admin:
                return {"statusCode": 403,
                        "headers": {"Content-Type": "text/plain"},
                        "body": "forbidden"}
            _del_id = (form.get("auction_id") or "").strip()
            if _del_id:
                _aucs = _load_auctions()
                if _del_id in _aucs:
                    del _aucs[_del_id]
                    _save_auctions(_aucs)
            return {"statusCode": 303,
                    "headers": {"Location": raw_path + "?view=auctions"},
                    "body": ""}

        if action == "auction_create":
            if not is_admin:
                return {"statusCode": 403,
                        "headers": {"Content-Type": "text/plain"},
                        "body": "forbidden"}
            _auc = _load_auctions()
            _aid = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            _auc[_aid] = {
                "company": (form.get("company") or "").strip(),
                "deal_id": (form.get("deal_id") or "").strip(),
                "ask": _auc_num(form.get("ask")),
                "shares": _auc_num(form.get("shares")),
                "structure": (form.get("structure") or "").strip(),
                "close_date": (form.get("close_date") or "").strip(),
                "buyers": _auc_num(form.get("buyers")),
                "min_size": _auc_num(form.get("min_size")),
                "max_size": _auc_num(form.get("max_size")),
                "note": (form.get("note") or "").strip(),
                "status": "open",
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            _save_auctions(_auc)
            return {"statusCode": 303,
                    "headers": {"Location": raw_path + "?view=auctions"},
                    "body": ""}

        # Remove one company from this side's CRM interest field. Writes only that
        # field via the shared primitive; Broadcast and the other side are untouched.
        if action == "wl_remove":
            back = raw_path + ("?as=" + urllib.parse.quote(qs["as"]) if (is_admin and qs.get("as")) else "")
            try:
                jwt = get_jwt()
            except Exception as e:
                print(f"wl_remove: jwt load failed: {e}")
                return {"statusCode": 303, "headers": {"Location": back}, "body": ""}
            side = form.get("side") if form.get("side") in ("buy", "sell") else "buy"
            try:
                drop = int(form.get("option_id") or 0)
            except (TypeError, ValueError):
                drop = 0
            owner = qs["as"] if (is_admin and qs.get("as")) else client_id
            field = BUY_INTEREST_FIELD if side == "buy" else SELL_INTEREST_FIELD
            cur = call_pipeline_api("GET", f"/people/{owner}.json", jwt=jwt)
            cur_cf = cur["data"].get("custom_fields", {}) if cur.get("status") == 200 and isinstance(cur.get("data"), dict) else {}
            keep = [i for i in cf_id_list(cur_cf.get(field)) if int(i) != drop]
            _crm_set_interest(owner, side, keep, None, jwt, mode="replace")
            return {"statusCode": 303, "headers": {"Location": back}, "body": ""}

        # Build Watchlist grid submit: dual write (CRM interest + S3 watchlist) for the
        # logged-in client's OWN portfolio. Uses the multi-value parse so the checkbox
        # groups aren't collapsed.
        if action == "watchlist_save":
            try:
                jwt = get_jwt()
            except Exception as e:
                print(f"watchlist_save: jwt load failed: {e}")
                return {"statusCode": 303,
                        "headers": {"Location": raw_path + "?view=watchlist"}, "body": ""}
            multi = _parse_body_multi(event)
            structures = [s for s in multi.get("structure", []) if s in WL_STRUCTURES]
            fees = [f for f in multi.get("fee", []) if f in WL_FEES]
            notify = form.get("notify") == "yes"
            # Both grids live in one form and both post, so both are saved: the Buy/Sell
            # radio only chooses which grid is on screen, and editing the other side then
            # switching back used to discard those edits silently.
            #
            # Which sides to write is decided by the grid_side markers, NOT by which
            # keep_* keys arrived. An unticked checkbox posts nothing, so an empty
            # keep_<side> is ambiguous: it means "the client cleared this side" when the
            # grid rendered, and "there was nothing to tick" when that side's options
            # failed to load — load_security_maps fetches the two dropdowns separately
            # and caches a partial result, so one side can come back empty while the
            # other is fine. Replacing on the second reading would wipe a good list.
            # The marker is emitted only by a grid that rendered, which tells the two
            # apart and keeps clearing a side by unticking everything working.
            sides = [s for s in ("buy", "sell") if s in multi.get("grid_side", [])]
            # A page cached before the markers existed posts none; fall back to the old
            # single-side behaviour rather than guessing at both.
            if not sides:
                sides = [form.get("side") if form.get("side") in ("buy", "sell") else "buy"]
            own = load_portfolio(client_id)
            own.setdefault("client_id", client_id)
            for _side in sides:
                keep = [int(v) for v in multi.get(f"keep_{_side}", [])
                        if v.strip().lstrip("-").isdigit()]
                # notify rides on every call: it is the same Broadcast value written to
                # the same field, so a repeat is a no-op, and it still lands if the first
                # side's write is the one that fails.
                save_watchlist_selection(own, client_id, _side, keep, structures, fees,
                                         notify, jwt, mode="replace")
            save_portfolio(own)
            return {"statusCode": 303, "headers": {"Location": raw_path}, "body": ""}
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

    view_id = qs["as"] if (is_admin and qs.get("as")) else client_id
    if qs.get("view") == "invites" and qs.get("id") and is_admin:
        return render_auction_invites(qs["id"], DESK_URL, qs.get("err") or "")
    if qs.get("view") == "auction" and qs.get("id"):
        return render_auction(qs["id"], view_id, effective_admin,
                              qs.get("err") or "")
    if qs.get("view") == "admin" and is_admin:
        return render_admin_hub()
    if qs.get("view") == "auctions" and is_admin:
        return render_auctions_admin()
    if qs.get("view") == "sendlink" and is_admin:
        return render_send_link()
    # The two pages this one replaced. Bookmarks and pasted URLs still land somewhere
    # useful, and the address bar corrects itself to the canonical route.
    if qs.get("view") in ("link", "deallinks") and is_admin:
        return {"statusCode": 303,
                "headers": {"Location": raw_path + "?view=sendlink"}, "body": ""}
    if qs.get("view") == "link_token" and is_admin:
        _lk_id = (qs.get("id") or "").strip()
        _lk_name = ""
        if _lk_id:
            try:
                _lk_rec = (_people_index().get("by_id", {}) or {}).get(str(_lk_id)) or {}
                _lk_name = (_lk_rec.get("name") or _lk_rec.get("first_name") or "").strip()
            except Exception as e:
                print(f"link_token: people index lookup failed: {e}")
        _lk_url = (f"{DESK_URL}/?client={urllib.parse.quote(_lk_id)}"
                   f"&token={make_token(_lk_id)}") if _lk_id else ""
        return {"statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"url": _lk_url, "name": _lk_name})}
    if qs.get("view") == "deal_link_tokens" and is_admin:
        _dl_id = (qs.get("id") or "").strip()
        _dl_name = _deal_name(_dl_id) if _dl_id else ""
        _dl_q = urllib.parse.quote(_dl_id)
        _dl_update = (f"{TRADE_UPDATE_BASE}?deal_id={_dl_q}"
                      f"&token={sign_id(TRADE_UPDATE_SECRET, _dl_id)}") if _dl_id else ""
        # Without the secret there is no signature to give, so the page is told to
        # disable the row instead of being handed a link the LOI lambda would reject.
        _dl_loi = (f"{LOI_SIGN_BASE}?deal_id={_dl_q}"
                   f"&t={sign_id(LOI_TOKEN_SECRET, _dl_id)}") if (_dl_id and LOI_TOKEN_SECRET) else ""
        _dl_err = "" if LOI_TOKEN_SECRET else (
            "The LOI_TOKEN_SECRET environment variable is not set on this Lambda, "
            "so LOI links can't be signed here.")
        return {"statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"name": _dl_name, "update_url": _dl_update,
                                    "loi_url": _dl_loi, "loi_error": _dl_err})}
    if qs.get("view") == "watchlist":
        return render_watchlist_builder(view_id)
    if qs.get("view") == "holdings":
        return render_portfolio(load_portfolio(view_id), effective_admin, client_id=view_id)
    if qs.get("view") == "portfolios" and is_admin:
        return render_admin_overview(client_id)
    return render_watchlist_status(view_id, effective_admin)


def _viewing_as_bar(client_id):
    """The small 'viewing as <name> — back to admin' strip, linking to the route
    that puts the admin's own session back."""
    return ('<div class="viewbar">Viewing as '
            f'<strong>{html.escape(display_name(client_id))}</strong> — '
            '<a href="?view=resume_admin">back to admin</a></div>')


def lambda_handler(event, context):
    """Thin shell around _route: renders the "viewing as" bar whenever the browser
    carries a valid admin cookie but the session cookie points at somebody else.
    Done here, once, rather than threaded through every render_* function — the bar
    is a property of the request, not of any particular page. Failures are swallowed:
    a missing bar must never cost the user their page."""
    resp = _route(event, context)
    try:
        admin_id = read_admin_cookie(get_cookie(event, ADMIN_COOKIE_NAME))
        if not admin_id:
            return resp
        client_id = read_session(get_cookie(event, COOKIE_NAME))
        if not client_id or client_id == admin_id:
            return resp
        headers = resp.get("headers") or {}
        body = resp.get("body") or ""
        anchor = '<div class="card">'
        if "text/html" in headers.get("Content-Type", "") and anchor in body:
            resp["body"] = body.replace(anchor, anchor + _viewing_as_bar(client_id), 1)
    except Exception as e:
        print(f"viewing-as bar skipped: {e}")
    return resp


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
