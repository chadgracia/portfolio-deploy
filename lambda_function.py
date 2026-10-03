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
from datetime import datetime, timezone, timedelta

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
    return html_response(body + EDIT_SCRIPT, view="holdings", client_id=client_id)


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
    return html_response(body + WL_SCRIPT, view="watchlist", client_id=client_id)


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

# The three client desk views (Watchlist, Update watchlist, Holdings) also carry
# the unified global nav (see _render_unified_nav), which already has its own
# Gracia Group brand link and Indications tab. Rather than repeat those in the
# row underneath, this sub-nav is left-aligned and styled lighter than the
# global nav-tabs so the hierarchy reads global nav -> section sub-nav.
_DESK_SUBNAV = (
    ("watchlist_status", "?", "Watchlist"),
    ("watchlist", "?view=watchlist", "Update watchlist"),
    ("holdings", "?view=holdings", "Holdings"),
)


def _render_desk_subnav(active, is_admin=False):
    pills = "".join(
        f'<a class="subnav-pill{" active" if key == active else ""}" href="{href}">{label}</a>'
        for key, href, label in _DESK_SUBNAV
    )
    if is_admin:
        pills += '<a class="subnav-pill" href="?view=admin">Admin</a>'
    return f'<nav class="gg-subnav">{pills}</nav>'

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
    "auction_list": ("⏱️", "Auctions · Gracia Group"),
    "auction_seller": ("📄", "Order Book · Gracia Group"),
    "sendlink": ("🚀", "Send a Link · GG Admin"),
    "engagement": ("📝", "Engagement Docs · GG Admin"),
    "demand": ("🗂️", "Demand Board · Gracia Group"),
    "profile": ("👤", "Profile · Gracia Group"),
}

# ── Unified top nav (same structure/styling as chadgracia/trades and
# chadgracia/CRMDealDetails) ──────────────────────────────────────────────────────
_syndicate_tenant_cache = {"emails": None}

# Demand Board data: syndicate-dash's own precomputed per-company table is the
# single source of truth (see its ?demand=list route / _handle_demand_list),
# fetched fresh at most once per _DEMAND_CACHE_TTL_SECONDS per warm container.
_DEMAND_CACHE_TTL_SECONDS = 15 * 60
_demand_cache = {"data": None, "fetched_at": 0.0}


def _fetch_demand_data():
    """The Demand Board table straight from syndicate-dash's admin-gated
    ?demand=list JSON route -- this file never reimplements that aggregation.
    Cached per warm container for _DEMAND_CACHE_TTL_SECONDS. Returns None on
    any failure (timeout, bad JSON, non-2xx) so the caller can show its own
    friendly fallback instead of a broken page."""
    now = time.monotonic()
    if (_demand_cache["data"] is not None
            and (now - _demand_cache["fetched_at"]) < _DEMAND_CACHE_TTL_SECONDS):
        return _demand_cache["data"]
    if not SYNDICATE_DASH_URL:
        print("Demand Board: ADMIN_KEY not set; skipping syndicate-dash fetch")
        return None
    try:
        req = urllib.request.Request(SYNDICATE_DASH_URL + "&demand=list")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        print(f"Demand Board: data fetch failed (non-fatal): {e}")
        return None
    _demand_cache["data"] = data
    _demand_cache["fetched_at"] = now
    return data


# "Your status" card on the Profile page (and the tier line on Portfolio &
# Watchlist): the ONE standing fetch path. standing_json from syndicate-dash
# (computed there, never here), cached per person_id for 5 minutes in module
# memory (survives across invocations of a warm container).
_STATUS_CARD_TTL_SECONDS = 5 * 60
_status_card_cache = {}


def _fetch_status_card_standing(person_id):
    """Standing payload for the status card, or None. visible:false caches as None;
    any failure logs one line and returns None (uncached, so the next view retries)."""
    pid = str(person_id or "").strip()
    if not pid:
        return None
    now = time.monotonic()
    hit = _status_card_cache.get(pid)
    if hit and (now - hit[0]) < _STATUS_CARD_TTL_SECONDS:
        return hit[1]
    if not SYNDICATE_DASH_URL:
        print("standing fetch failed: ADMIN_KEY not set")
        return None
    try:
        req = urllib.request.Request(SYNDICATE_DASH_URL + "&view=standing_json&pid="
                                     + urllib.parse.quote(pid, safe=""))
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")
            parsed = json.loads(resp.read().decode())
        if not isinstance(parsed, dict):
            raise ValueError("response is not a JSON object")
    except Exception as e:
        print(f"standing fetch failed: {type(e).__name__}: {e}")
        return None
    data = parsed if parsed.get("visible") is True else None
    _status_card_cache[pid] = (now, data)
    return data


def _post_standing_share(person_id, share):
    """POST syndicate-dash ?action=standing_share for this person_id (admin key
    stays server-side in SYNDICATE_DASH_URL). Returns the new standing_json
    payload, or None on any failure. Clears then reseeds the 5-minute cache
    entry from the returned payload so the next render shows the change."""
    pid = str(person_id or "").strip()
    if not pid or not SYNDICATE_DASH_URL:
        print("standing share failed: no pid or ADMIN_KEY not set")
        return None
    _status_card_cache.pop(pid, None)
    try:
        req = urllib.request.Request(
            SYNDICATE_DASH_URL + "&action=standing_share",
            data=json.dumps({"pid": pid, "share": bool(share)}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")
            parsed = json.loads(resp.read().decode())
        if not isinstance(parsed, dict) or parsed.get("share_with_sellers") is not bool(share):
            raise ValueError("unexpected response")
    except Exception as e:
        print(f"standing share failed: {type(e).__name__}: {e}")
        return None
    _status_card_cache[pid] = (time.monotonic(), parsed if parsed.get("visible") is True else None)
    return parsed


# Rows of standing_json that are never shown to a counterparty (and so are
# left out of the "What matched ... see" preview): the referral and trades rows,
# plus qualification for seller-only clients. Matched on the row's "key";
# rows without one fall back to the label prefixes.
_SHARE_PREVIEW_SKIP_KEYS = ("referral", "trades")
_SHARE_PREVIEW_SKIP = ("Completed trades", "Introduced a new client")


def _share_audience(st):
    """'buyers' for a seller-only client, else 'sellers' (also when roles is missing)."""
    roles = st.get("roles")
    if isinstance(roles, dict):
        seller, buyer = bool(roles.get("seller")), bool(roles.get("buyer"))
    elif isinstance(roles, (list, tuple)):
        seller, buyer = "seller" in roles, "buyer" in roles
    elif isinstance(roles, str):
        seller, buyer = "seller" in roles.lower(), "buyer" in roles.lower()
    else:
        return "sellers"
    return "buyers" if (seller and not buyer) else "sellers"


def _share_card_html(st, viewing_as=False, share_err=False):
    """The sharing card beside "Your status" on Profile. The switch is a submit
    button posting the existing action=standing_share form to this desk route
    (no key in the page). Disabled when an admin is viewing as the client
    (consent must come from the client) or when standing_json says
    sharing_locked."""
    aud = _share_audience(st)
    on = st.get("share_with_sellers") is True
    locked = st.get("sharing_locked") is True
    disabled = viewing_as or locked
    subtitle = ("Buyers move faster with sellers whose onboarding is already in place."
                if aud == "buyers" else
                "Sellers prioritize buyers whose onboarding is already in place.")
    note = ""
    if viewing_as:
        note = '<p class="sc-note">Only the client can change this.</p>'
    elif locked:
        note = '<p class="sc-note">Sharing is turned off for your account.</p>'
    elif share_err:
        note = '<p class="sc-note sc-err">Couldn&rsquo;t save &mdash; please try again.</p>'
    skip_keys = _SHARE_PREVIEW_SKIP_KEYS + (("qualification",) if aud == "buyers" else ())
    seen = ""
    for it in (st.get("items") or []):
        if not isinstance(it, dict) or not it.get("done"):
            continue
        label = str(it.get("label") or "")
        if not label:
            continue
        key = it.get("key")
        if key:
            if str(key) in skip_keys:
                continue
        elif label.startswith(_SHARE_PREVIEW_SKIP):
            continue
        seen += f'<li>{_CTS_TICK}<span>{html.escape(label)}</span></li>'
    if not seen:
        seen = '<li class="sc-none">Nothing yet &mdash; completed items will appear here.</li>'
    state = "Sharing on" if on else "Sharing off"
    return (
        '<div class="sc">'
        f'<h2 class="sc-title">Increase your chances of closing by sharing with matched {aud}</h2>'
        f'<p class="sc-sub">{html.escape(subtitle)}</p>'
        '<form class="sc-form" method="POST" action="?view=profile">'
        '<input type="hidden" name="action" value="standing_share">'
        f'<input type="hidden" name="share" value="{"0" if on else "1"}">'
        f'<button type="submit" class="sc-switch-row" role="switch" aria-checked="{"true" if on else "false"}"'
        f' aria-label="Share my standing with matched {aud}"{" disabled" if disabled else ""}>'
        f'<span class="sc-track{" on" if on else ""}" aria-hidden="true"><span class="sc-knob"></span></span>'
        f'<span class="sc-state">{state}</span></button>'
        '</form>'
        + note +
        f'<div class="sc-seen"><div class="sc-seen-h">What matched {aud} see</div>'
        f'<ul>{seen}</ul></div>'
        f'<p class="sc-fine">Shown only to {aud} matched with you or introduced to you. Never published, '
        'and never includes your trades, amounts, tier or referrals. You can turn this off at any time.</p>'
        '</div>'
    )


_STATUS_CARD_CSS = """
  .cts.ys { margin: 0 0 18px; }
  .cts.ys .status { padding: 18px; gap: 12px; }
  .cts.ys .mark.off { border: 2px solid #b8c0c8; box-sizing: border-box; }
  .cts.ys .note { margin-top: 0; font-style: normal; }
  .cts.ys .note a { color: inherit; }
  .cts.ys .foot { display: flex; flex-direction: column; gap: 4px; font-size: 14px; }
  .cts.ys, .cts.ys * { overflow-wrap: anywhere; }
  /* Profile: two columns (status 58% / sharing 42%), stacked under 760px. */
  .pf-grid { display: grid; grid-template-columns: minmax(0, 58fr) minmax(0, 42fr); gap: 24px;
             align-items: start; max-width: 1040px; }
  @media (max-width: 760px) { .pf-grid { grid-template-columns: 1fr; } }
  .pf-grid .cts, .pf-grid .cts.ys { margin: 0; }
  .cts .sc { background: #fff; border: 1px solid var(--rule); border-radius: 12px; padding: 24px;
             box-shadow: 0 1px 2px rgba(20,30,45,.05), 0 4px 14px rgba(20,30,45,.06);
             display: flex; flex-direction: column; gap: 14px; }
  .cts .sc-title { font-family: var(--serif); font-size: 20px; font-weight: 600; line-height: 1.3; margin: 0; }
  .cts .sc-sub { color: var(--muted); font-size: 14px; }
  .cts .sc-form { margin: 0; }
  .cts .sc-switch-row { display: flex; align-items: center; gap: 12px; width: 100%; padding: 6px 0;
                        background: none; border: 0; font: inherit; color: var(--ink); cursor: pointer; text-align: left; }
  .cts .sc-switch-row:disabled { cursor: not-allowed; opacity: .6; }
  .cts .sc-switch-row:focus-visible { outline: 2px solid var(--navy); outline-offset: 3px; border-radius: 6px; }
  .cts .sc-track { position: relative; flex: none; width: 44px; height: 24px; border-radius: 999px;
                   background: #c4cad1; transition: background .15s; }
  .cts .sc-track.on { background: #1f7a4d; }
  .cts .sc-knob { position: absolute; top: 3px; left: 3px; width: 18px; height: 18px; border-radius: 50%;
                  background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,.25); transition: left .15s; }
  .cts .sc-track.on .sc-knob { left: 23px; }
  .cts .sc-state { font-weight: 600; font-size: 15px; }
  .cts .sc-note { font-size: 13px; color: var(--muted); }
  .cts .sc-err { color: #b23b3b; }
  .cts .sc-seen { background: var(--tint); border-radius: 8px; padding: 14px 16px; }
  .cts .sc-seen-h { font-size: 12px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase;
                    color: var(--muted); margin-bottom: 8px; }
  .cts .sc-seen ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .cts .sc-seen li { display: flex; align-items: flex-start; gap: 8px; font-size: 14px; }
  .cts .sc-seen li .mark { flex: none; width: 16px; height: 16px; margin-top: 3px; }
  .cts .sc-seen li .mark.on svg { width: 10px; height: 10px; }
  .cts .sc-seen li.sc-none { color: var(--muted); }
  .cts .sc-fine { font-size: 13px; color: var(--muted); }
  @media (max-width: 480px) { .cts .sc { padding: 18px; } }
  @media (max-width: 480px) { .cts.ys .status { padding: 14px; } }
"""


def _render_status_card(person_id, viewing_as=False, share_err=False):
    """Profile's two cards: the "Your status" checklist (left) and the sharing
    card (right, _share_card_html) in a two-column grid, or "" when there's
    nothing to show. Never raises."""
    try:
        st = _fetch_status_card_standing(person_id)
        if not st:
            return ""
        pill = ""
        if st.get("tier") is not None:
            label = str(st.get("tier_label") or st.get("tier") or "").strip()
            try:
                pct_txt = f"{float(st.get('discount_pct')):g}% off"
            except (TypeError, ValueError):
                pct_txt = ""
            txt = " · ".join(x for x in (label, pct_txt) if x)
            if txt:
                pill = f'<span class="pill">{html.escape(txt)}</span>'
        lis = ""
        for it in (st.get("items") or []):
            if not isinstance(it, dict):
                continue
            label = html.escape(str(it.get("label") or ""))
            note = html.escape(str(it.get("note") or ""))
            href = _safe_href(it.get("form_url"))
            extra = ""
            if note:
                if href:
                    note = f'<a href="{href}" target="_blank" rel="noopener">{note}</a>'
                extra = f'<span class="note">{note}</span>'
            mark = _CTS_TICK if it.get("done") else '<span class="mark off"></span>'
            lis += f'<li>{mark}<div>{label}{extra}</div></li>'
        tiers_href = _safe_href(st.get("tiers_url"))
        return (
            '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Source+Serif+4:'
            'opsz,wght@8..60,400;8..60,600&family=IBM+Plex+Sans:wght@400;500;600&display=swap">'
            f'<style>{_CTS_CSS}{_STATUS_CARD_CSS}</style>'
            '<div class="pf-grid">'
            '<div class="cts ys"><div class="status">'
            f'<div class="status-head"><span class="who">Your status</span>{pill}</div>'
            + (f'<ul class="checks">{lis}</ul>' if lis else "")
            + '<div class="foot">'
            + (f'<p><a href="{tiers_href}" target="_blank" rel="noopener">How tiers work &rarr;</a></p>'
               if tiers_href else "")
            + "<p>See something that looks wrong? Reply to any of my emails and I'll correct it.</p>"
            '</div></div></div>'
            f'<div class="cts">{_share_card_html(st, viewing_as, share_err)}</div>'
            '</div>'
        )
    except Exception as e:
        print(f"standing fetch failed: render error {type(e).__name__}: {e}")
        return ""


def _syndicate_eligible_emails():
    """Lowercased emails eligible for the Syndicate Dashboard, fetched once per
    warm container from syndicate-dash's own admin-gated ?tenants=list route --
    the same endpoint chadgracia/trades reads for its My Dashboard nav tab.
    Fail-soft: any error caches an empty set so the tab just doesn't render."""
    if _syndicate_tenant_cache["emails"] is not None:
        return _syndicate_tenant_cache["emails"]
    emails = set()
    if not SYNDICATE_DASH_URL:
        print("Unified nav: ADMIN_KEY not set; skipping syndicate tenants fetch")
        _syndicate_tenant_cache["emails"] = emails
        return emails
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
        live_ids = [aid for aid, auc in (_load_auctions() or {}).items()
                   if _auction_is_live(auc.get("close_date"))]
        if len(live_ids) == 1:
            auctions_href = f"?view=auction&id={urllib.parse.quote(str(live_ids[0]))}"
        elif live_ids:
            auctions_href = "?view=auction_list"
        else:
            auctions_href = ""
        if auctions_href:
            auctions_tab = (
                f'<a href="{auctions_href}" class="nav-tab">Auctions ({len(live_ids)})</a>'
            )
    except Exception as e:
        print(f"Unified nav: Auctions tab failed (non-fatal): {e}")
        auctions_tab = ""

    dashboard_tab = ""
    try:
        if email and email.lower() in _syndicate_eligible_emails():
            # Signed SSO handoff, never the keyed admin URL. No secret -> no tab.
            token = _make_handoff_token(email)
            if token:
                dash_href = f"{CLIENT_DASH_URL}&sso={urllib.parse.quote(token, safe='')}"
                dashboard_tab = (
                    f'<a href="{html.escape(dash_href, quote=True)}" '
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
        '<a class="navacct-item" href="?view=profile">Profile</a>'
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
        '<a href="?view=demand" class="nav-tab">Demand Board</a>'
        + auctions_tab
        + dashboard_tab
        + '</div>'
        + account_html
        + '</nav>'
    )


def html_response(body_html, status=200, eyebrow="Private Secondaries Watchlist",
                  is_admin=False, view=None, client_id=None):
    # Every page shares this shell. The four client-facing views that also carry
    # the unified global nav (Watchlist, Update watchlist, Holdings, the auction
    # buyer view) get the left-aligned sub-nav underneath it instead of the full
    # legacy topnav, since the unified nav above already has its own brand link
    # and Indications tab; every other caller (admin views, send-a-link) keeps
    # the legacy topnav exactly as before, unchanged.
    if view == "profile":
        topnav = ""          # Profile: unified nav only, no desk sub-nav pills
    elif view in ("watchlist_status", "watchlist", "holdings", "auction", "auction_list", "demand"):
        topnav = _render_desk_subnav(view, is_admin)
    else:
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
      flex-wrap: nowrap;
      gap: 12px;
      padding: 10px 0;
      margin-bottom: 10px;
      border-bottom: 1px solid #ddd;
    }}
    .nav-brand {{
      display: inline-block;
      background-color: #eef2f6;
      border: 1px solid #d7dee6;
      border-radius: 999px;
      padding: 7px 11px;
      font-size: 13.5px;
      font-weight: 700;
      color: #3d5a73;  /* literal: this page redefines --accent */
      text-decoration: none;
      white-space: nowrap;
      flex-shrink: 0;
    }}
    .nav-tabs {{
      display: flex;
      align-items: center;
      flex-wrap: nowrap;
      gap: 6px;
      flex: 1;
      min-width: 0;
    }}
    .nav-tab {{
      display: inline-block;
      background-color: #fff;
      border: 1px solid #ddd;
      border-radius: 999px;
      padding: 7px 11px;
      font-size: 13.5px;
      font-weight: 600;
      color: var(--ink);
      text-decoration: none;
      white-space: nowrap;
    }}
    /* 1120px, not 1000px: this nav sits inside .card's 40px padding. */
    @media (max-width: 1120px) {{
      .gg-unav {{
        flex-wrap: wrap;
      }}
      .nav-tabs {{
        flex-wrap: wrap;
        min-width: auto;
      }}
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
    .gg-subnav {{
      display: flex;
      justify-content: flex-start;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 26px;
    }}
    .subnav-pill {{
      display: inline-block;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.03em;
      line-height: 1;
      color: var(--muted);
      text-decoration: none;
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 7px 13px;
      transition: color 0.15s, border-color 0.15s;
    }}
    .subnav-pill:hover {{
      color: var(--ink);
      border-color: var(--muted);
    }}
    .subnav-pill.active {{
      color: #fff;
      background: var(--accent);
      border-color: var(--accent);
    }}
    .subnav-pill.active:hover {{
      color: #fff;
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
    {"" if view == "profile" else f'<div class="logo">{html.escape(eyebrow)}</div>'}
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


def make_seller_token(auction_id):
    """Read-only seller-view token: HMAC over 'seller:<auction_id>'. Same
    sign_id construction and HMAC_SECRET as the client magic link, so the
    seller route needs no session or client identity at all -- the token
    alone is the credential."""
    return sign_id(HMAC_SECRET, f"seller:{auction_id}")


def verify_seller_token(auction_id, token):
    return hmac.compare_digest(make_seller_token(auction_id), token or "")


def _make_handoff_token(email):
    """Signed, 1-hour SSO handoff for the client dashboard: base64url(f"{email}|{exp}|{sig}"),
    sig = HMAC-SHA256(IDENTITY_SECRET, f"{email}|{exp}").hexdigest(). Mirrors
    chadgracia/trades. Returns "" when IDENTITY_SECRET is unset (callers fail closed)."""
    if not (IDENTITY_SECRET and email):
        return ""
    exp = int(time.time()) + 3600
    sig = hmac.new(IDENTITY_SECRET.encode(), f"{email}|{exp}".encode(),
                   hashlib.sha256).hexdigest()
    return _b64u(f"{email}|{exp}|{sig}".encode())


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


VIEW_AS_COOKIE_NAME = "gg_view_as"
VIEW_AS_DAYS = 1


def make_view_as_cookie(admin_id, view_pid):
    """Signed, expiring admin "view as" marker: base64url("viewas"|admin|pid|exp).sig.
    Same HMAC construction as the session/admin cookies; the "viewas" first field
    keeps it from verifying as either of them."""
    payload = f"viewas|{admin_id}|{view_pid}|{int(time.time()) + VIEW_AS_DAYS * 86400}"
    p = _b64u(payload.encode())
    sig = hmac.new(HMAC_SECRET.encode(), p.encode(), hashlib.sha256).digest()
    return f"{p}.{_b64u(sig)}"


def read_view_as_cookie(value, admin_id):
    """The viewed client's id if the cookie is validly signed, unexpired and was
    minted for THIS admin, else None."""
    try:
        if not admin_id:
            return None
        p, s = (value or "").split(".", 1)
        expected = hmac.new(HMAC_SECRET.encode(), p.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64u(expected), s):
            return None
        parts = _b64u_decode(p).decode().split("|")
        if len(parts) != 4 or parts[0] != "viewas" or parts[1] != admin_id:
            return None
        if int(parts[3]) < int(time.time()):
            return None
        return parts[2] or None
    except Exception:
        return None


def _request_admin_id(event):
    """The admin's own client_id when this browser holds admin privilege (same
    test _route uses for is_admin), else None."""
    client_id = read_session(get_cookie(event, COOKIE_NAME))
    admin_id = read_admin_cookie(get_cookie(event, ADMIN_COOKIE_NAME))
    if admin_id:
        return admin_id
    return client_id if client_id in ADMIN_CLIENT_IDS else None


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


def _fee_pct(v):
    """A fee/carry percentage as a bare number (e.g. '5' or '2.5'), or None
    when unset/unparseable. Shared by the watchlist structure cell and the
    auction Fund Deal Summary so both format fees identically."""
    try:
        f = float(str(v).replace("%", "").strip())
    except (TypeError, ValueError):
        return None
    return int(f) if f == int(f) else f


def _wl_layers_label(layers_val):
    """'SPV on cap table'/'2-Layer SPV'/'3-Layer SPV' -> '1L'/'2L'/'3L', the
    same abbreviation the watchlist structure cell and the auction Fund Deal
    Summary both use. Unrecognized/blank input returns ''."""
    return {"spv on cap table": "1L", "2-layer spv": "2L",
            "3-layer spv": "3L"}.get((layers_val or "").strip().lower(), "")


def _wl_structure_label(d):
    """Structure cell for a watchlist deal row, annotated with layers and fees:
    'Fund (1L - 5/0/10)' = structure (layers - seller_fee/management_fee/carry).
    Fees show only when at least one of the three is recorded; layers only when
    recognized. Falls back to the bare structure string."""
    base = (d.get("structure") or "").strip()
    layer = _wl_layers_label(d.get("layers"))
    fees = [_fee_pct(d.get("seller_fee")), _fee_pct(d.get("management_fee")),
            _fee_pct(d.get("carry"))]
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
# Update-form link key: the dedicated FORM_HMAC_SECRET env var, the same value
# deal-update-form verifies with. Read from env only -- never hardcoded. When it's
# unset the admin deal-link row is disabled rather than handing out a bad link.
TRADE_UPDATE_SECRET = os.environ.get("FORM_HMAC_SECRET", "")


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
        <div class="sl-block" id="dl-update-block">
          <div class="sl-label">Update request form</div>
          <input id="dl-update" class="sl-url" readonly onclick="this.select()">
          <div class="sl-row">
            <button type="button" onclick="slCopy('dl-update')">Copy</button>
            <a id="dl-update-open" href="#" target="_blank" rel="noopener">Open in new tab &rarr;</a>
          </div>
          <div id="dl-update-note" class="sl-note"></div>
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
            if (!d) { alert('Could not generate links.'); return; }
            var who = document.getElementById('dl-who');
            if (d.name) {
              who.textContent = d.name;
              who.style.color = '';
            } else {
              who.textContent = 'No deal found with that ID — check before sending.';
              who.style.color = '#b45309';
            }
            // No FORM_HMAC_SECRET on this Lambda -> the update row goes dead,
            // same treatment as the LOI row below.
            var ublock = document.getElementById('dl-update-block');
            var unote = document.getElementById('dl-update-note');
            if (d.update_url) {
              ublock.classList.remove('sl-off');
              document.getElementById('dl-update').value = d.update_url;
              document.getElementById('dl-update-open').href = d.update_url;
              unote.textContent = '';
            } else {
              ublock.classList.add('sl-off');
              document.getElementById('dl-update').value = '';
              document.getElementById('dl-update-open').href = '#';
              unote.textContent = d.update_error || 'Update-form links are unavailable.';
            }
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


def _auction_is_live(close_date):
    """The one open/closed rule every live-auctions surface (nav tab, auction
    list, admin table) shares: no close_date (open-ended) or a close_date that
    hasn't passed yet is live; an unparseable close_date is treated as live
    rather than silently hidden."""
    close_date = (close_date or "").strip()
    if not close_date:
        return True
    try:
        return datetime.strptime(close_date, "%Y-%m-%d").date() >= datetime.now(timezone.utc).date()
    except ValueError:
        return True


def _auc_num(v):
    try:
        s = str(v).replace("$", "").replace(",", "").strip()
        return float(s) if s else None
    except (TypeError, ValueError):
        return None


def _auc_tick(price):
    """Standard bid-increment tick for a given reference price."""
    p = price or 0
    if p < 25:
        return 0.10
    if p < 100:
        return 0.25
    if p < 250:
        return 0.50
    if p < 500:
        return 1.00
    return 2.50


def _auc_increment(auc, reference_price):
    """Minimum bid increment in effect at reference_price: the auction's own
    configured Min increment ($) if set and > 0, else the automatic tick."""
    custom = _auc_num((auc or {}).get("min_increment"))
    if custom and custom > 0:
        return custom
    return _auc_tick(reference_price)


AUC_EXTEND_DAYS = (3, 7, 14)
AUC_EXTEND_CAP_DAYS = 30


def _extend_auction(auc, days):
    """Attempt a seller-initiated extension of auc['close_date'] by `days`.
    On success, mutates auc in place and returns (True, None): close_date
    moves forward only, original_bids_close is captured once -- on the
    FIRST extension ever, from whatever close_date was in effect right
    before it -- and never overwritten again, and one entry is appended to
    the auction's own append-only extensions list (past entries are never
    rewritten or dropped). On failure, auc is left untouched and the
    second element is a short error code: "invalid" (bad days value or no
    close_date to extend), "closed" (already past close), or "capped"
    (would land more than AUC_EXTEND_CAP_DAYS past the ORIGINAL close)."""
    if days not in AUC_EXTEND_DAYS:
        return False, "invalid"
    close_date = (auc.get("close_date") or "").strip()
    if not close_date:
        return False, "invalid"
    try:
        old_close = datetime.strptime(close_date, "%Y-%m-%d").date()
    except ValueError:
        return False, "invalid"
    if not _auction_is_live(close_date):
        return False, "closed"
    original = (auc.get("original_bids_close") or "").strip()
    try:
        original_date = (datetime.strptime(original, "%Y-%m-%d").date()
                         if original else old_close)
    except ValueError:
        original_date = old_close
    new_close = old_close + timedelta(days=days)
    if new_close > original_date + timedelta(days=AUC_EXTEND_CAP_DAYS):
        return False, "capped"
    if not original:
        auc["original_bids_close"] = close_date
    auc["close_date"] = new_close.strftime("%Y-%m-%d")
    history = list(auc.get("extensions") or [])
    history.append({
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_added": days,
        "old_close": close_date,
        "new_close": auc["close_date"],
    })
    auc["extensions"] = history
    return True, None


ADMIN_BRIEF_URL = "https://bddpwqsqvt32ritxpjqlqwhaim0ykbol.lambda-url.us-east-1.on.aws/?key=alkj%2A707q235-qjdf"
ADMIN_MAILER_URL = ADMIN_BRIEF_URL + "&view=mailer"
ADMIN_PRICING_URL = "https://jw2kk4a73jbft32yf5lr7u22bm0bgkiy.lambda-url.us-east-1.on.aws/"
# Shared admin key for deal-alerts and syndicate-dash, from the Lambda env.
# Empty -> both URLs are "": server-side syndicate fetches fail soft and the
# keyed admin-hub links are omitted.
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
_ADMIN_KEY_QS = "?key=" + urllib.parse.quote(ADMIN_KEY, safe="")
ADMIN_ALERTS_URL = ("https://3m3tx5bqrdvddzsyjitnjiipjy0hftoe.lambda-url.us-east-1.on.aws/"
                    + _ADMIN_KEY_QS) if ADMIN_KEY else ""
SYNDICATE_DASH_URL = ("https://ws4stw4iul75a7yx5dra2wmnq40kipav.lambda-url.us-east-1.on.aws/"
                      + _ADMIN_KEY_QS) if ADMIN_KEY else ""
# Client-facing dashboard entry; the nav appends a signed &sso= handoff.
CLIENT_DASH_URL = "https://desk.graciagroup.com/dashboard/?tab=overview"
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
        # None (not "") when ADMIN_KEY is unset: rendered greyed out, unlinked.
        ("Client Standing", "Update client badges, tiers and referrals",
         (SYNDICATE_DASH_URL + "&view=standing") if SYNDICATE_DASH_URL else None),
        ("Deal alerts", "Active deals with live counterparty match counts, and a "
                        "button to alert them.",
         ADMIN_ALERTS_URL),
        ("Deal matcher", "Paste an inbound inquiry, match it against the book, draft "
                         "the intro email.",
         "https://izahxskgeee5mihwi7y62v333q0ajkji.lambda-url.us-east-1.on.aws/?key=Vq83RkPnZ2wYhT6d"),
        ("News mailer composer", "Compose and send the company news mailer.",
         "https://bddpwqsqvt32ritxpjqlqwhaim0ykbol.lambda-url.us-east-1.on.aws/?view=news&key=alkj%2A707q235-qjdf"),
        ("Engagement Docs", "Sell-side agreement and Schedule A, prefilled from a deal "
                            "or person. Preview only for now.",
         "?view=engagement"),
    ]
    # Every tool opens in its own tab, so the hub stays put behind them.
    cards = ""
    for title, desc, href in tiles:
        if href is None:  # keyed card shown disabled when ADMIN_KEY is unset
            cards += (f'<div class="hub-card hub-card-off">'
                      f'<div class="hub-title">{html.escape(title)}</div>'
                      f'<div class="hub-desc">{html.escape(desc)}</div></div>')
            continue
        if not href:  # keyed link omitted when ADMIN_KEY is unset
            continue
        cards += (f'<a class="hub-card" href="{html.escape(href, quote=True)}"'
                  f' target="_blank" rel="noopener">'
                  f'<div class="hub-title">{html.escape(title)}</div>'
                  f'<div class="hub-desc">{html.escape(desc)}</div></a>')

    sellers = syndicator_eligible_sellers()
    seller_rows = ""
    for r in sellers[:50]:
        if not SYNDICATE_DASH_URL:
            seller_rows += (
                '<li class="syn-row">'
                f'<span class="syn-name">{html.escape(r["full_name"])}</span>'
                f' &middot; <span class="syn-co">{html.escape(r["company_name"])}</span>'
                '</li>'
            )
            continue
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
        + (f'<a href="{html.escape(SYNDICATE_DASH_URL, quote=True)}" target="_blank" rel="noopener">Open admin view</a>'
           if SYNDICATE_DASH_URL else '') +
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
      .hub-card-off, .hub-card-off:hover {{ opacity:.5; cursor:default;
                   border-color:var(--line); background:#fff; }}
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


# ── Engagement Docs (?view=engagement) — READ-ONLY ───────────────────────────────
# Admin-only form + live preview for the sell-/buy-side agent agreement and Schedule A.
# Reads the CRM snapshot (deals.json, companies.json, syndicate-dash/people-slim.json,
# syndicate-dash/deals-closed.json) and, through its own JSON sub-route, Google Drive.
# Makes NO writes of any kind: no Pipeline API, no S3 put, no Drive write, no email.
# The only non-GET request anywhere in here is the OAuth refresh-token exchange.
ENG_SELLER_LEGAL_FIELD  = "custom_label_3064355"   # Deal: Seller Legal Name
ENG_BUYER_LEGAL_FIELD   = "custom_label_3064356"   # Deal: Buyer Legal Name
ENG_STRUCTURE_FIELD     = "custom_label_3064360"   # Deal: Structure (single id or list)
ENG_COMPANY_LEGAL_FIELD = "custom_label_3769275"   # Company: Legal Name
ENG_MIN_SIZE_FIELD      = "custom_label_3065488"
ENG_MAX_SIZE_FIELD      = "custom_label_3064645"
ENG_BUY_ORDER_OPTION_ID = 5077819                  # custom_label_1958 Buy Order
ENG_STRUCTURE_LABELS    = {6250090: "Direct", 5077906: "SPV", 5077903: "Forward"}
ENG_CLOSED_STAGES       = {"won", "lost", "obsolete", "trade broken"}
ENG_TRANSACTOR_FIELD    = "custom_label_3759163"   # Person: Transactor Type
ENG_TT_INDIVIDUAL       = {6484810, 6716196, 6892622, 6484809}
ENG_TT_LABELS = {6484810: "Natural Person", 6716196: "Employee Holder",
                 6892622: "Employee Holder - VIP", 6484809: "Ex-Employee Holder",
                 6484811: "Family Office", 6484815: "Corporation", 6484808: "VC or PE Fund",
                 6484812: "Institution", 6859893: "Syndicator", 7037492: "Hedge Fund"}
ENG_INVESTOR_LEVEL_FIELD = "custom_label_3923758"  # Person: Investor Level
ENG_INVESTOR_LEVELS = {6950561: "Unknown", 7161646: "Hold: Screen for Substantive",
                       6950562: "Non-Accredited", 7162165: "Substantive",
                       6950563: "Accredited Investor", 7209227: "Qualified Client",
                       6950564: "Qualified Purchaser"}
ENG_PEOPLE_SLIM_KEY     = "syndicate-dash/people-slim.json"   # on COMPANIES_BUCKET
ENG_DEALS_CLOSED_KEY    = "syndicate-dash/deals-closed.json"  # on COMPANIES_BUCKET
ENG_CACHE_SECONDS       = 600

_eng_cache = {"ts": 0.0, "data": None}
_eng_people_cache = None   # see _eng_people()


def _eng_stage_name(deal):
    for key in ("deal_stage", "stage"):
        v = deal.get(key)
        if isinstance(v, dict):
            return (v.get("name") or "").strip()
        if isinstance(v, str):
            return v.strip()
    return ""


def _eng_size(cf, deal):
    """Deal size label from Max Size (else Min Size, else the deal value)."""
    v = None
    for raw in (cf.get(ENG_MAX_SIZE_FIELD), cf.get(ENG_MIN_SIZE_FIELD), deal.get("value")):
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        v = _auc_num(raw)
        if v:
            break
    if not v:
        return ""
    if v >= 1_000_000:
        return f"${v / 1_000_000:.1f}".rstrip("0").rstrip(".") + "M"
    if v >= 1_000:
        return f"${v / 1_000:.0f}K"
    return f"${v:,.0f}"


def _eng_str(v):
    return v.strip() if isinstance(v, str) else ""


def _eng_person_name(p):
    full = (p.get("full_name") or p.get("name") or "").strip()
    if not full:
        full = " ".join(x for x in [(p.get("first_name") or "").strip(),
                                    (p.get("last_name") or "").strip()] if x)
    return full


def _eng_person_company(p):
    """(company_id_str, company_name) for a Pipeline person record."""
    co = p.get("company") if isinstance(p.get("company"), dict) else {}
    cid = co.get("id") or p.get("company_id")
    name = (co.get("name") or p.get("company_name") or "").strip()
    return (str(cid) if cid else ""), name


def _eng_person_phone(p):
    for k in ("phone", "mobile", "work_phone", "mobile_phone", "home_phone"):
        v = _eng_str(p.get(k))
        if v:
            return v
    phones = p.get("phones")
    for x in phones if isinstance(phones, list) else []:
        v = _eng_str(x) if isinstance(x, str) else _eng_str((x or {}).get("number") or (x or {}).get("phone"))
        if v:
            return v
    return ""


def _eng_deal_person_ids(deal):
    ids = []
    for p in deal.get("people") if isinstance(deal.get("people"), list) else []:
        if isinstance(p, dict) and p.get("id") is not None:
            ids.append(str(p["id"]))
    for pid in deal.get("person_ids") or []:
        if pid is not None:
            ids.append(str(pid))
    pc = deal.get("primary_contact")
    if isinstance(pc, dict) and pc.get("id") is not None:
        ids.append(str(pc["id"]))
    return list(dict.fromkeys(ids))


def _eng_people():
    """People from people-slim.json, parsed ONCE per warm instance and kept slim:
       {"by_id": {pid: (pid, name, co, coId, title, phone, tt, il)}, "rows": [...],
        "by_co_id": {coId: [pid]}, "by_co_name": {lower(co): [pid]}, "note": str}
    tt is "individual" / "entity" / "" from Transactor Type; il is the Investor Level
    label. rows is None when the file is unreadable or carries no name + company."""
    global _eng_people_cache
    if _eng_people_cache is not None:
        return _eng_people_cache
    out = {"by_id": {}, "rows": None, "by_co_id": {}, "by_co_name": {}, "note": ""}
    try:
        obj = boto3.client("s3").get_object(Bucket=COMPANIES_BUCKET, Key=ENG_PEOPLE_SLIM_KEY)
        data = json.loads(obj["Body"].read())
    except Exception as e:
        print(f"engagement: people-slim unavailable: {e}")
        out["note"] = f"people-slim.json not readable ({type(e).__name__})"
        _eng_people_cache = out
        return out
    recs = data.get("people", []) if isinstance(data, dict) else (data or [])
    del data
    rows, with_co = [], 0
    for p in recs if isinstance(recs, list) else []:
        if not isinstance(p, dict) or p.get("id") is None:
            continue
        name = _eng_person_name(p)
        if not name:
            continue
        cid, co = _eng_person_company(p)
        cf = p.get("custom_fields") or {}
        tt_ids = cf_id_list(cf.get(ENG_TRANSACTOR_FIELD))
        tt = ("individual" if any(t in ENG_TT_INDIVIDUAL for t in tt_ids)
              else "entity" if tt_ids else "")
        il = next((ENG_INVESTOR_LEVELS[i] for i in cf_id_list(cf.get(ENG_INVESTOR_LEVEL_FIELD))
                   if i in ENG_INVESTOR_LEVELS), "")
        row = (str(p["id"]), name, co, cid, _eng_str(p.get("title")), _eng_person_phone(p), tt, il)
        rows.append(row)
        out["by_id"][row[0]] = row
        if co:
            with_co += 1
            out["by_co_name"].setdefault(co.lower(), []).append(row[0])
        if cid:
            out["by_co_id"].setdefault(cid, []).append(row[0])
    del recs
    if rows and with_co:
        out["rows"] = rows
        out["note"] = "people-slim.json"
    else:
        out["note"] = "people-slim.json has no usable name + company fields"
    _eng_people_cache = out
    return out


def _engagement_data():
    """Everything the page and the sub-routes need, cached ENG_CACHE_SECONDS on the
    warm instance. The page embeds only deals + companies; people are searched
    server-side (api=people) so the page stays small however large the slim file is."""
    now = time.time()
    if _eng_cache["data"] is not None and now - _eng_cache["ts"] < ENG_CACHE_SECONDS:
        return _eng_cache["data"]

    raw_cos = (_wl_json(COMPANIES_BUCKET, COMPANIES_KEY, {}) or {}).get("companies") or []
    co_by_id, companies = {}, []
    for c in raw_cos:
        if not isinstance(c, dict) or c.get("id") is None:
            continue
        name = (c.get("name") or "").strip()
        legal = _eng_str((c.get("custom_fields") or {}).get(ENG_COMPANY_LEGAL_FIELD))
        co_by_id[str(c["id"])] = (name, legal)
        if name and not name.endswith("$"):
            companies.append([str(c["id"]), name, legal])
    companies.sort(key=lambda r: r[1].lower())
    del raw_cos

    ppl = _eng_people()
    try:
        idx = _people_index().get("by_id", {}) or {}
    except Exception:
        idx = {}

    raw_deals = (_wl_json(COMPANIES_BUCKET, DEALS_KEY, {}) or {}).get("deals") or []
    closed = _wl_json(COMPANIES_BUCKET, ENG_DEALS_CLOSED_KEY, None)
    closed_ok = closed is not None
    closed = (closed.get("deals") if isinstance(closed, dict) else closed) or []

    # Seller / Buyer Legal Name per linked person, across live AND closed deals.
    legal_by_pid = {}
    for d in list(raw_deals) + list(closed):
        if not isinstance(d, dict):
            continue
        cf = d.get("custom_fields") or {}
        names = [(n, lab) for n, lab in ((_eng_str(cf.get(ENG_SELLER_LEGAL_FIELD)), "Seller Legal Name"),
                                         (_eng_str(cf.get(ENG_BUYER_LEGAL_FIELD)), "Buyer Legal Name")) if n]
        if not names:
            continue
        for pid in _eng_deal_person_ids(d):
            for n, lab in names:
                legal_by_pid.setdefault(pid, []).append((n, f"{lab} · deal #{d.get('id')}"))

    deals, deal_people = [], {}
    for d in raw_deals:
        if not isinstance(d, dict) or d.get("id") is None:
            continue
        if _eng_stage_name(d).lower() in ENG_CLOSED_STAGES:
            continue
        cf = d.get("custom_fields") or {}
        co = d.get("company") if isinstance(d.get("company"), dict) else {}
        co_id = str(co.get("id") or d.get("company_id") or "")
        co_name = (co.get("name") or "").strip() or co_by_id.get(co_id, ("", ""))[0]
        side_ids = _deal_cf_option_ids(d, SELL_ORDER_FIELD)
        side = ("Sell" if SELL_ORDER_OPTION_ID in side_ids
                else "Buy" if ENG_BUY_ORDER_OPTION_ID in side_ids else "")
        structs = []
        for oid in cf_id_list(cf.get(ENG_STRUCTURE_FIELD)):
            lab = ENG_STRUCTURE_LABELS.get(oid)
            if lab and lab not in structs:
                structs.append(lab)
        embedded = {str(p["id"]): p for p in (d.get("people") if isinstance(d.get("people"), list) else [])
                    if isinstance(p, dict) and p.get("id") is not None}
        people = []
        for pid in _eng_deal_person_ids(d):
            row = ppl["by_id"].get(pid)
            if row:
                people.append([row[0], row[1], row[2], row[3]])
                continue
            p = embedded.get(pid) or {}
            name = _eng_person_name(p) or ((idx.get(pid) or {}).get("name") or "").strip()
            if name:
                pcid, pco = _eng_person_company(p)
                people.append([pid, name, pco, pcid])
        for row in people:
            deal_people.setdefault(row[0], row)
        deals.append({"id": str(d["id"]), "co": co_name, "coId": co_id,
                      "il": co_by_id.get(co_id, ("", ""))[1], "side": side,
                      "size": _eng_size(cf, d), "sl": _eng_str(cf.get(ENG_SELLER_LEGAL_FIELD)),
                      "bl": _eng_str(cf.get(ENG_BUYER_LEGAL_FIELD)), "st": structs,
                      "stage": _eng_stage_name(d), "pp": people})
    deals.sort(key=lambda r: (0 if r["side"] == "Sell" else 1, r["co"].lower()))

    if ppl["rows"]:
        source, fallback = "people-slim.json", None
    else:
        fallback = sorted(deal_people.values(), key=lambda r: r[1].lower())
        source = f"people linked to deals in deals.json ({ppl['note']})"
    data = {"page": {"deals": deals, "companies": companies},
            "legal_by_pid": legal_by_pid, "fallback_people": fallback, "source": source,
            "counts": {"deals_total": len(raw_deals), "deals_live": len(deals),
                       "deals_closed": len(closed), "closed_ok": closed_ok,
                       "companies": len(companies),
                       "people": len(ppl["rows"]) if ppl["rows"] else len(fallback)}}
    _eng_cache.update(ts=now, data=data)
    return data


def _eng_json(obj, status=200):
    return {"statusCode": status, "headers": {"Content-Type": "application/json",
                                              "Cache-Control": "no-store"},
            "body": json.dumps(obj, separators=(",", ":"))}


def _eng_api_people(q):
    """Type-ahead over people by name (and company), max 30 rows."""
    toks = [t for t in (q or "").lower().split() if t]
    if not toks:
        return _eng_json({"people": []})
    ppl = _eng_people()
    if ppl["rows"]:
        rows = ppl["rows"]
    else:
        rows = [(r[0], r[1], r[2], r[3], "", "", "", "") for r in (_engagement_data()["fallback_people"] or [])]
    out = []
    for r in rows:
        hay = (r[1] + " " + r[2]).lower()
        if all(t in hay for t in toks):
            out.append([r[0], r[1], r[2], r[3]])
            if len(out) >= 30:
                break
    return _eng_json({"people": out})


def _eng_api_party(pid, co_id, co_name):
    """Pipeline-only party facts: the person, everyone at their company, and every
    Seller/Buyer Legal Name on live or closed deals linked to any of them."""
    data = _engagement_data()
    ppl = _eng_people()
    person = ppl["by_id"].get(str(pid)) if pid else None
    if person:
        co_id = co_id or person[3]
        co_name = co_name or person[2]
    team_ids = []
    if co_id and ppl["by_co_id"].get(str(co_id)):
        team_ids = ppl["by_co_id"][str(co_id)]
    elif co_name:
        team_ids = ppl["by_co_name"].get(co_name.strip().lower(), [])
    team = [[r[0], r[1], r[4]] for r in (ppl["by_id"].get(t) for t in team_ids[:300]) if r]
    legal, seen = [], set()
    for who in ([str(pid)] if pid else []) + list(team_ids):
        for n, src in data["legal_by_pid"].get(who, []):
            if n.lower() not in seen:
                seen.add(n.lower())
                legal.append([n, src])
    return _eng_json({
        "person": ({"id": person[0], "name": person[1], "co": person[2], "coId": person[3],
                    "title": person[4], "phone": person[5], "tt": person[6], "il": person[7]}
                   if person else None),
        "team": team, "legal": legal})


# ── Google Drive (read-only) — mirrors pipeline-agent's token refresh + folder match ──
ENG_DRIVE_CLIENTS_FOLDER_ID = "15tJGEiOe4eKszNHDLrm5wG_8C6Icn5wo"
ENG_DRIVE_CREDS_BUCKET      = "pipeline-token"
ENG_DRIVE_CREDS_KEY         = "google-drive-oauth.json"
ENG_DRIVE_FILES_URL         = "https://www.googleapis.com/drive/v3/files"
ENG_DRIVE_ALL = {"supportsAllDrives": "true", "includeItemsFromAllDrives": "true",
                 "corpora": "allDrives"}
ENG_CEF_MAX_BYTES = 8 * 1024 * 1024

_eng_drive_creds = None
_eng_drive_token = {"access_token": None, "expires_at": 0}
_eng_drive_cache = {}                     # key -> (ts, result)
_eng_drive_folders = {"ts": 0.0, "folders": None}


class _EngDriveError(Exception):
    pass


def _eng_drive_access_token():
    global _eng_drive_creds
    if _eng_drive_token["access_token"] and time.time() < _eng_drive_token["expires_at"]:
        return _eng_drive_token["access_token"]
    if _eng_drive_creds is None:
        try:
            obj = boto3.client("s3").get_object(Bucket=ENG_DRIVE_CREDS_BUCKET, Key=ENG_DRIVE_CREDS_KEY)
            _eng_drive_creds = json.loads(obj["Body"].read())
        except Exception as e:
            code = e.response.get("Error", {}).get("Code", "") if isinstance(e, ClientError) else ""
            raise _EngDriveError(f"can't read {ENG_DRIVE_CREDS_BUCKET}/{ENG_DRIVE_CREDS_KEY}"
                                 f" ({code or type(e).__name__})")
    body = urllib.parse.urlencode({
        "client_id": _eng_drive_creds.get("client_id", ""),
        "client_secret": _eng_drive_creds.get("client_secret", ""),
        "refresh_token": _eng_drive_creds.get("refresh_token", ""),
        "grant_type": "refresh_token",
    }).encode()
    req = urllib.request.Request("https://oauth2.googleapis.com/token", data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            tok = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise _EngDriveError(f"Google token refresh failed (HTTP {e.code})")
    except Exception as e:
        raise _EngDriveError(f"Google token refresh failed ({type(e).__name__})")
    _eng_drive_token["access_token"] = tok["access_token"]
    _eng_drive_token["expires_at"] = time.time() + int(tok.get("expires_in", 3600)) - 60
    return _eng_drive_token["access_token"]


def _eng_drive_get(url, params, raw=False, _retried=False):
    """Drive GET (the only Drive method this page ever uses). JSON dict, or bytes
    when raw. Raises _EngDriveError with a short reason."""
    token = _eng_drive_access_token()
    req = urllib.request.Request(f"{url}?{urllib.parse.urlencode(params)}",
                                 headers={"Authorization": f"Bearer {token}"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read(ENG_CEF_MAX_BYTES + 1) if raw else resp.read()
            return body if raw else json.loads(body.decode() or "{}")
    except urllib.error.HTTPError as e:
        if e.code == 401 and not _retried:
            _eng_drive_token.update(access_token=None, expires_at=0)
            return _eng_drive_get(url, params, raw, _retried=True)
        raise _EngDriveError(f"Drive returned HTTP {e.code}")
    except _EngDriveError:
        raise
    except Exception as e:
        raise _EngDriveError(f"Drive request failed ({type(e).__name__})")


def _eng_drive_list(q, fields):
    files, page_token = [], None
    while True:
        params = dict(ENG_DRIVE_ALL, q=q, fields=f"nextPageToken,files({fields})", pageSize=1000)
        if page_token:
            params["pageToken"] = page_token
        r = _eng_drive_get(ENG_DRIVE_FILES_URL, params)
        files.extend(r.get("files", []))
        page_token = r.get("nextPageToken")
        if not page_token:
            return files


def _eng_client_folders():
    now = time.time()
    if _eng_drive_folders["folders"] is None or now - _eng_drive_folders["ts"] > ENG_CACHE_SECONDS:
        _eng_drive_folders["folders"] = _eng_drive_list(
            f"'{ENG_DRIVE_CLIENTS_FOLDER_ID}' in parents and "
            "mimeType='application/vnd.google-apps.folder' and trashed=false", "id,name")
        _eng_drive_folders["ts"] = now
    return _eng_drive_folders["folders"]


_ENG_ENTITY_SUFFIXES = {"llc", "inc", "incorporated", "ltd", "limited", "lp", "llp",
                        "corp", "corporation", "co", "gmbh", "sa", "ag", "plc"}


def _eng_folder_tokens(name, drop_suffixes=True):
    s = (name or "").lower()
    s = re.sub(r"[-‐‑‒–—/]", " ", s)   # dashes/slashes separate words
    s = re.sub(r"[^\w\s]", "", s)      # other punctuation dropped: "l.l.c." -> "llc"
    tokens = s.split()
    while drop_suffixes and len(tokens) > 1 and tokens[-1] in _ENG_ENTITY_SUFFIXES:
        tokens.pop()
    return tokens


def _eng_match_client_folders(client_name, client_type, folders):
    """pipeline-agent's tiered matching, read-only. Returns (matches, near_matches)."""
    target = _eng_folder_tokens(client_name)
    if not target:
        return [], []
    normed = [(f, _eng_folder_tokens(f.get("name"))) for f in folders]
    tier1 = [f for f, t in normed if t == target]
    if tier1:
        return tier1, []
    if client_type == "person":
        tier2 = [f for f, t in normed if set(t) == set(target)]
        if tier2:
            return tier2, []
    prefixes = [target]
    if client_type == "person" and "," not in client_name and len(target) > 1:
        prefixes.append([target[-1]] + target[:-1])
    tier3 = []
    for f in folders:
        t = _eng_folder_tokens(f.get("name"), drop_suffixes=False)
        if any(t[:len(pre)] == pre for pre in prefixes):
            tier3.append(f)
    if tier3:
        return tier3, []
    near = []
    for f, t in normed:
        if not t:
            continue
        shared = set(t) & set(target)
        if target[:len(t)] == t or (len(shared) >= 2 and len(shared) / len(set(t) | set(target)) >= 0.6):
            near.append(f)
    return [], near


_ENG_CEF_LABELS = [
    ("entity_name", r"Name\s+of\s+Entity\s+Client"),
    ("_", r"Principal\s+Place\s+of\s+Business\s+of\s+Entity\s+Client"),
    ("person_name", r"Name\s+of\s+Natural\s+Person\s+Client"),
    ("_", r"Address\s+of\s+Client"),
    ("phone", r"(?:Client\s+)?(?:Phone|Telephone)(?:\s+Number)?"),
    ("_", r"Client\s+Email|Email(?:\s+Address)?|OPTIONAL:|Entity\s+Client\s+US\s+Tax\s+ID"
          r"|Client'?s\s+Total\s+Assets|Entity\s+Control\s+Person|Name\s+of\s+Entity\s+Control"
          r"|Control\s+Person|Date\s+of\s+Birth|Is\s+the\s+Client|Tax\s+ID|Identity\s+Verification"
          r"|Natural\s+Person\s+Client\s+Profile|Address\s+of\s+Employer|Attestation"
          r"|Please\s+confirm|Submission\s+Date|Who\s+is\s+the|Page\s+\d+|Upload"),
]
_ENG_CEF_NOISE = re.compile(r"^(?:PDF|IMG|JPG|JPEG|PNG|\d{1,2})$|\.(?:pdf|jpe?g|png|heic)$", re.I)


def _eng_parse_cef(text):
    """Pull the client's name and phone out of a Jotform CEF's text.
    Returns {"kind": "entity"|"individual"|"", "name", "phone"}."""
    hits = []
    for key, pat in _ENG_CEF_LABELS:
        for m in re.finditer(pat, text):
            hits.append((m.start(), m.end(), key))
    hits.sort()
    # Drop labels that sit inside a longer label already matched.
    clean, last_end = [], -1
    for h in hits:
        if h[0] >= last_end:
            clean.append(h)
            last_end = h[1]
    vals = {}
    for i, (s, e, key) in enumerate(clean):
        if key == "_" or key in vals:
            continue
        nxt = clean[i + 1][0] if i + 1 < len(clean) else len(text)
        lines = [ln.strip() for ln in text[e:nxt].splitlines()]
        vals[key] = [ln for ln in lines if ln and not _ENG_CEF_NOISE.search(ln)]

    phone = " ".join(vals.get("phone", [])[:1])
    if not re.search(r"\d{3}", phone):
        phone = ""
    if vals.get("entity_name"):
        return {"kind": "entity", "name": vals["entity_name"][0],
                "phone": phone}
    if vals.get("person_name"):
        return {"kind": "individual", "name": vals["person_name"][0],
                "phone": phone}
    return {"kind": "", "name": "", "phone": phone}


def _eng_cef_text(pdf_bytes):
    """Text of a CEF PDF via pypdf (bundled by deploy.yml). None if pypdf is absent."""
    try:
        import io as _io
        import pypdf
    except ImportError:
        return None
    reader = pypdf.PdfReader(_io.BytesIO(pdf_bytes))
    return "\n".join((pg.extract_text() or "") for pg in reader.pages)


_ENG_AGREEMENT_NAME = re.compile(r"Agent\s+Agreement\s*-\s*(.+?)\s+-\s+", re.I)


def _eng_drive_lookup(person_name, company_name):
    """Read-only Drive facts for a party: matched client folders, entity names from
    agreement file names, signed sell/buy agreements, and the newest CEF parsed."""
    folders = _eng_client_folders()
    picked = []
    for nm, typ in ((person_name, "person"), (company_name, "entity")):
        if nm:
            matches, _near = _eng_match_client_folders(nm, typ, folders)
            for f in matches:
                if f["id"] not in {p["id"] for p in picked}:
                    picked.append({"id": f["id"], "name": f.get("name", ""), "for": typ})
    files = []
    for f in picked:
        for x in _eng_drive_list(f"'{f['id']}' in parents and trashed=false and "
                                 "mimeType!='application/vnd.google-apps.folder'",
                                 "id,name,mimeType,modifiedTime"):
            x["_folder"] = f["name"]
            files.append(x)
    names, signed = [], {"sell": [], "buy": []}
    for x in files:
        n = x.get("name") or ""
        m = _ENG_AGREEMENT_NAME.search(n)
        if m and m.group(1).strip() not in names:
            names.append(m.group(1).strip())
        low = n.lower()
        if "agent agreement" in low and "signed" in low:
            if "sell" in low:
                signed["sell"].append(n)
            if "buy" in low:
                signed["buy"].append(n)
    cefs = sorted([x for x in files if "client engagement form" in (x.get("name") or "").lower()
                   and (x.get("mimeType") == "application/pdf" or (x.get("name") or "").lower().endswith(".pdf"))],
                  key=lambda x: x.get("modifiedTime") or "", reverse=True)
    cef, cef_note = None, ""
    if cefs:
        blob = _eng_drive_get(f"{ENG_DRIVE_FILES_URL}/{cefs[0]['id']}",
                              {"alt": "media", "supportsAllDrives": "true"}, raw=True)
        if len(blob) > ENG_CEF_MAX_BYTES:
            cef_note = "CEF too large to read"
        else:
            try:
                text = _eng_cef_text(blob)
            except Exception as e:
                text, cef_note = "", f"CEF unreadable ({type(e).__name__})"
            if text is None:
                cef_note = "CEF parsing unavailable (pypdf not installed)"
            elif text:
                cef = _eng_parse_cef(text)
                cef["file"] = cefs[0].get("name", "")
    return {"ok": True,
            "folders": [{"name": f["name"], "for": f["for"],
                         "url": f"https://drive.google.com/drive/folders/{f['id']}"} for f in picked],
            "entity_names": names, "signed": signed, "cef": cef, "cef_note": cef_note,
            "files": len(files)}


def _eng_api_drive(person_name, company_name):
    key = ((person_name or "").strip().lower(), (company_name or "").strip().lower())
    hit = _eng_drive_cache.get(key)
    if hit and time.time() - hit[0] < ENG_CACHE_SECONDS:
        return _eng_json(hit[1])
    try:
        result = _eng_drive_lookup(person_name, company_name)
    except _EngDriveError as e:
        result = {"ok": False, "error": str(e)}
    except Exception as e:
        print(f"engagement: drive lookup failed: {e}")
        result = {"ok": False, "error": f"unexpected error ({type(e).__name__})"}
    _eng_drive_cache[key] = (time.time(), result)
    return _eng_json(result)


def _engagement_route(qs):
    """?view=engagement and its JSON sub-routes. Caller has already enforced the
    admin gate; every branch here is a read."""
    api = qs.get("api") or ""
    if api == "people":
        return _eng_api_people(qs.get("q") or "")
    if api == "party":
        return _eng_api_party(qs.get("pid") or "", qs.get("co_id") or "", qs.get("co_name") or "")
    if api == "drive":
        return _eng_api_drive(qs.get("person") or "", qs.get("company") or "")
    return render_engagement()


ENG_FEE_TEMPLATES = [
    "{p}% multiplied by the Transaction Value for transactions at or under $1,000,000; or",
    "{p}% multiplied by the Transaction Value for transactions between $1,000,001 and $5,000,000; or",
    "{p}% multiplied by the Transaction Value for transactions between $5,000,001 and $10,000,000; or",
    "{p}% multiplied by the Transaction Value for transactions above $10,000,001.",
]
ENG_FEES_STANDARD = ["5", "4.0", "3.5", "2.5"]
ENG_FEES_GENEROUS = ["4", "3.5", "3", "2"]
# Non-Circumvention's item number under "2. TERMS AND CONDITIONS", read from the Google
# Docs "Sell-Side Secondary Agent Agreement Template" and "Buy-Side Agent Agreement
# Template" (the buy-side template has no Regulation S-P item, so it sits one earlier).
ENG_NONCIRC_SECTION = {"sell": 6, "buy": 5}
# Agreement text for the print version, copied verbatim (typos included) from the Google
# Docs "Sell-Side Secondary Agent Agreement Template" (1mEO3PEVnltSmUASFq6s-f9ePaKx9224hFC9l12tCYeE)
# and "Buy-Side Agent Agreement Template" (1JgRtsRkkl1TuKRQiNiQQxrnL8FXnwTTtNy6IYpkNunw).
# Blocks: top / title / h (section heading) / p / r (recital) / c [title, rest] (clause) /
# s1, s2 (sub-points) / sigfollow / sigp. The page numbers them; the text is untouched.
ENG_PRINT_TEMPLATES_JSON = (
    "{\"sell\": [[\"top\", \"Sell-Side Secondary\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00"
    "a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0CONFIDENTI"
    "AL\"], [\"title\", \"AGENT AGREEMENT\"], [\"h\", \"OVERVIEW\"], [\"p\", \"This Sell-Side Agent Agreement (\\u"
    "201cAgreement\\u201d) is made and entered into as of August 29th, 2026 (\\u201cEffective Date\\u201"
    "d), by and between Rainmaker Securities, LLC, a FINRA registered broker-dealer with CRD# 132995 "
    "(\\u201cRMS\\u201d) and \\u201cSeller\\u201d with a name and address as specified on the signature p"
    "age to this Agreement. RMS and Seller may each be referred to individually as a \\u201cParty\\u201"
    "d and together as the \\u201cParties\\u201d.\"], [\"r\", \"Seller offers the \\u201cSecurities\\u201d of"
    " the \\u201cIssuer\\u201d, as defined in Schedule A\\u00a0to this Agreement, pursuant to exemption "
    "from registration under the Securities Act of 1933 (\\u201cSecurities Act\\u201d).\"], [\"r\", \"Selle"
    "r engages RMS as its agent to refer Seller to potential buyers of the Securities (\\u201cBuyers\\u"
    "201d). \"], [\"r\", \"Upon completion of a (a) direct sale, (b) indirect transfer of interest in, or"
    " (c) hypothecation of the Securities involving (i) Seller or Seller\\u2019s affiliate, and (ii) a"
    " Referred Buyer (\\u201cTransaction\\u201d), RMS shall be paid a commission based upon the value o"
    "f the consideration paid from the Referred Buyer to the Seller within the Transaction (\\u201cTra"
    "nsaction Value\\u201d).\"], [\"p\", \"In consideration of the mutual covenants, promises and obligati"
    "ons set forth below, the Parties agree as follows:\"], [\"h\", \"TERMS AND CONDITIONS\"], [\"c\", \"Regu"
    "lation S-P Notification.\", \" \\u00a0Seller acknowledges that the RMS privacy notice, provided pur"
    "suant to SEC Regulation S-P, is available at www.rainmakersecurities.com/privacy-policy\\u00a0and"
    " agrees that delivery via this hyperlink constitutes delivery of the Regulation S-P privacy noti"
    "ce.\"], [\"c\", \"Scope of Services.\", \"\\u00a0Seller engages RMS as its agent to use commercially re"
    "asonable efforts to refer Seller to potential Buyers that RMS reasonably believes are ready, wil"
    "ling, and able to enter into a Transaction (the \\u201cServices\\u201d).\\u00a0On an as needed basi"
    "s, and in furtherance of RMS performance of the Services, Seller authorizes RMS to enter into fe"
    "e sharing arrangements with third-party brokers, agents, and finders, provided that no such arra"
    "ngement shall result in any additional cost to Seller beyond that which is contemplated by this "
    "Agreement. Seller acknowledges that RMS provides no representation, assurance, or warranty that "
    "a Referral will be made or Transaction will be completed. Seller may accept or reject any propos"
    "ed Transaction for any reason or no reason in Seller\\u2019s sole discretion.\"], [\"c\", \"Referred "
    "Buyer.\", \"\\u00a0A Buyer shall qualify as a Referred Buyer if RMS or an existing Referred Buyer ("
    "each a \\u201cReferring Party\\u201d) makes a Referral to such Buyer during the term of this Agree"
    "ment. \"], [\"s1\", \"A \\u201cReferral\\u201d shall be deemed to have occurred if:\"], [\"s2\", \"Referri"
    "ng Party introduces such Buyer to the Seller, Seller\\u2019s affiliate, or their respective emplo"
    "yees, officers, agents, or representatives (\\u201cSeller\\u00a0Representatives\\u201d); or \"], [\"s"
    "2\", \"Referring Party notifies Seller or Seller Representatives or otherwise makes them aware of "
    "Buyer\\u2019s interest in the purchase of Seller\\u2019s Securities.\"], [\"s1\", \"A Referred Buyer s"
    "hall also include any affiliate, subsidiary, related parties under common control of such Referr"
    "ed Buyer, and entities owned or controlled by such Referred Buyer. \"], [\"s1\", \"A Referral shall "
    "be presumed valid, unless disqualified. A Buyer shall be disqualified as a Referred Buyer if, wi"
    "thin two business days of a Referral, the Seller can provide substantive, written evidence that "
    "the Seller had, previously and independently from the Referring Party efforts, been in mutual co"
    "mmunications with the Buyer regarding a Transaction for the Securities during the six month peri"
    "od prior to the Referral.\"], [\"c\", \"Success Fees.\", \"\\u00a0If Referred Buyer completes a Transac"
    "tion within the \\u201cTail Period\\u201d, as defined in Schedule A\\u00a0to this Agreement, RMS sh"
    "all be paid a commission based upon the Transaction Value (\\u201cSuccess Fee\\u201d). The Success"
    " Fee shall be paid to RMS as follows:\"], [\"s1\", \"The Success Fee shall be calculated as defined "
    "in Schedule A.\"], [\"s1\", \"The Success Fee shall be paid via wire transfer, in U.S. Dollars, and "
    "in immediately available funds to the accounts and in the amounts set forth in the wire transfer"
    " instructions provided by RMS.\"], [\"s1\", \"The Success Fee shall become due and payable concurren"
    "tly with payment of the Transaction Value by the Referred Buyer to the Seller, whether Transacti"
    "on Value is paid via the closing of escrow or via direct payment to the Seller.\"], [\"s1\", \"In th"
    "e event escrow is used to complete a Transaction, the Seller agrees, at the sole discretion and "
    "direction of RMS, to include as irrevocable conditions to closing of escrow, the payment of the "
    "applicable Success Fee due.\"], [\"s1\", \"If the Transaction requires Issuer approval, the Seller s"
    "hall remain obligated to pay the Success Fee to RMS if, as a direct result of submitting a Refer"
    "red Buyer\\u2019s Transaction for the Securities to the Issuer, the Issuer or existing shareholde"
    "r of the Issuer purchases the Securities, whether via the exercise of any applicable right of fi"
    "rst refusal or otherwise.\"], [\"c\", \"Late Fees.\", \"\\u00a0For each thirty-days an outstanding bala"
    "nce remains due and payable by Seller, RMS shall assess a late fee equal to the lesser of: (i) o"
    "f five percent [5%]; or (ii) the maximum percentage allowable by applicable law (\\u201cLate Fee\\"
    "u201d). \\u00a0The Late Fee shall be assessed on the total outstanding balance due and payable at"
    " each thirty-day interval, including Late Fees previously assessed.\"], [\"c\", \"Non-Circumvention."
    "\", \" Seller shall not circumvent, avoid, bypass or obviate RMS, directly or indirectly, to avoid"
    " payment of Success Fees to RMS. Furthermore, Seller shall not, and Seller shall not direct its "
    "affiliates, employees, directors, officers, partners, or advisors to contact, solicit, or deal w"
    "ith any Referred Buyer, directly or indirectly, in connection with the purchase or sale of secur"
    "ities without express written authorization of RMS. During the Tail Period, Seller shall not dir"
    "ectly market or offer any securities to a Referred Buyer without RMS's prior written consent, or"
    " without paying RMS its applicable Success Fee in the event a Transaction is completed.\"], [\"c\","
    " \"Termination.\", \"\\u00a0This Agreement may be terminated by either Party upon delivery of writte"
    "n notice at least thirty days prior to termination. Upon termination, RMS shall immediately ceas"
    "e solicitation of Referrals on behalf of Seller. Seller\\u2019s obligation to pay any outstanding"
    " balance shall survive termination. Seller\\u2019s obligation to pay Success Fees shall survive w"
    "hen: (i) the Referral occurred prior to termination; and (ii) the Transaction is initiated befor"
    "e the end of the Tail Period.\"], [\"h\", \"REPRESENTATIONS, WARRANTIES, AND COVENANTS\"], [\"c\", \"\", "
    "\"Mutual representations, warranties, and covenants of the Parties:\"], [\"s1\", \"This Agreement has"
    " been duly authorized, executed, and delivered on its behalf, and is its legal, valid and bindin"
    "g agreement, enforceable against it in accordance with its terms.\"], [\"s1\", \"Party is either a n"
    "atural person, or an entity that is duly organized, validly existing and in good standing under "
    "the laws of the state of its jurisdiction of formation or organization and has full power and au"
    "thority to execute, deliver and perform its obligations under this Agreement. The Party\\u2019s p"
    "erformance of its obligations under this Agreement will not conflict with, violate the terms of "
    "or constitute a default under: (A) its articles of incorporation, by-laws or similar governing d"
    "ocuments; (B) any other agreement or instrument to which it is a party or by which it is bound o"
    "r to which any of its property or assets are subject; or (C) any order, rule, law, regulation, o"
    "r other legal requirement applicable to it or its property or assets.\"], [\"c\", \"\", \"Seller repre"
    "sents, warrants to, and covenants with RMS as follows:\"], [\"s1\", \"Seller has entered into this A"
    "greement in its sole discretion, and not as a result of any influence, advice, call to action, o"
    "r recommendation made by RMS or its representatives.\"], [\"s1\", \"Each Transaction will be structu"
    "red and effected pursuant to an applicable exemption from registration under the Securities Act "
    "and applicable state securities laws. The Seller shall be solely responsible for ensuring each T"
    "ransaction complies with all applicable provisions of the Securities Act, as well as applicable "
    "state securities laws. The Seller shall not structure or execute any Transaction in a manner tha"
    "t would require RMS to be registered with the Commodity Futures Trading Commission in any capaci"
    "ty under the Commodity Exchange Act.\"], [\"s1\", \"Seller agrees to provide RMS with the Seller\\u20"
    "19s identity verification information and Transaction documentation RMS reasonably deems require"
    "d to maintain compliance with applicable laws and regulations.\"], [\"s1\", \"In the event Seller en"
    "ters into a Transaction structured as a forward sale contract involving the Securities, Seller r"
    "epresents and warrants to RMS:\"], [\"s2\", \"Seller qualifies as an \\u201cEligible Contract Partici"
    "pant\\u201d as defined by Section 1a(18) of the Commodities Exchange Act, as amended; or \"], [\"s2"
    "\", \"Seller is not aware (and has not been made aware) of any contractual restrictions on transfe"
    "r of the Securities, or Seller has obtained a waiver from the Issuer with respect to such restri"
    "ctions; and\"], [\"s2\", \"Any such forward sale agreement between Seller and Buyer shall be intende"
    "d to be physically settled via the delivery of Securities without option for cash offset.\"], [\"s"
    "1\", \"Seller has read and understands the required broker-dealer disclosures located at www.rainm"
    "akersecurities.com/disclosures, including but not limited to, the Relationship Summary.\"], [\"c\","
    " \"\", \"RMS represents, warrants to, and covenants with Seller as follows:\"], [\"s1\", \"RMS agrees t"
    "o maintain any and all registrations and licenses under the relevant laws applicable to its oper"
    "ations in connection with the services performed pursuant to this Agreement including registrati"
    "on as a broker-dealer with the SEC, FINRA, and every state or territory of the United States of "
    "America where such registration is required to complete a Transaction.\"], [\"s1\", \"RMS shall be r"
    "esponsible for supervising the activities of its associated persons that are conducted in furthe"
    "rance of this Agreement to ensure compliance with applicable law.\"], [\"h\", \"MISCELLANEOUS TERMS "
    "AND CONDITIONS\"], [\"c\", \"Entire Agreement.\", \"\\u00a0This Agreement, together with any Schedules,"
    " constitutes the entire agreement between the Parties and supersedes, voids, and rescinds any an"
    "d all prior oral or written agreements between RMS and Seller on the subject matter related to t"
    "his Agreement, except with respect to any Non-Circumvention or Non-Disclosure Agreements execute"
    "d between the Parties. This Agreement may not be amended nor modified except by the mutual writt"
    "en agreement of the Parties. The Parties understand and agree that only the RMS President, Gener"
    "al Counsel, and/or Managing Director have the authority to bind RMS to this agreement.\"], [\"c\", "
    "\"Counterparts.\", \"\\u00a0This Agreement may be executed in counterparts, each of which shall be d"
    "eemed an original but all of which shall constitute one and the same instrument.\"], [\"c\", \"Sever"
    "ability.\", \"\\u00a0Any provision of this Agreement that is prohibited or unenforceable in any jur"
    "isdiction shall, as to such jurisdiction, be ineffective to the extent of such prohibition or un"
    "enforceability without invalidating the remaining provisions, and any such prohibition or unenfo"
    "rceability in any jurisdiction shall not invalidate or render unenforceable such provision in an"
    "y other jurisdiction.\"], [\"c\", \"Headings:\", \" \\u00a0Headings of this Agreement are for the conve"
    "nience of the Parties only, and are not intended to be a part of or to affect the meanings or in"
    "terpretation of this Agreement.\"], [\"c\", \"Assignment and Successors.\", \"\\u00a0This Agreement sha"
    "ll be binding upon, and shall inure to the benefit of the Parties hereto, their successors, perm"
    "itted assigns and legal representatives as well as subsidiaries, affiliates, joint-ventures, hei"
    "rs and any other related parties or entities. This Agreement shall not be assigned by the Partie"
    "s without prior mutual written consent.\"], [\"c\", \"Waiver.\", \"\\u00a0 The waiver by a Party of a b"
    "reach of any provision of this Agreement shall not operate nor be construed as a waiver of any s"
    "ubsequent breach by a Party. The failure of a Party to insist upon strict adherence to any provi"
    "sion of this Agreement shall not constitute a waiver or thereafter deprive such Party of the rig"
    "ht to insist upon a strict adherence.\"], [\"c\", \"Privacy Notice.\", \"\\u00a0To help the government "
    "fight the funding of terrorism and money laundering activities, federal law requires all financi"
    "al institutions to obtain, verify, and record information about the identities of individuals an"
    "d institutions with which it does business. Therefore, RMS will verify the information provided "
    "by the counterparty of this Agreement through publicly available private and government sources."
    "\"], [\"c\", \"Notice to the Parties.\", \"\\u00a0The \\u201cwritten notice\\u201d requirement of this Ag"
    "reement shall be satisfied if received at the Party\\u2019s address or email specified on the sig"
    "nature page, or, if to Seller, (i) via email sent to Seller\\u2019s account last known to RMS, or"
    " (ii) by letter sent via post or courier to the Seller\\u2019s address last known to RMS.\"], [\"c\""
    ", \"Relationship of Parties.\", \"\\u00a0Neither Party may legally bind the other Party, unless expr"
    "essly authorized in writing. No joint venture, partnership, employment, or any other relationshi"
    "p, including any clearing arrangement, is intended, accomplished or embodied in this Agreement. "
    "Both Parties may have similar dealings with other parties and their relationship is only exclusi"
    "ve to the extent specified in the Agreement.\"], [\"c\", \"Indemnification.\", \"\\u00a0Each Party agre"
    "es to indemnify, defend and hold harmless the other Party (including its respective affiliates, "
    "directors, officers, employees, successors and agents) from and against any and all losses, clai"
    "ms, expenses, damages and liabilities (including reasonable attorney fees and disbursements and "
    "other expenses for investigating or defending any actions or threatened actions) to which such o"
    "ther Party may become subject based upon, arising out of or otherwise in respect of the other Pa"
    "rty\\u2019s willful misconduct, gross negligence, fraudulent or criminal act, or a material breac"
    "h of this Agreement by the Party of the provisions of this Agreement. Parties agree to notify ea"
    "ch other, in writing, within fifteen days of any claim asserted or any legal action commenced ag"
    "ainst it in connection with this Agreement. The indemnifying Party shall not be liable to indemn"
    "ify the other Party for an aggregate amount of losses in excess of the total value of the Succes"
    "s Fees which were paid or made payable under the Agreement.\"], [\"c\", \"Governing Law and Jurisdic"
    "tion.\", \" This Agreement shall be construed and governed in accordance with the laws of the Stat"
    "e of Delaware, without reference to its conflict of laws provisions. The Parties submit to the e"
    "xclusive jurisdiction of the state or federal courts located in the State of Delaware (\\u201cCou"
    "rts\\u201d).\"], [\"c\", \"FINRA Pre-Dispute Arbitration Disclosure.\", \" By signing this Agreement, t"
    "he Parties acknowledge and agrees to the following:\"], [\"s1\", \"All Parties to this Agreement are"
    " giving up the right to sue each other in court, including the right to a trial by jury, except "
    "as provided by the rules of the arbitration forum in which a claim is filed.\"], [\"s1\", \"Arbitrat"
    "ion awards are generally final and binding; a Party's ability to have a court reverse or modify "
    "an arbitration award is very limited.\"], [\"s1\", \"The ability of the Parties to obtain documents,"
    " witness statements and other discovery is generally more limited in arbitration than in court p"
    "roceedings.\"], [\"s1\", \"The arbitrators do not have to explain the reason(s) for their award unle"
    "ss, in an eligible case, a joint request for an explained decision has been submitted by all Par"
    "ties to the panel at least 20 days prior to the first scheduled hearing date.\"], [\"s1\", \"The pan"
    "el of arbitrators may include a minority of arbitrators who were or are affiliated with the secu"
    "rities industry.\"], [\"s1\", \"The rules of some arbitration forums may impose time limits for brin"
    "ging a claim in arbitration. In some cases, a claim that is ineligible for arbitration may be br"
    "ought in court.\"], [\"s1\", \"The rules of the arbitration forum in which the claim is filed, and a"
    "ny amendments thereto, shall be incorporated into this agreement.\"], [\"s1\", \"No person shall bri"
    "ng a putative or certified class action to arbitration, nor seek to enforce any pre-dispute arbi"
    "tration agreement against any person who has initiated in court a putative class action; or who "
    "is a member of a putative class who has not opted out of the class with respect to any claims en"
    "compassed by the putative class action until: (i) the class certification is denied; or (ii) the"
    " class is decertified; or (iii) the customer is excluded from the class by the court. Such forbe"
    "arance to enforce an agreement to arbitrate shall not constitute a waiver of any rights under th"
    "is agreement except to the extent stated herein.\"], [\"s1\", \"By initiating, consenting to, or sub"
    "stantially participating in any legal proceeding or arbitration administered by a forum other th"
    "an FINRA, including, without limitation, JAMS or the Courts, the Seller shall be deemed to have "
    "voluntarily and knowingly waived any right to compel arbitration before FINRA in connection with"
    " such dispute.\"], [\"c\", \"Dispute Resolution.\", \"\\u00a0Any dispute, claim or controversy arising "
    "out of or relating to this Agreement or the breach, termination, enforcement, interpretation or "
    "validity of the Agreement, including the determination of the scope or applicability of this agr"
    "eement to arbitrate, whether brought against a Party or its respective affiliates, employees or "
    "agents (\\u201cDispute\\u201d), shall be submitted to and administered by JAMS pursuant to its Com"
    "prehensive Arbitration Rules and Procedures and in accordance with the Expedited Procedures in t"
    "hose Rules (\\u201cJAMS Rules\\u201d). Arbitration under the JAMS Rules shall be held via remote h"
    "earings before three arbitrators. Judgment on the award shall be final and may be entered in any"
    " court having jurisdiction. This clause shall not preclude either Party from seeking provisional"
    " remedies in aid of arbitration from the Courts.\\u00a0\"], [\"p\", \"If arbitration administered by "
    "JAMS is not permitted by law, then any action, claim, suit, or proceeding (\\u201cProceeding\\u201"
    "d) concerning the Dispute may be commenced exclusively in the Courts. Each Party submits to the "
    "exclusive jurisdiction of the Courts and waives the right to assert in any Proceeding, any claim"
    " that it is not personally subject to the jurisdiction of the Courts, or that such Proceeding ha"
    "s been commenced in an improper or inconvenient forum. \"], [\"sigfollow\", \"[SIGNATURE PAGE TO FOL"
    "LOW]\"], [\"h\", \"SIGNATURES AND ACKNOWLEDGEMENTS\"], [\"sigp\", \"This Agreement contains a pre-disput"
    "e arbitration clause. By executing this Agreement, the Parties agree that they acknowledge and u"
    "nderstand the FINRA Pre-Dispute Arbitration Disclosure.\"]], \"buy\": [[\"top\", \"Buy-Side Secondary\\"
    "u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\"
    "u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0\\u00a0CONFIDENTIAL\"], [\"title\", \"AGENT AGREEMENT\"], [\"h"
    "\", \"OVERVIEW\"], [\"p\", \"This Buy-Side Agent Agreement (\\u201cAgreement\\u201d) is made and entered"
    " into as of Oct 1, 2026\\u00a0(\\u201cEffective Date\\u201d), by and between Rainmaker Securities, "
    "LLC, a FINRA registered broker-dealer with CRD# 132995 (\\u201cRMS\\u201d) and \\u201cBuyer\\u201d w"
    "ith a name and address as specified on the signature page to this Agreement. RMS and Buyer may e"
    "ach be referred to individually as a \\u201cParty\\u201d and together as the \\u201cParties\\u201d.\""
    "], [\"r\", \"Buyer seeks to purchase the \\u201cSecurities\\u201d of the \\u201cIssuer\\u201d, as defin"
    "ed in Schedule A\\u00a0to this Agreement, which are sold pursuant to exemption from registration "
    "under the Securities Act of 1933 (\\u201cSecurities Act\\u201d).\"], [\"r\", \"Buyer engages RMS as it"
    "s non-exclusive agent to refer Buyer to potential sellers of the Securities (\\u201cSellers\\u201d"
    "). \"], [\"r\", \"Upon completion of a direct sale, indirect transfer, or hypothecation of the Secur"
    "ities involving a Referred Seller and the Buyer (\\u201cTransaction\\u201d), RMS shall be paid a c"
    "ommission based upon the value of the consideration paid from the Buyer to the Seller within the"
    " Transaction (\\u201cTransaction Value\\u201d).\"], [\"p\", \"In consideration of the mutual covenants"
    ", promises and obligations set forth below, the Parties agree as follows:\"], [\"h\", \"TERMS AND CO"
    "NDITIONS\"], [\"c\", \"Scope of Services.\", \"\\u00a0Buyer engages RMS as its non-exclusive agent to u"
    "se commercially reasonable efforts to refer Buyer to potential Sellers that RMS reasonably belie"
    "ves are ready, willing, and able to enter into a Transaction (the \\u201cServices\\u201d). On an a"
    "s needed basis, and in furtherance of RMS performance of the Services, Buyer authorizes RMS to e"
    "nter into fee sharing arrangements with third-party brokers, agents, and finders, provided that "
    "no such arrangement shall result in any additional cost to Buyer beyond that which is contemplat"
    "ed by this Agreement. Buyer acknowledges that RMS provides no representation, assurance, or warr"
    "anty that a Referral will be made or Transaction will be completed.\\u00a0Buyer may accept or rej"
    "ect any proposed Transaction for any reason or no reason in Buyer\\u2019s sole discretion. \"], [\""
    "c\", \"Referred Seller.\", \"\\u00a0A Seller shall qualify as a Referred Seller if RMS or an existing"
    " Referred Seller (each a \\u201cReferring Party\\u201d) makes a Referral to such Seller during the"
    " term of this Agreement. \"], [\"s1\", \"A \\u201cReferral\\u201d shall be deemed to have occurred if:"
    "\"], [\"s2\", \"Referring Party introduces such Seller to the Buyer, a Buyer\\u2019s affiliate, their"
    " employees, officers, agents, representatives, or any person otherwise acting to facilitate the "
    "Transaction on behalf of the Buyer (\\u201cBuyer\\u00a0Representatives\\u201d); or \"], [\"s2\", \"Refe"
    "rring Party makes Buyer or Buyer Representatives aware of Seller\\u2019s interest in the sale of "
    "Seller\\u2019s Securities.\"], [\"s1\", \"A Referred Seller shall also include any affiliate, subsidi"
    "ary, related parties under common control of such Referred Seller, and entities owned or control"
    "led by such Referred Seller.\"], [\"s1\", \"A Seller shall be disqualified as a Referred Seller if, "
    "within two business days of a Referral, the Buyer can provide substantive, written evidence that"
    " the Buyer had, previously and independently from the Referring Party efforts, been in mutual co"
    "mmunications with the Seller regarding a Transaction for the Securities during the six-month per"
    "iod prior to the Referral.\"], [\"c\", \"Success Fees.\", \"\\u00a0If a Referred Seller completes a Tra"
    "nsaction within the \\u201cTail Period\\u201d, as defined in Schedule A\\u00a0to this Agreement, RM"
    "S shall be paid a commission based upon the Transaction Value (\\u201cSuccess Fee\\u201d). The Suc"
    "cess Fee shall be paid to RMS as follows:\"], [\"s1\", \"The Success Fee shall be calculated as defi"
    "ned in Schedule A.\"], [\"s1\", \"The Success Fee shall be paid via wire transfer, in U.S. Dollars, "
    "and in immediately available funds to the accounts and in the amounts set forth in the wire tran"
    "sfer instructions provided by RMS.\"], [\"s1\", \"The Success Fee shall become due and payable concu"
    "rrently with payment of the Transaction Value by the Buyer to the Seller, whether Transaction Va"
    "lue is paid via the closing of escrow or via direct payment to the Seller.\"], [\"s1\", \"In the eve"
    "nt escrow is used to complete a Transaction, the Buyer agrees, at the sole discretion and direct"
    "ion of RMS, to include as irrevocable conditions to closing of escrow, the payment of the applic"
    "able Success Fee due.\"], [\"c\", \"Late Fees.\", \"\\u00a0For each thirty-days an outstanding balance "
    "remains due and payable by Buyer, RMS shall assess a late fee equal to the lesser of: (i) of fiv"
    "e percent [5%]; or (ii) the maximum percentage allowable by applicable law (\\u201cLate Fee\\u201d"
    "). \\u00a0The Late Fee shall be assessed on the total outstanding balance due and payable at each"
    " thirty-day interval, including Late Fees previously assessed.\"], [\"c\", \"Non-Circumvention.\", \" "
    "Buyer shall not circumvent, avoid, bypass or obviate RMS, directly or indirectly, to avoid payme"
    "nt of fees, commission or any other form of compensation to RMS. Furthermore, Buyer shall not, a"
    "nd Buyer shall not direct its affiliates, employees, directors, officers, partners, or advisors "
    "to contact, solicit, or deal with any Referred Seller, directly or indirectly, in connection wit"
    "h the purchase or sale of securities without express written authorization of RMS. During the Ta"
    "il Period, Buyer shall not directly purchase, acquire, or otherwise enter into a Transaction for"
    " any securities with a Referred Seller without RMS's prior written consent, or without ensuring "
    "RMS is paid its applicable Success Fee upon the completion of such Transaction.\"], [\"c\", \"Termin"
    "ation.\", \"\\u00a0This Agreement may be terminated by either Party upon delivery of written notice"
    " at least thirty days prior to termination. Upon termination, RMS shall immediately cease solici"
    "tation of Referrals on behalf of Buyer. Buyer\\u2019s obligation to pay any outstanding balance s"
    "hall survive termination. Buyer\\u2019s obligation to pay Success Fees shall survive when: (i) th"
    "e Referral occurred prior to termination; and (ii) the Transaction is initiated before the end o"
    "f the Tail Period.\"], [\"h\", \"REPRESENTATIONS, WARRANTIES, AND COVENANTS\"], [\"c\", \"\", \"Mutual rep"
    "resentations, warranties, and covenants of the Parties:\"], [\"s1\", \"This Agreement has been duly "
    "authorized, executed, and delivered of its behalf, and is its legal, valid and binding agreement"
    ", enforceable against it in accordance with its terms.\"], [\"s1\", \"Party is either a natural pers"
    "on, or an entity that is duly organized, validly existing and in good standing under the laws of"
    " the state of its jurisdiction of formation or organization and has full power and authority to "
    "execute, deliver and perform its obligations under this Agreement. The Party\\u2019s performance "
    "of its obligations under this Agreement will not conflict with, violate the terms of or constitu"
    "te a default under: (A) its articles of incorporation, by-laws or similar governing documents; ("
    "B) any other agreement or instrument to which it is a party or by which it is bound or to which "
    "any of its property or assets are subject; or (C) any order, rule, law, regulation, or other leg"
    "al requirement applicable to it or its property or assets.\"], [\"c\", \"\", \"Buyer represents, warra"
    "nts to, and covenants with RMS as follows:\"], [\"s1\", \"Buyer has not entered into the Agreement a"
    "s a result of any general solicitation by RMS.\\u00a0\"], [\"s1\", \"Buyer has entered into this Agre"
    "ement in its sole discretion, and not as a result of any influence, advice, call to action, or r"
    "ecommendation made by RMS or is representatives.\"], [\"s1\", \"Buyer is a sophisticated investor no"
    "t in need of public protections afforded by SEC regulations. The Buyer has the financial ability"
    " to bear the risk of loss in a contemplated Transaction or has extensive business experience wit"
    "h access to the necessary information to make an informed decision regarding a contemplated Tran"
    "saction. The Buyer is an \\u201caccredited investor\\u201d as defined under Rule 501(d) of the Sec"
    "urities Act.\"], [\"s1\", \"Buyer agrees to provide RMS with the Buyer\\u2019s identity verification "
    "information and Transaction documentation RMS reasonably deems required to maintain compliance w"
    "ith applicable laws and regulations. \"], [\"s1\", \"Buyer has read and understands the required bro"
    "ker-dealer disclosures located at www.rainmakersecurities.com/disclosures, including but not lim"
    "ited to, the Relationship Summary.\"], [\"c\", \"\", \"RMS represents, warrants to, and covenants with"
    " Buyer as follows:\"], [\"s1\", \"RMS agrees to maintain any and all registrations and licenses unde"
    "r the relevant laws applicable to its operations in connection with the services performed pursu"
    "ant to this Agreement including registration as a broker-dealer with the SEC, FINRA, and every s"
    "tate or territory of the United States of America where such registration is required to complet"
    "e a Transaction.\"], [\"s1\", \"RMS shall be responsible for supervising the activities of its assoc"
    "iated persons that are conducted in furtherance of this Agreement to ensure compliance with appl"
    "icable law.\"], [\"h\", \"MISCELLANEOUS TERMS AND CONDITIONS\"], [\"c\", \"Entire Agreement.\", \"\\u00a0Th"
    "is Agreement, together with any Schedules, constitutes the entire agreement between the Parties "
    "and supersedes, voids, and rescinds any and all prior oral or written agreements between RMS and"
    " Buyer on the subject matter related to this Agreement, except with respect to any Non-Circumven"
    "tion or Non-Disclosure Agreements executed between the Parties. This Agreement may not be amende"
    "d nor modified except by the mutual written consent of the Parties.\"], [\"c\", \"Counterparts.\", \"\\"
    "u00a0This Agreement may be executed in counterparts, each of which shall be deemed an original b"
    "ut all of which shall constitute one and the same instrument.\"], [\"c\", \"Severability.\", \"\\u00a0A"
    "ny provision of this Agreement that is prohibited or unenforceable in any jurisdiction shall, as"
    " to such jurisdiction, be ineffective to the extent of such prohibition or unenforceability with"
    "out invalidating the remaining provisions, and any such prohibition or unenforceability in any j"
    "urisdiction shall not invalidate or render unenforceable such provision in any other jurisdictio"
    "n.\"], [\"c\", \"Headings:\", \" \\u00a0Headings of this Agreement are for the convenience of the Parti"
    "es only, and are not intended to be a part of or to affect the meanings or interpretation of thi"
    "s Agreement.\"], [\"c\", \"Assignment and Successors.\", \"\\u00a0This Agreement shall be binding upon,"
    " and shall inure to the benefit of the Parties hereto, their successors, permitted assigns and l"
    "egal representatives as well as subsidiaries, affiliates, joint-ventures, heirs and any other re"
    "lated parties or entities. This Agreement shall not be assigned by the Parties without prior mut"
    "ual written consent.\"], [\"c\", \"Waiver.\", \"\\u00a0 The waiver by a Party of a breach of any provis"
    "ion of this Agreement shall not operate nor be construed as a waiver of any subsequent breach by"
    " a Party. The failure of a Party to insist upon strict adherence to any provision of this Agreem"
    "ent shall not constitute a waiver or thereafter deprive such Party of the right to insist upon a"
    " strict adherence.\"], [\"c\", \"Privacy Notice.\", \"\\u00a0To help the government fight the funding o"
    "f terrorism and money laundering activities, federal law requires all financial institutions to "
    "obtain, verify, and record information about the identities of individuals and institutions with"
    " which it does business. Therefore, RMS will verify the information provided by the counterparty"
    " of this Agreement through publicly available private and government sources.\"], [\"c\", \"Notice t"
    "o the Parties.\", \"\\u00a0The \\u201cwritten notice\\u201d requirement of this Agreement shall be sa"
    "tisfied if received at the Party\\u2019s address or email specified on the signature page, or, if"
    " to Buyer, (i) via email sent to Buyer\\u2019s account last known to RMS, or (ii) by letter sent "
    "via post or courier to the Buyer\\u2019s address last known to RMS.\"], [\"c\", \"Relationship of Par"
    "ties.\", \"\\u00a0Neither Party may legally bind the other Party, unless expressly authorized in wr"
    "iting. No joint venture, partnership, employment, or any other relationship, including any clear"
    "ing arrangement, is intended, accomplished or embodied in this Agreement. Both Parties may have "
    "similar dealings with other parties and their relationship is only exclusive to the extent speci"
    "fied in the Agreement.\"], [\"c\", \"Indemnification.\", \"\\u00a0Each Party agrees to indemnify, defen"
    "d and hold harmless the other Party (including its respective affiliates, directors, officers, e"
    "mployees, successors and agents) from and against any and all losses, claims, expenses, damages "
    "and liabilities (including reasonable attorney fees and disbursements and other expenses for inv"
    "estigating or defending any actions or threatened actions) to which such other Party may become "
    "subject based upon, arising out of or otherwise in respect of the other Party\\u2019s willful mis"
    "conduct, gross negligence, fraudulent or criminal act, or a material breach by the Party of the "
    "provisions of this Agreement. This indemnity is in addition to any liability that each Party may"
    " otherwise have to the other and shall survive termination of this Agreement. Parties agree to n"
    "otify each other, in writing, within fifteen days of any claim asserted or any legal action comm"
    "enced against it in connection with this Agreement. The indemnifying Party shall not be liable t"
    "o indemnify the other Party for an aggregate amount of losses in excess of the total value of th"
    "e Success Fees which were paid or made payable under the Agreement.\"], [\"c\", \"Governing Law and "
    "Jurisdiction.\", \" This Agreement shall be construed and governed in accordance with the laws of "
    "the State of Delaware, without reference to its conflict of laws provisions. The Parties submit "
    "to the exclusive jurisdiction of the state or federal courts located in the State of Delaware (\\"
    "u201cCourts\\u201d).\"], [\"c\", \"Arbitration.\", \" By signing this Agreement, the Buyer acknowledges"
    " and agrees to the following:\"], [\"s1\", \"All Parties to this Agreement are giving up the right t"
    "o sue each other in court, including the right to a trial by jury, except as provided by the rul"
    "es of the arbitration forum in which a claim is filed.\"], [\"s1\", \"Arbitration awards are general"
    "ly final and binding; a Party's ability to have a court reverse or modify an arbitration award i"
    "s very limited.\"], [\"s1\", \"The ability of the Parties to obtain documents, witness statements an"
    "d other discovery is generally more limited in arbitration than in court proceedings.\"], [\"s1\", "
    "\"The arbitrators do not have to explain the reason(s) for their award unless, in an eligible cas"
    "e, a joint request for an explained decision has been submitted by all Parties to the panel at l"
    "east 20 days prior to the first scheduled hearing date.\"], [\"s1\", \"The panel of arbitrators may "
    "include a minority of arbitrators who were or are affiliated with the securities industry.\"], [\""
    "s1\", \"The rules of some arbitration forums may impose time limits for bringing a claim in arbitr"
    "ation. In some cases, a claim that is ineligible for arbitration may be brought in court.\"], [\"s"
    "1\", \"The rules of the arbitration forum in which the claim is filed, and any amendments thereto,"
    " shall be incorporated into this agreement.\"], [\"s1\", \"No person shall bring a putative or certi"
    "fied class action to arbitration, nor seek to enforce any pre-dispute arbitration agreement agai"
    "nst any person who has initiated in court a putative class action; or who is a member of a putat"
    "ive class who has not opted out of the class with respect to any claims encompassed by the putat"
    "ive class action until: (i) the class certification is denied; or (ii) the class is decertified;"
    " or (iii) the customer is excluded from the class by the court. Such forbearance to enforce an a"
    "greement to arbitrate shall not constitute a waiver of any rights under this agreement except to"
    " the extent stated herein.\"], [\"s1\", \"Any dispute, claim or controversy arising out of or relati"
    "ng to this Agreement or the breach, termination, enforcement, interpretation or validity of the "
    "Agreement, including the determination of the scope or applicability of this agreement to arbitr"
    "ate, whether brought against a Party or its respective affiliates, employees or agents (\\u201cDi"
    "spute\\u201d), shall be submitted to FINRA arbitration and conducted in accordance with the FINRA"
    " Code of Arbitration Procedure for Customer Disputes (\\u201cFINRA Code\\u201d). In the event the "
    "FINRA Director of Arbitration finds that such Dispute is ineligible for arbitration under the FI"
    "NRA Code, then the Dispute shall be administered by JAMS pursuant to its Comprehensive Arbitrati"
    "on Rules and Procedures and in accordance with the Expedited Procedures in those Rules (\\u201cJA"
    "MS Rules\\u201d). Arbitration under the JAMS Rules shall be held in Los Angeles, California befor"
    "e three arbitrators. Judgment on the award shall be final and may be entered in any court having"
    " jurisdiction. This clause shall not preclude either Party from seeking provisional remedies in "
    "aid of arbitration from the Courts. \"], [\"s1\", \"If arbitration of the Dispute pursuant to the FI"
    "NRA Code and JAMS Rules is not permitted by law, then any action, claim, suit, or proceeding (\\u"
    "201cProceeding\\u201d) concerning the Dispute may be commenced exclusively in the Courts. Each Pa"
    "rty submits to the exclusive jurisdiction of the Courts and waives the right to assert in any Pr"
    "oceeding, any claim that it is not personally subject to the jurisdiction of the Courts, or that"
    " such Proceeding has been commenced in an improper or inconvenient forum. \"], [\"sigfollow\", \"[SI"
    "GNATURE PAGE TO FOLLOW]\"], [\"h\", \"SIGNATURES AND ACKNOWLEDGEMENTS\"], [\"sigp\", \"This Agreement co"
    "ntains a pre-dispute arbitration clause. By executing this Agreement, the Parties agree to submi"
    "t to arbitration in the event of a dispute.\"]], \"securities_full\": \"The securities of the Issuer"
    ", or the interests in an entity holding the securities of the Issuer, whether directly or indire"
    "ctly.\", \"securities_sched\": \"The securities of the Issuer.\", \"sell_version\": \"v20251125\", \"buy_v"
    "ersion\": \"\"}"
)

# Plain JS, deliberately NOT inside an f-string: braces are literal here.
ENG_JS = r"""
(function () {
  var D = JSON.parse(document.getElementById('eng-data').textContent);
  var C = JSON.parse(document.getElementById('eng-const').textContent);
  var OWN = '__own';
  var $ = function (id) { return document.getElementById(id); };
  var st = { deal: null, person: null, issuer: null, party: null, drive: null,
             typeTouched: false, ptypeTouched: false, dirty: {} };
  var seq = { party: 0, drive: 0, people: 0 };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function api(params, cb) {
    var qs = Object.keys(params).map(function (k) {
      return encodeURIComponent(k) + '=' + encodeURIComponent(params[k] || '');
    }).join('&');
    fetch('?view=engagement&' + qs, { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (j) { cb(null, j); })
      .catch(function (e) { cb(e.message || String(e)); });
  }

  // ── Date: today in America/New_York, "October 2nd, 2026" ──
  function ordinal(n) {
    var m = n % 100;
    if (m >= 11 && m <= 13) return n + 'th';
    return n + ({ 1: 'st', 2: 'nd', 3: 'rd' }[n % 10] || 'th');
  }
  function todayNY() {
    var parts = {};
    new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', year: 'numeric',
      month: 'long', day: 'numeric' }).formatToParts(new Date())
      .forEach(function (p) { parts[p.type] = p.value; });
    return parts.month + ' ' + ordinal(parseInt(parts.day, 10)) + ', ' + parts.year;
  }

  // ── Type-ahead (source may call back again later with async results) ──
  function typeahead(input, list, source, onPick) {
    var items = [], active = -1, gen = 0;
    function render() {
      list.innerHTML = items.map(function (it, i) {
        return '<div class="ta-item' + (i === active ? ' active' : '') + '" data-i="' + i + '">' +
          (it.tag ? '<span class="ta-tag">' + esc(it.tag) + '</span>' : '') + esc(it.label) + '</div>';
      }).join('');
      list.style.display = items.length ? 'block' : 'none';
    }
    function search() {
      var q = input.value.trim().toLowerCase(), my = ++gen;
      if (!q) { items = []; render(); return; }
      source(q.split(/\s+/), q, function (res) {
        if (my !== gen) return;
        items = res.slice(0, 50);
        active = items.length ? Math.max(0, Math.min(active, items.length - 1)) : -1;
        render();
      });
    }
    function pick(i) {
      var it = items[i];
      if (!it) return;
      input.value = it.label;
      gen++; items = []; render();
      onPick(it);
    }
    input.addEventListener('input', function () { active = 0; search(); });
    input.addEventListener('focus', function () { if (input.value) search(); });
    input.addEventListener('keydown', function (e) {
      if (!items.length) return;
      if (e.key === 'ArrowDown') { active = Math.min(active + 1, items.length - 1); render(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { active = Math.max(active - 1, 0); render(); e.preventDefault(); }
      else if (e.key === 'Enter') { pick(active); e.preventDefault(); }
      else if (e.key === 'Escape') { items = []; render(); }
    });
    list.addEventListener('mousedown', function (e) {
      var el = e.target.closest('.ta-item');
      if (el) { pick(parseInt(el.getAttribute('data-i'), 10)); e.preventDefault(); }
    });
    input.addEventListener('blur', function () { setTimeout(function () { items = []; render(); }, 150); });
  }
  function matchAll(hay, toks) {
    for (var i = 0; i < toks.length; i++) if (hay.indexOf(toks[i]) < 0) return false;
    return true;
  }

  function dealLabel(d) {
    var who = '—';
    if (d.pp.length) {
      var p = d.pp[0];
      who = p[1] + (p[2] ? ' / ' + p[2] : '');
      if (d.pp.length > 1) who += ' +' + (d.pp.length - 1);
    }
    return [d.co || '(no company)', d.side || '?', who, d.size || 'size n/a'].join(' · ');
  }
  var dealIndex = D.deals.map(function (d) {
    var label = dealLabel(d);
    return { kind: 'deal', tag: 'Deal', label: label, ref: d,
      hay: (label + ' ' + d.pp.map(function (p) { return p[1] + ' ' + p[2]; }).join(' ')).toLowerCase() };
  });
  var companyIndex = D.companies.map(function (c) {
    return { label: c[1], ref: { id: c[0], name: c[1], legal: c[2] }, hay: c[1].toLowerCase() };
  });
  var peopleTimer = null;

  // ── Select helpers ──
  // opts: [{v, label, group, src}] ; groups become <optgroup>s in first-seen order.
  function fillSelect(sel, opts, pre, withOwn) {
    var seen = {}, html = '', groups = [], byGroup = {}, srcs = {};
    opts.forEach(function (o) {
      var key = (o.v || '').toLowerCase();
      if (!o.v || seen[key]) return;
      seen[key] = o.v;
      srcs[o.v] = o.src || '';
      var g = o.group || '';
      if (!byGroup[g]) { byGroup[g] = []; groups.push(g); }
      byGroup[g].push('<option value="' + esc(o.v) + '">' + esc(o.label || o.v) + '</option>');
    });
    groups.forEach(function (g) {
      html += g ? '<optgroup label="' + esc(g) + '">' + byGroup[g].join('') + '</optgroup>' : byGroup[g].join('');
    });
    if (withOwn !== false) html += '<option value="' + OWN + '">Type your own…</option>';
    sel.innerHTML = html;
    sel._srcs = srcs;
    var hit = pre && seen[pre.toLowerCase()];
    if (hit) sel.value = hit;
    else if (!Object.keys(seen).length && withOwn !== false) sel.value = OWN;
    syncOwn(sel);
  }
  function syncOwn(sel) {
    var own = $(sel.id + '-own');
    if (own) own.style.display = sel.value === OWN ? 'block' : 'none';
    var note = $(sel.id + '-src');
    if (note) note.textContent = (sel._srcs && sel._srcs[sel.value]) ? 'Source: ' + sel._srcs[sel.value] : '';
  }
  function val(id) {
    var sel = $(id);
    if (sel.value === OWN) return ($(id + '-own').value || '').trim();
    return sel.value;
  }

  // ── Type (side + full / schedule) ──
  function typeVal() { return document.querySelector('input[name="f-type"]:checked').value; }
  function side() { return typeVal().indexOf('buy') === 0 ? 'buy' : 'sell'; }
  function isFull() { return /_full$/.test(typeVal()); }
  function setType(v) { var r = document.querySelector('input[name="f-type"][value="' + v + '"]'); if (r) r.checked = true; }

  // ── Party ──
  function partyPool() { return st.deal ? st.deal.pp : (st.person ? [st.person] : []); }
  function partyInfo() {
    var v = $('f-party').value || '', person = null, coId = '', coName = '';
    if (v.indexOf('p:') === 0) {
      var pid = v.slice(2);
      partyPool().forEach(function (p) { if (p[0] === pid) person = p; });
      if (person) { coName = person[2]; coId = person[3]; }
    } else if (v.indexOf('c:') === 0) {
      var bar = v.indexOf('|');
      coId = v.slice(2, bar); coName = v.slice(bar + 1);
    }
    return { person: person, coId: coId, coName: coName };
  }
  function refreshPartyOptions() {
    var opts = [];
    partyPool().forEach(function (p) { opts.push({ v: 'p:' + p[0], label: p[1] + (p[2] ? ' (' + p[2] + ')' : '') }); });
    partyPool().forEach(function (p) { if (p[2]) opts.push({ v: 'c:' + (p[3] || '') + '|' + p[2], label: p[2] + ' (company)' }); });
    fillSelect($('f-party'), opts, opts.length ? opts[0].v : '', false);
    $('f-party').disabled = !opts.length;
  }
  function onPartyChange() {
    var pi = partyInfo();
    st.party = { info: pi, facts: null };
    st.drive = null;
    st.ptypeTouched = false;
    st.dirty = {};
    $('f-title').value = 'Authorized Signatory';
    $('f-phone').value = '';
    $('drive-note').textContent = '';
    applyPartyType();
    refreshEntityNames(); refreshSigner(); refreshInvestorLevel();
    preview();
    if (!pi.person && !pi.coName) return;
    var my = ++seq.party;
    api({ api: 'party', pid: pi.person ? pi.person[0] : '', co_id: pi.coId, co_name: pi.coName }, function (err, j) {
      if (my !== seq.party) return;
      st.party.facts = err ? null : j;
      if (err) $('drive-note').textContent = 'Pipeline lookup failed: ' + err;
      applyPartyType();
      fillContact();
      refreshEntityNames(); refreshSigner(); refreshInvestorLevel();
      preview();
    });
    var myd = ++seq.drive;
    $('drive-note').textContent = 'Looking up Drive…';
    api({ api: 'drive', person: pi.person ? pi.person[1] : '', company: pi.coName }, function (err, j) {
      if (myd !== seq.drive) return;
      if (err || !j || !j.ok) {
        st.drive = null;
        $('drive-note').textContent = 'Drive lookup unavailable: ' + (err || (j && j.error) || 'unknown error');
      } else {
        st.drive = j;
        var bits = [];
        bits.push(j.folders.length ? 'Drive: ' + j.folders.map(function (f) { return f.name; }).join(', ') : 'Drive: no client folder found');
        if (j.cef) bits.push('CEF: ' + j.cef.file);
        if (j.cef_note) bits.push(j.cef_note);
        if (j.signed.sell.length) bits.push('signed sell-side agreement on file');
        if (j.signed.buy.length) bits.push('signed buy-side agreement on file');
        $('drive-note').textContent = bits.join(' · ');
        if (!st.typeTouched && j.signed[side()].length) setType(side() + '_sched');
      }
      applyPartyType();
      fillContact();
      refreshEntityNames();
      preview();
    });
  }
  function partyPerson() {
    var f = st.party && st.party.facts;
    return (f && f.person) || null;
  }
  function applyPartyType() {
    if (st.ptypeTouched) return syncPartyTypeUI();
    var pi = st.party ? st.party.info : {}, pp = partyPerson(), t;
    if (!pi.person && pi.coName) t = 'entity';
    else if (pp && pp.tt) t = pp.tt;
    else t = (pi.person && !pi.person[2]) ? 'individual' : (pi.person ? 'entity' : 'individual');
    document.querySelector('input[name="f-ptype"][value="' + t + '"]').checked = true;
    syncPartyTypeUI();
  }
  function ptype() { return document.querySelector('input[name="f-ptype"]:checked').value; }
  function syncPartyTypeUI() {
    var ent = ptype() === 'entity';
    $('row-entity').style.display = ent ? '' : 'none';
    $('row-title').style.display = ent ? '' : 'none';
    var pp = partyPerson();
    $('ptype-note').textContent = pp && pp.tt ? 'Transactor Type: ' + (pp.tt === 'individual' ? 'individual' : 'entity') : '';
  }
  function fillContact() {
    var cef = st.drive && st.drive.cef, pp = partyPerson();
    if (!st.dirty.phone) $('f-phone').value = (cef && cef.phone) || (pp && pp.phone) || '';
  }
  function refreshEntityNames() {
    var opts = [], pi = st.party ? st.party.info : {}, f = st.party && st.party.facts;
    var cef = st.drive && st.drive.cef;
    if (cef && cef.kind === 'entity' && cef.name)
      opts.push({ v: cef.name, group: 'Client Engagement Form', src: 'CEF “Name of Entity Client” (' + cef.file + ')' });
    (f ? f.legal : []).forEach(function (l) { opts.push({ v: l[0], group: 'Pipeline deals', src: l[1] }); });
    if (st.deal) {
      if (st.deal.sl) opts.push({ v: st.deal.sl, group: 'Pipeline deals', src: 'Seller Legal Name · deal #' + st.deal.id });
      if (st.deal.bl) opts.push({ v: st.deal.bl, group: 'Pipeline deals', src: 'Buyer Legal Name · deal #' + st.deal.id });
    }
    (st.drive ? st.drive.entity_names : []).forEach(function (n) { opts.push({ v: n, group: 'Drive agreement files', src: 'Agreement file name in Drive' }); });
    if (pi.coName) opts.push({ v: pi.coName, group: 'Pipeline company', src: 'Pipeline company name' });
    // Keep the user's own pick across async refreshes; otherwise preselect the first candidate.
    var keep = st.dirty.entity ? $('f-entity').value : '';
    fillSelect($('f-entity'), opts, (keep && keep !== OWN) ? keep : (opts[0] && opts[0].v));
    if (keep === OWN) { $('f-entity').value = OWN; syncOwn($('f-entity')); }
  }
  function refreshSigner() {
    var opts = [], pi = st.party ? st.party.info : {}, f = st.party && st.party.facts;
    (f ? f.team : []).forEach(function (t) { opts.push({ v: t[1], label: t[1] + (t[2] ? ' — ' + t[2] : '') }); });
    partyPool().forEach(function (p) { opts.push({ v: p[1] }); });
    var pre = pi.person ? pi.person[1] : (opts[0] && opts[0].v);
    fillSelect($('f-signer'), opts, pre);
  }
  function refreshInvestorLevel() {
    var pp = partyPerson(), b = $('il-badge');
    var show = side() === 'buy' && pp && pp.il;
    b.style.display = show ? 'inline-block' : 'none';
    b.innerHTML = show ? '<span>Investor level</span> ' + esc(pp.il) : '';
    $('row-platinum').style.display = side() === 'buy' ? '' : 'none';
  }
  function refreshIssuerLegal() {
    var iss = st.issuer, opts = [];
    if (iss && iss.legal) opts.push({ v: iss.legal });
    if (iss && iss.name) opts.push({ v: iss.name, label: iss.name + '  — Pipeline name' });
    fillSelect($('f-issuer-legal'), opts, iss ? (iss.legal || iss.name) : '');
    $('issuer-legal-note').style.display = (iss && !iss.legal) ? 'block' : 'none';
  }
  function refreshStructure(list) {
    $('f-structure').value = list && list.length ? list[0] : '';
    var extra = (list || []).slice(1);
    $('structure-note').textContent = extra.length ? 'Deal also lists: ' + extra.join(', ') : '';
  }

  function onStart(it) {
    if (it.kind === 'deal') {
      st.deal = it.ref; st.person = null;
      st.issuer = { id: it.ref.coId, name: it.ref.co, legal: it.ref.il };
      $('f-issuer').value = it.ref.co;
      refreshStructure(it.ref.st);
      $('start-picked').textContent = 'Deal #' + it.ref.id + (it.ref.stage ? ' · ' + it.ref.stage : '');
      if (!st.typeTouched && it.ref.side) setType((it.ref.side === 'Buy' ? 'buy' : 'sell') + '_full');
    } else {
      st.person = it.ref; st.deal = null; st.issuer = null;
      $('f-issuer').value = '';
      refreshStructure([]);
      $('start-picked').textContent = 'Person #' + it.ref[0];
    }
    refreshPartyOptions();
    refreshIssuerLegal();
    onPartyChange();
  }

  typeahead($('f-start'), $('f-start-list'), function (toks, q, cb) {
    var deals = dealIndex.filter(function (it) { return matchAll(it.hay, toks); }).slice(0, 25);
    cb(deals);
    clearTimeout(peopleTimer);
    var my = ++seq.people;
    peopleTimer = setTimeout(function () {
      api({ api: 'people', q: q }, function (err, j) {
        if (my !== seq.people || err) return;
        cb(deals.concat(j.people.map(function (p) {
          return { kind: 'person', tag: 'Person', label: p[1] + (p[2] ? ' · ' + p[2] : ''), ref: p };
        })));
      });
    }, 180);
  }, onStart);
  typeahead($('f-issuer'), $('f-issuer-list'), function (toks, q, cb) {
    cb(companyIndex.filter(function (it) { return matchAll(it.hay, toks); }));
  }, function (it) { st.issuer = it.ref; refreshIssuerLegal(); preview(); });

  // ── Fees ──
  function setFees(vals) { for (var i = 0; i < 4; i++) $('f-fee-' + i).value = vals[i]; }
  function feeLine(i) {
    var p = $('f-fee-' + i).value.trim();
    return C.fee_templates[i].replace('{p}', p || '[%]');
  }
  function money(s) {
    var t = String(s || '').replace(/[$,\s]/g, '');
    if (!t || isNaN(Number(t))) return '';
    var parts = t.split('.');
    return '$' + parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',') + (parts[1] ? '.' + parts[1] : '') + '.';
  }

  // ── Preview ──
  function hl(s, fallback) {
    return s ? '<span class="pv-val">' + esc(s) + '</span>'
             : '<span class="pv-missing">' + esc(fallback) + '</span>';
  }
  function preview() {
    var full = isFull(), sd = side(), Party = sd === 'buy' ? 'Buyer' : 'Seller';
    $('row-txn').style.display = full ? 'none' : '';
    refreshInvestorLevel();
    var date = $('f-date').value.trim();
    var signer = val('f-signer'), entity = val('f-entity'), title = $('f-title').value.trim();
    var phone = $('f-phone').value.trim();
    var issuer = val('f-issuer-legal');
    var structure = $('f-structure').value;
    var tail = $('f-tail').value.trim();
    var txn = full ? '1' : $('f-txn').value.trim();
    var ent = ptype() === 'entity';
    var out = '';
    if (full) {
      out += '<div class="pv-sec"><div class="pv-h">Agreement</div><p>This ' + (sd === 'buy' ? 'Buy' : 'Sell') +
        '-Side Agent Agreement (“<i>Agreement</i>”) is made and entered into as of ' + hl(date, '[date]') +
        ' (“<i>Effective Date</i>”), by and between Rainmaker Securities, LLC, a FINRA registered broker-dealer ' +
        'with CRD# 132995 (“<i>RMS</i>”) and “<i>' + Party + '</i>” with a name and address as specified on the ' +
        'signature page to this Agreement.</p></div>';
      // Address lines stay blank, as on the template's signature page.
      var addr = '<div class="pv-kv"><span></span><div><span class="uline wide"></span><div class="pv-cap">Address</div></div></div>' +
        '<div class="pv-kv"><span></span><div><span class="uline wide"></span><div class="pv-cap">City/State/Zip</div></div></div>' +
        '<div class="pv-kv"><span>Phone:</span><div>' + hl(phone, '[phone]') + '</div></div>';
      var sig = ent
        ? '<div class="pv-ent">' + hl((entity || '').toUpperCase(), '[ENTITY NAME]') + '</div>' +
          '<div class="pv-kv"><span>By:</span><div><span class="uline wide"></span></div></div>' +
          '<div class="pv-kv"><span>Name:</span><div>' + hl(signer, '[signer]') + '</div></div>' +
          '<div class="pv-kv"><span>Title:</span><div>' + hl(title, '[title]') + '</div></div>' + addr
        : '<div class="pv-kv"><span></span><div><span class="uline wide"></span> (Signature)</div></div>' +
          '<div class="pv-kv"><span>Name:</span><div>' + hl(signer, '[signer]') + '</div></div>' + addr;
      out += '<div class="pv-sec"><div class="pv-h">Signature block</div><div class="pv-sig">' + sig +
        '<div class="pv-rms"><b>RAINMAKER SECURITIES, LLC</b><br><b>By: Glen Anderson, President</b><br>' +
        '382 NE 191st St. #86647 Miami, FL 33179-3899</div></div></div>';
    }
    var securities = full
      ? 'The securities of the Issuer, or the interests in an entity holding the securities of the Issuer, whether directly or indirectly.'
      : 'The securities of the Issuer.';
    var fees = '';
    for (var i = 0; i < 4; i++) fees += '<li>' + hl(feeLine(i)) + '</li>';
    var minRow = $('f-min-on').checked
      ? '<tr><th>Minimum Commission.</th><td>' + hl(money($('f-min-amt').value), '[amount]') + '</td></tr>' : '';
    var scope = $('f-scope-on').checked
      ? '<tr><th>Scope of Coverage.</th><td>For the avoidance of doubt (see Section ' + C.noncirc_section[sd] +
        ', Non-Circumvention), the scope of this Agreement and any Success Fee obligations extend to any and all ' +
        'transactions, securities sales, or fund allocations completed between ' +
        (sd === 'buy' ? 'Buyer and any Referred Seller' : 'Seller and any Referred Buyer') +
        ' during the Tail Period, regardless of whether the specific Issuer or security was listed on Schedule A ' +
        'at the time of Referral.</td></tr>' : '';
    out += '<div class="pv-sec"><div class="pv-h">Schedule A</div>' +
      '<div class="pv-txn">TRANSACTION ' + hl(txn, '[#]') + '</div><table class="pv-tbl">' +
      '<tr><th>Issuer.</th><td>' + hl(issuer, '[issuer]') + '</td></tr>' +
      '<tr><th>Securities.</th><td>' + esc(securities) + '</td></tr>' +
      '<tr><th>Success Fee.</th><td>The Success Fee shall be calculated as:<ul>' + fees + '</ul></td></tr>' +
      minRow +
      scope +
      '<tr><th>Tail Period.</th><td>The ' + hl(tail, '[N]') + ' month period after the Referral.</td></tr>' +
      '<tr><th>Anticipated Structure.</th><td>' + hl(structure, '[structure]') + '</td></tr>' +
      '<tr><th>Initials.</th><td><table class="pv-init">' +
        '<tr><td>' + Party + ':</td><td><span class="uline"></span></td><td>Date:</td><td><span class="uline"></span></td></tr>' +
        '<tr><td>RMS:</td><td><span class="uline"></span></td><td>Date:</td><td><span class="uline"></span></td></tr>' +
      '</table></td></tr></table></div>';
    $('preview').innerHTML = out;
  }

  // ── Print version: the complete document in a new tab, built from the template
  // text (verbatim, ENG_PRINT_TEMPLATES) plus the current form values. Client-side only.
  var PT = JSON.parse(document.getElementById('eng-print').textContent);
  function roman(n) {
    return ['', 'i', 'ii', 'iii', 'iv', 'v', 'vi', 'vii', 'viii', 'ix', 'x', 'xi', 'xii'][n] || String(n);
  }
  function letter(n) { return String.fromCharCode(96 + n); }
  function blank(v, wide) {
    return v ? esc(v) : '<span class="ul' + (wide ? ' wide' : '') + '"></span>';
  }
  function printDoc() {
    var full = isFull(), sd = side(), Party = sd === 'buy' ? 'Buyer' : 'Seller';
    var T = PT[sd], ent = ptype() === 'entity';
    var date = $('f-date').value.trim(), signer = val('f-signer'), entity = val('f-entity');
    var title = $('f-title').value.trim();
    var phone = $('f-phone').value.trim(), issuer = val('f-issuer-legal'), structure = $('f-structure').value;
    var tail = $('f-tail').value.trim(), txn = full ? '1' : $('f-txn').value.trim();
    var h = [], sec = 0, clause = 0, sub1 = 0, sub2 = 0, rec = 0, firstP = true;
    var top = T.filter(function (b) { return b[0] === 'top'; })[0][1].split(/[\s ]{2,}/);
    var topHtml = '<div class="top"><span>' + esc(top[0]) + '</span><span>' + esc(top[top.length - 1]) + '</span></div>';
    if (full) {
      T.forEach(function (b) {
        var k = b[0];
        if (k === 'top') { h.push(topHtml); return; }
        if (k === 'title') { h.push('<div class="title">' + esc(b[1]) + '</div>'); return; }
        if (k === 'h') {
          sec++; clause = 0; rec = 0;
          if (/^SIGNATURES/.test(b[1])) {
            h.push('<section class="sigpage"><h2>' + sec + '. ' + esc(b[1]) + '</h2>');
          } else {
            h.push('<h2>' + sec + '. ' + esc(b[1]) + '</h2>');
          }
          return;
        }
        if (k === 'p') {
          var t = b[1];
          if (firstP) {
            firstP = false;
            var m = t.match(/as of (.+?)([\s ])\(“Effective Date”\)/);
            if (m) {
              h.push('<p>' + esc(t.slice(0, m.index + 6)) + '<b class="fill">' + (date ? esc(date) : '<span class="ul"></span>') + '</b>' +
                     esc(t.slice(m.index + 6 + m[1].length)) + '</p>');
              return;
            }
          }
          h.push('<p class="' + (clause ? 'cont' : '') + '">' + esc(t) + '</p>');
          return;
        }
        if (k === 'r') { rec++; h.push('<p class="rec"><span class="n">' + String.fromCharCode(64 + rec) + '.</span>' + esc(b[1]) + '</p>'); return; }
        if (k === 'c') {
          clause++; sub1 = 0;
          h.push('<p class="cl"><span class="n">' + clause + '.</span>' + (b[1] ? '<b>' + esc(b[1]) + '</b>' : '') + esc(b[2]) + '</p>');
          return;
        }
        if (k === 's1') { sub1++; sub2 = 0; h.push('<p class="s1"><span class="n">(' + letter(sub1) + ')</span>' + esc(b[1]) + '</p>'); return; }
        if (k === 's2') { sub2++; h.push('<p class="s2"><span class="n">(' + roman(sub2) + ')</span>' + esc(b[1]) + '</p>'); return; }
        if (k === 'sigfollow') { h.push('<p class="sigfollow">' + esc(b[1]) + '</p>'); return; }
        if (k === 'sigp') {
          // Address lines stay blank, as on the template's signature page.
          var addr = '<tr><td></td><td class="fl"><span class="ul wide"></span><div class="cap">Address</div></td></tr>' +
                     '<tr><td></td><td class="fl"><span class="ul wide"></span><div class="cap">City/State/Zip</div></td></tr>' +
                     '<tr><td>Phone:</td><td>' + blank(phone, 1) + '</td></tr>';
          var blk = ent
            ? '<div class="entname">' + (entity ? esc(entity.toUpperCase()) : '<span class="ul wide"></span>') + '</div><table class="sig">' +
              '<tr><td>By:</td><td><span class="ul wide"></span></td></tr>' +
              '<tr><td>Name:</td><td>' + blank(signer, 1) + '</td></tr>' +
              '<tr><td>Title:</td><td>' + blank(title, 1) + '</td></tr>' + addr + '</table>'
            : '<table class="sig"><tr><td></td><td><span class="ul wide"></span> (Signature)</td></tr>' +
              '<tr><td>Name:</td><td>' + blank(signer, 1) + '</td></tr>' + addr + '</table>';
          h.push('<p><i>' + esc(b[1]) + '</i></p>' + blk +
            '<div class="rms"><b>RAINMAKER SECURITIES, LLC</b><br>' +
            '<b>By: Glen Anderson, President</b><br>382 NE 191st St. #86647 Miami, FL 33179-3899</div></section>');
          return;
        }
      });
    }
    // Schedule A — labels and text from the template table.
    var rows = [], fees = '';
    for (var i = 0; i < 4; i++) fees += '<li>' + esc(feeLine(i)) + '</li>';
    rows.push(['Issuer.', blank(issuer, 1)]);
    rows.push(['Securities.', esc(full ? PT.securities_full : PT.securities_sched)]);
    rows.push(['Success Fee.', 'The Success Fee shall be calculated as:<ul>' + fees + '</ul>']);
    if ($('f-min-on').checked) rows.push(['Minimum Commission.', esc(money($('f-min-amt').value))]);
    if ($('f-scope-on').checked) rows.push(['Scope of Coverage.', esc('For the avoidance of doubt (see Section ' + C.noncirc_section[sd] +
      ', Non-Circumvention), the scope of this Agreement and any Success Fee obligations extend to any and all ' +
      'transactions, securities sales, or fund allocations completed between ' +
      (sd === 'buy' ? 'Buyer and any Referred Seller' : 'Seller and any Referred Buyer') +
      ' during the Tail Period, regardless of whether the specific Issuer or security was listed on Schedule A at the time of Referral.')]);
    rows.push(['Tail Period', 'The ' + (tail ? esc(tail) : '<span class="ul short"></span>') + ' month period after the Referral.']);
    rows.push(['Anticipated Structure', blank(structure)]);
    rows.push(['Initials.', '<table class="init"><tr><td>' + Party + ':</td><td><span class="ul"></span></td><td>Date:</td><td><span class="ul"></span></td></tr>' +
      '<tr><td>RMS:</td><td><span class="ul"></span></td><td>Date:</td><td><span class="ul"></span></td></tr></table>']);
    h.push('<section class="sched' + (full ? ' brk' : '') + '">' + (full ? '' : topHtml) +
      '<div class="title">SCHEDULE A</div><div class="title">TRANSACTION ' + (txn ? esc(txn) : '<span class="ul short"></span>') + '</div>' +
      '<table class="sa">' + rows.map(function (r, n) {
        return '<tr><th>' + (n + 1) + '. ' + r[0] + '</th><td>' + r[1] + '</td></tr>';
      }).join('') + '</table>' + (full && PT[sd + '_version'] ? '<div class="ver">' + esc(PT[sd + '_version']) + '</div>' : '') + '</section>');

    var who = ent ? entity : signer, co = $('f-issuer').value.trim();
    var docTitle = (full ? (sd === 'buy' ? 'Buy-Side Agent Agreement' : 'Sell-Side Secondary Agent Agreement')
                         : (sd === 'buy' ? 'Schedule A - Buy Side' : 'Schedule A - Sell Side')) +
                   (who ? ' - ' + who : '') + (co ? ' - ' + co : '');
    var css = '@page{size:Letter;margin:1in}' +
      'html,body{background:#fff;color:#000;margin:0}' +
      'body{font-family:Arial,Helvetica,sans-serif;font-size:11pt;line-height:1.4}' +
      '.doc{max-width:6.5in;margin:0 auto;padding:24px 0}' +
      '.note{font:13px -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;background:#fff8d6;border:1px solid #e9d98a;' +
        'padding:8px 12px;border-radius:6px;margin:12px auto;max-width:6.5in}' +
      '@media print{.note{display:none}.doc{padding:0;max-width:none}}' +
      '.top{display:flex;justify-content:space-between;font-weight:700;margin-bottom:18px}' +
      '.title{text-align:center;font-weight:700;margin:6px 0 12px}' +
      'h2{font-size:11pt;font-weight:700;margin:16px 0 8px}' +
      'p{margin:0 0 8px;text-align:justify}' +
      'p .n{display:inline-block;min-width:0.35in;text-indent:0}' +
      'p.rec{padding-left:0.35in;text-indent:-0.35in}' +
      'p.cl{padding-left:0.35in;text-indent:-0.35in}' +
      'p.cont{padding-left:0.35in}' +
      'p.s1{padding-left:0.75in;text-indent:-0.4in}' +
      'p.s2{padding-left:1.15in;text-indent:-0.4in}' +
      'p.sigfollow{text-align:center;margin-top:16px}' +
      '.sigpage,.sched.brk{break-before:page;page-break-before:always}' +
      '.entname{font-weight:700;margin:28px 0 10px}' +
      'table.sig{border-collapse:collapse;margin-top:6px}table.sig td{padding:5px 8px 5px 0;vertical-align:bottom}' +
      'table.sig td:first-child{width:0.8in}table.sig td.fl{padding-top:14px}' +
      '.cap{font-size:10pt;font-weight:700;margin-top:2px}' +
      '.rms{margin-top:36px}' +
      '.ul{display:inline-block;width:1.6in;border-bottom:1px solid #000;height:1.1em;vertical-align:bottom}' +
      '.ul.wide{width:3in}.ul.short{width:0.5in}' +
      'table.sa{width:100%;border-collapse:collapse;margin-top:10px}' +
      'table.sa th,table.sa td{border:1px solid #000;padding:8px 10px;vertical-align:top;text-align:left}' +
      'table.sa th{width:32%;font-weight:700}table.sa ul{margin:4px 0 0 18px;padding:0}' +
      'table.init{border-collapse:collapse}table.init td{border:none;padding:6px 8px 6px 0;vertical-align:bottom}' +
      '.ver{font-size:8pt;margin-top:24px;color:#444}';
    var out = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>' + esc(docTitle) + '</title>' +
      '<style>' + css + '</style></head><body><div class="note">Cmd+P → Save as PDF</div><div class="doc">' +
      h.join('') + '</div></body></html>';
    var w = window.open('', '_blank');
    if (!w) { alert('Allow pop-ups for this page to open the print version.'); return; }
    w.document.open(); w.document.write(out); w.document.close();
  }

  // ── Wire up ──
  $('f-date').value = todayNY();
  setFees(C.fees_standard);
  $('f-generous').addEventListener('change', function () {
    setFees(this.checked ? C.fees_generous : C.fees_standard); preview();
  });
  document.querySelectorAll('input[name="f-type"]').forEach(function (r) {
    r.addEventListener('change', function () { st.typeTouched = true; preview(); });
  });
  document.querySelectorAll('input[name="f-ptype"]').forEach(function (r) {
    r.addEventListener('change', function () { st.ptypeTouched = true; syncPartyTypeUI(); preview(); });
  });
  $('f-party').addEventListener('change', onPartyChange);
  $('f-entity').addEventListener('change', function () { st.dirty.entity = true; });
  ['f-entity', 'f-signer', 'f-issuer-legal'].forEach(function (id) {
    $(id).addEventListener('change', function () { syncOwn($(id)); preview(); });
  });
  $('f-phone').addEventListener('input', function () { st.dirty.phone = true; });
  $('print-btn').addEventListener('click', printDoc);
  $('f-min-on').addEventListener('change', function () { $('f-min-amt').disabled = !this.checked; });
  document.querySelectorAll('#eng-form input, #eng-form select').forEach(function (el) {
    el.addEventListener('input', preview);
    el.addEventListener('change', preview);
  });
  fillSelect($('f-party'), [], '', false); $('f-party').disabled = true;
  fillSelect($('f-entity'), [], '');
  fillSelect($('f-signer'), [], '');
  fillSelect($('f-issuer-legal'), [], '');
  syncPartyTypeUI();
  preview();
})();
"""


def render_engagement():
    """Admin-only Engagement Docs page (read-only form + live preview)."""
    try:
        data = _engagement_data()
        page, counts, source, load_err = data["page"], data["counts"], data["source"], ""
    except Exception as e:
        print(f"engagement: data load failed: {e}")
        page = {"deals": [], "companies": []}
        counts = {"deals_total": 0, "deals_live": 0, "deals_closed": 0, "closed_ok": False,
                  "companies": 0, "people": 0}
        source, load_err = "", "Couldn't load Pipeline data from S3."
    # JSON inside <script> is safe once "</" can't close the tag.
    data_json = json.dumps(page, separators=(",", ":")).replace("</", "<\\/")
    const_json = json.dumps({"fee_templates": ENG_FEE_TEMPLATES, "fees_standard": ENG_FEES_STANDARD,
                             "fees_generous": ENG_FEES_GENEROUS,
                             "noncirc_section": ENG_NONCIRC_SECTION}).replace("</", "<\\/")
    print_json = ENG_PRINT_TEMPLATES_JSON.replace("</", "<\\/")
    c = counts
    meta = (f'{c["deals_live"]} live deals (of {c["deals_total"]}) · '
            f'{c["deals_closed"] if c["closed_ok"] else "no"} closed deals · {c["companies"]} companies · '
            f'{c["people"]} people from {html.escape(source or "—")}')
    fee_rows = "".join(
        f'<div class="fee-row"><input type="text" inputmode="decimal" id="f-fee-{i}" class="pct">'
        f'<span>{html.escape(t.replace("{p}", ""))}</span></div>'
        for i, t in enumerate(ENG_FEE_TEMPLATES))
    css = """
    <style>
      .eng-wrap { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); gap:28px; margin-top:18px; }
      @media (max-width: 860px) { .eng-wrap { grid-template-columns:1fr; } }
      .eng-meta { font-size:12px; color:var(--muted); margin-top:6px; }
      .eng-err { color:var(--neg); font-size:13px; margin-top:8px; }
      #eng-form .row { margin-bottom:16px; }
      #eng-form label.lbl { display:block; font-size:12px; font-weight:600; letter-spacing:.03em;
        text-transform:uppercase; color:var(--muted); margin-bottom:6px; }
      #eng-form input[type=text], #eng-form input[type=number], #eng-form select {
        width:100%; font:inherit; font-size:14px; padding:8px 10px; border:1px solid var(--line);
        border-radius:8px; background:#fff; color:var(--ink); }
      #eng-form input:disabled { background:#f3f2ee; color:#9a978f; }
      #eng-form .own { margin-top:6px; display:none; }
      #eng-form .stack input + input { margin-top:6px; }
      #eng-form .radios label:not(.lbl), #eng-form .chk { display:inline-flex; align-items:center; gap:6px;
        margin:0 18px 4px 0; font-size:14px; }
      #eng-form .radios input, #eng-form .chk input { width:auto; margin:0; }
      .type-grid { display:grid; grid-template-columns:1fr 1fr; gap:2px 12px; }
      .note { font-size:12px; color:#9a978f; margin-top:4px; }
      .fee-row { display:flex; align-items:baseline; gap:6px; font-size:13px; line-height:1.4; margin-bottom:6px; }
      #eng-form .fee-row input.pct { width:58px; flex:none; padding:5px 6px; text-align:right; }
      .min-row { display:flex; align-items:center; gap:10px; }
      #eng-form .min-row input[type=text] { width:140px; }
      .badge { display:none; font-size:12px; padding:2px 8px; border-radius:999px; background:#eef2ff;
        color:#3730a3; margin-top:6px; }
      .badge span { color:#6b7280; }
      .ta { position:relative; }
      .ta-list { display:none; position:absolute; left:0; right:0; top:100%; z-index:20; background:#fff;
        border:1px solid var(--line); border-radius:8px; max-height:320px; overflow-y:auto;
        box-shadow:0 6px 24px rgba(20,24,29,.12); }
      .ta-item { padding:7px 10px; font-size:13px; cursor:pointer; border-top:1px solid #f1efea; }
      .ta-item:first-child { border-top:none; }
      .ta-item.active, .ta-item:hover { background:#faf8f3; }
      .ta-tag { display:inline-block; font-size:10px; font-weight:600; text-transform:uppercase;
        color:var(--muted); border:1px solid var(--line); border-radius:4px; padding:1px 4px; margin-right:6px; }
      .eng-preview { border:1px solid var(--line); border-radius:10px; padding:20px 22px; background:#fcfbf8;
        font-family: 'Times New Roman', Times, serif; font-size:14px; line-height:1.5; align-self:start;
        position:sticky; top:16px; }
      .pv-sec { margin-bottom:18px; }
      .pv-h { font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size:11px;
        font-weight:600; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); margin-bottom:6px; }
      .pv-val { background:#fff4c2; border-radius:3px; padding:0 2px; }
      .pv-missing { color:#b23b3b; }
      .pv-ent { font-weight:700; margin-bottom:6px; }
      .pv-kv { display:flex; gap:8px; margin-bottom:3px; }
      .pv-kv > span { width:62px; flex:none; }
      .pv-rms { margin-top:16px; }
      .pv-cap { font-size:12px; font-weight:700; margin-top:2px; }
      .uline { display:inline-block; width:120px; border-bottom:1px solid var(--ink); height:1em; vertical-align:bottom; }
      .uline.wide { width:220px; }
      .pv-txn { text-align:center; font-weight:700; margin:4px 0 10px; }
      .pv-tbl { width:100%; border-collapse:collapse; }
      .pv-tbl th { text-align:left; vertical-align:top; width:34%; padding:6px 8px 6px 0; font-weight:700;
        font-size:14px; text-transform:none; letter-spacing:normal; color:var(--ink); }
      .pv-tbl td { padding:6px 0; vertical-align:top; }
      .pv-tbl ul { margin:4px 0 0 18px; }
      .pv-init { border-collapse:collapse; }
      .pv-init td { padding:4px 6px 4px 0; vertical-align:bottom; }
      .print-btn { margin:8px 8px 0 0; font:inherit; font-size:14px; font-weight:600; padding:10px 16px;
        border-radius:8px; border:1px solid var(--ink); background:var(--ink); color:#fff; cursor:pointer; }
      .gen-btn { margin-top:8px; font:inherit; font-size:14px; font-weight:600; padding:10px 16px;
        border-radius:8px; border:1px solid var(--line); background:#eeece7; color:#9a978f; cursor:not-allowed; }
    </style>"""
    body = css + f"""
    <h1>Engagement Docs</h1>
    <p class="sub">Agent agreement and Schedule A. Read-only preview — nothing is generated or sent yet.</p>
    <p class="eng-meta">{meta}</p>
    {f'<p class="eng-err">{html.escape(load_err)}</p>' if load_err else ''}
    <div class="eng-wrap">
      <form id="eng-form" autocomplete="off" onsubmit="return false">
        <div class="row radios"><label class="lbl">Type</label>
          <div class="type-grid">
            <label><input type="radio" name="f-type" value="sell_full" checked> Sell-side full agreement</label>
            <label><input type="radio" name="f-type" value="sell_sched"> Sell-side Schedule A</label>
            <label><input type="radio" name="f-type" value="buy_full"> Buy-side full agreement</label>
            <label><input type="radio" name="f-type" value="buy_sched"> Buy-side Schedule A</label>
          </div>
        </div>
        <div class="row"><label class="lbl" for="f-start">Start from</label>
          <div class="ta"><input type="text" id="f-start" placeholder="Search live deals or people…">
            <div class="ta-list" id="f-start-list"></div></div>
          <div class="note" id="start-picked"></div>
        </div>
        <div class="row"><label class="lbl" for="f-party">Party</label>
          <select id="f-party"></select>
          <span class="badge" id="il-badge"></span>
          <div class="note" id="drive-note"></div></div>
        <div class="row radios"><label class="lbl">Party type</label>
          <label><input type="radio" name="f-ptype" value="individual" checked> Individual</label>
          <label><input type="radio" name="f-ptype" value="entity"> Entity</label>
          <div class="note" id="ptype-note"></div></div>
        <div class="row" id="row-entity"><label class="lbl" for="f-entity">Entity name</label>
          <select id="f-entity"></select>
          <input type="text" id="f-entity-own" class="own" placeholder="Entity name">
          <div class="note" id="f-entity-src"></div></div>
        <div class="row"><label class="lbl" for="f-signer">Signer</label>
          <select id="f-signer"></select>
          <input type="text" id="f-signer-own" class="own" placeholder="Signer name"></div>
        <div class="row" id="row-title"><label class="lbl" for="f-title">Title</label>
          <input type="text" id="f-title" value="Authorized Signatory"></div>
        <div class="row"><label class="lbl" for="f-phone">Phone</label>
          <input type="text" id="f-phone"></div>
        <div class="row"><label class="lbl" for="f-issuer">Company (issuer)</label>
          <div class="ta"><input type="text" id="f-issuer" placeholder="Search Pipeline companies…">
            <div class="ta-list" id="f-issuer-list"></div></div></div>
        <div class="row"><label class="lbl" for="f-issuer-legal">Issuer legal name</label>
          <select id="f-issuer-legal"></select>
          <input type="text" id="f-issuer-legal-own" class="own" placeholder="Issuer legal name">
          <div class="note" id="issuer-legal-note" style="display:none">No Legal Name in Pipeline</div></div>
        <div class="row"><label class="lbl" for="f-structure">Structure</label>
          <select id="f-structure"><option value=""></option><option>Direct</option>
            <option>SPV</option><option>Forward</option></select>
          <div class="note" id="structure-note"></div></div>
        <div class="row"><label class="lbl">Success fee</label>{fee_rows}
          <label class="chk"><input type="checkbox" id="f-generous"> Generous fees</label></div>
        <div class="row"><label class="lbl">Minimum commission</label>
          <div class="min-row"><label class="chk"><input type="checkbox" id="f-min-on"> Apply</label>
            <input type="text" id="f-min-amt" value="7,500" disabled></div></div>
        <div class="row"><label class="lbl">Scope of coverage</label>
          <label class="chk"><input type="checkbox" id="f-scope-on"> Add Scope of Coverage row</label></div>
        <div class="row" id="row-platinum" style="display:none">
          <label class="chk"><input type="checkbox" id="f-platinum" disabled>
            Platinum client: apply commission discounts (coming soon)</label></div>
        <div class="row"><label class="lbl" for="f-tail">Tail (months)</label>
          <input type="number" id="f-tail" value="12" min="0"></div>
        <div class="row" id="row-txn" style="display:none"><label class="lbl" for="f-txn">Transaction #</label>
          <input type="number" id="f-txn" min="1"></div>
        <div class="row"><label class="lbl" for="f-date">Date</label>
          <input type="text" id="f-date"></div>
        <button type="button" class="print-btn" id="print-btn">Print version</button>
        <button type="button" class="gen-btn" disabled>Generate (coming next)</button>
      </form>
      <div class="eng-preview" id="preview"></div>
    </div>
    <script type="application/json" id="eng-data">{data_json}</script>
    <script type="application/json" id="eng-const">{const_json}</script>
    <script type="application/json" id="eng-print">{print_json}</script>
    <script>""" + ENG_JS + "</script>"
    return html_response(body, eyebrow="Admin", is_admin=True, view="engagement")


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
    <p class="sub">Create an auction, then share its link with interested buyers.
    Fields left blank fill in from the seed deal, if one is given.</p>
    {banner}
    <form method="POST" action="?view=auctions">
      <input type="hidden" name="action" value="auction_create">
      <div class="auc-grid">
        <div><label>Company</label><input name="company" required placeholder="Hadrian"></div>
        <div><label>Seed deal ID (optional)</label><input name="deal_id" placeholder="55266875"></div>
        <div><label>Reserve price per share</label><input name="ask" placeholder="110"></div>
        <div><label>Shares (optional)</label><input name="shares" placeholder="100000"></div>
        <div><label>Structure</label><input name="structure" placeholder="Direct Transfer"></div>
        <div><label>Share class (optional)</label><input name="share_class" placeholder="Common"></div>
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
    # Append-only revision history: a change to an EXISTING bid's price or size
    # appends one entry; a brand-new bid (no prior record) starts with none --
    # bids from before this field existed simply have no history yet, and pick
    # it up starting from their next change, never a fabricated past. Past
    # entries are carried forward untouched and never rewritten or dropped.
    history = list(prior.get("revision_history") or [])
    if prior and (
        _auc_num(prior.get("gross")) != _auc_num(bid.get("gross"))
        or _auc_num(prior.get("min_size")) != _auc_num(bid.get("min_size"))
        or _auc_num(prior.get("max_size")) != _auc_num(bid.get("max_size"))
    ):
        history.append({
            "timestamp": now,
            "old_price": prior.get("gross"),
            "new_price": bid.get("gross"),
            "old_size_min": prior.get("min_size"),
            "old_size_max": prior.get("max_size"),
            "new_size_min": bid.get("min_size"),
            "new_size_max": bid.get("max_size"),
        })
    bid["revision_history"] = history
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
# Pipeline CRM custom field for the fund's exemption. The cached value is an
# option ID, not a string -- verified in chadgracia/deal-update-form's own
# _FE_LABELS map, which this mirrors exactly.
AUC_FUND_EXEMPTION_FIELD = "custom_label_4006089"
AUC_FUND_EXEMPTION_LABELS = {7200027: "3(c)(1)", 7200028: "3(c)(7)",
                             7201486: "Other / Non-US"}


def _auc_fund_exemption_label(val):
    """Resolve a raw custom_label_4006089 value to its option label. val may
    arrive as an int, float, or numeric string (option IDs from JSON can come
    back in any of these forms) -- int(float(str(val))) normalises all three
    before the label lookup. Any unknown or unparseable value falls back to
    showing itself, as a string, rather than going blank."""
    if val in (None, ""):
        return ""
    try:
        oid = int(float(str(val)))
    except (TypeError, ValueError):
        return str(val).strip()
    return AUC_FUND_EXEMPTION_LABELS.get(oid, str(val).strip())


def _auction_deal_prefill(deal_id, company_name):
    """Auction-record fields sourced from the deal, for the create-from-deal
    flow and the Edit Auction form: only fields that are empty on the auction
    itself should ever be overwritten by these, never a manually-entered
    value. Two caches, both already read elsewhere in this repo, split the
    fields between them:
      - full-pipeline-cache/deals.json (DEALS_KEY on COMPANIES_BUCKET), the
        raw Pipeline snapshot syndicator_eligible_sellers also reads: shares
        and share class (the same AUC_SHARES_FIELD/AUC_CLASS_FIELD custom
        fields _auction_deal_facts already resolves, just from the cache
        instead of a live per-request API call), the deal summary as the
        description/teaser, and the fund exemption custom field.
      - pipeline-public-deal-data/pipeline_deals.json (WL_DEALS_BUCKET/
        WL_DEALS_KEY), the same flattened cache the trades watchlist and
        _wl_structure_label read: structure, size, price and the three fund
        fees/layers, none of which are broken out as their own custom fields
        here.
    Never raises; a field simply stays at its empty default on any failure."""
    out = {"structure": "", "shares": None, "price": None, "min_size": None,
           "max_size": None, "share_class": "", "description": "",
           "management_fee": None, "seller_fee": None, "carry": None,
           "layers": "", "fund_exemption": ""}
    if not deal_id:
        return out
    deal_id = str(deal_id)

    raw_deals = (_wl_json(COMPANIES_BUCKET, DEALS_KEY, {}) or {}).get("deals") or []
    deal = next((d for d in raw_deals if str(d.get("id")) == deal_id), None)
    if deal:
        cf = deal.get("custom_fields") or {}
        for oid in cf_id_list(cf.get(AUC_CLASS_FIELD)):
            if oid in AUC_CLASS_LABELS:
                out["share_class"] = AUC_CLASS_LABELS[oid]
                break
        out["shares"] = _auc_num(cf.get(AUC_SHARES_FIELD))
        out["description"] = (deal.get("summary") or "").strip()
        _exempt = cf.get(AUC_FUND_EXEMPTION_FIELD)
        if isinstance(_exempt, list):
            _exempt = _exempt[0] if _exempt else None
        out["fund_exemption"] = _auc_fund_exemption_label(_exempt)

    wl_deals = _wl_json(WL_DEALS_BUCKET, WL_DEALS_KEY, [])
    if not isinstance(wl_deals, list):
        wl_deals = []
    wl = next((d for d in wl_deals if str(d.get("id")) == deal_id), None)
    if not wl and company_name:
        wl = next((d for d in wl_deals if (d.get("company") or "").strip().lower()
                   == company_name.strip().lower()), None)
    if wl:
        out["structure"] = (wl.get("structure") or "").strip()
        out["min_size"] = _auc_num(wl.get("min_deal_size"))
        out["max_size"] = _auc_num(wl.get("max_deal_size"))
        out["price"] = _auc_num(wl.get("net")) or _auc_num(wl.get("gross"))
        out["management_fee"] = _fee_pct(wl.get("management_fee"))
        out["seller_fee"] = _fee_pct(wl.get("seller_fee"))
        out["carry"] = _fee_pct(wl.get("carry"))
        out["layers"] = _wl_layers_label(wl.get("layers"))
    return out


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


def render_demand_board(client_id, is_admin):
    """Client-facing Demand Board at ?view=demand. Counts only -- no QP/
    Accredited/Unknown breakdown, no names, no emails, no dollar figures --
    sourced entirely from syndicate-dash's own precomputed table via
    _fetch_demand_data. Never breaks the page: any failure (network, bad
    shape, whatever) falls through to a friendly placeholder in the normal
    shell instead of a stack trace."""
    try:
        data = _fetch_demand_data()
        if not isinstance(data, dict):
            raise ValueError("no demand data available")
        rows = [r for r in (data.get("rows") or [])
               if isinstance(r, dict)
               and not (r.get("company") or "").strip().endswith("$")
               and (r.get("buyers") or 0) > 0]
        rows.sort(key=lambda r: (-(r.get("buyers") or 0), (r.get("company") or "").lower()))

        total_note = ""
        companies_with_buyers = data.get("companies_with_buyers")
        if companies_with_buyers:
            total_note = (f'<p class="dmd-total">{int(companies_with_buyers):,} '
                          'companies with interested buyers</p>')

        if rows:
            trs = "".join(
                '<tr data-name="' + html.escape((r.get("company") or "").lower(), quote=True) + '">'
                f'<td class="dmd-company">{html.escape(r.get("company") or "")}</td>'
                f'<td class="num">{int(r.get("buyers") or 0):,}</td>'
                f'<td class="num">{int(r.get("sellers") or 0):,}</td>'
                '</tr>'
                for r in rows
            )
        else:
            trs = '<tr><td colspan="3" class="wl-soft">No live buyer interest right now.</td></tr>'

        body = f"""
        <style>
          .dmd-sub {{ color:#6b7280; margin:2px 0 4px; }}
          .dmd-total {{ color:#6b7280; font-size:13px; margin:0 0 14px; }}
          .dmd-search {{ width:100%; max-width:320px; padding:9px 12px; margin-bottom:14px;
                         font-family:inherit; font-size:14px; border:1px solid var(--line);
                         border-radius:8px; }}
          table.dmd {{ width:100%; border-collapse:collapse; font-size:14px; }}
          table.dmd th, table.dmd td {{ border-bottom:1px solid var(--line); padding:10px 14px;
                                        text-align:left; }}
          table.dmd th {{ font-size:11px; letter-spacing:.05em; text-transform:uppercase;
                         color:#6b7280; font-weight:600; }}
          table.dmd td.num, table.dmd th.num {{ text-align:right; }}
          .dmd-company {{ font-weight:600; }}
        </style>
        <h1>Demand Board</h1>
        <p class="dmd-sub">Live buyer interest across our private-markets network.</p>
        {total_note}
        <input type="text" id="dmd-search" class="dmd-search" autocomplete="off"
               placeholder="Search companies&hellip;">
        <table class="dmd">
          <thead><tr><th>Company</th><th class="num">Interested Buyers</th><th class="num">Sellers</th></tr></thead>
          <tbody id="dmd-rows">{trs}</tbody>
        </table>
        <script>
          (function () {{
            var box = document.getElementById('dmd-search');
            var rows = Array.prototype.slice.call(document.querySelectorAll('#dmd-rows tr[data-name]'));
            if (!box) return;
            box.addEventListener('input', function () {{
              var q = box.value.trim().toLowerCase();
              rows.forEach(function (tr) {{
                tr.style.display = tr.getAttribute('data-name').indexOf(q) !== -1 ? '' : 'none';
              }});
            }});
          }})();
        </script>
        """
        return html_response(body, is_admin=is_admin, view="demand", client_id=client_id)
    except Exception as e:
        print(f"Demand Board: render failed (non-fatal): {e}")
        body = ('<h1>Demand Board</h1>'
               '<p class="wl-soft">The Demand Board is being updated — check back shortly.</p>')
        return html_response(body, is_admin=is_admin, view="demand", client_id=client_id)


def render_auction_list(client_id, is_admin):
    """Client-facing list of LIVE auctions only -- no bids, no admin controls, no
    closed auctions. The caller (the session-gated route) enforces the same
    login wall as the buyer auction view; admins see this read-only list too."""
    live = [(aid, auc) for aid, auc in _load_auctions().items()
           if _auction_is_live(auc.get("close_date"))]
    live.sort(key=lambda kv: (kv[1].get("company") or "").lower())

    if live:
        cards = "".join(
            '<div class="aul-card">'
            '<div class="aul-main">'
            f'<div class="aul-title">{html.escape(auc.get("company") or "")}'
            + (f' <span class="aul-structure">&mdash; {html.escape(auc["structure"])}</span>'
               if auc.get("structure") else "")
            + '</div>'
            '<div class="aul-close">'
            + (f'Closes {html.escape(_auc_date(auc.get("close_date")))}'
               if auc.get("close_date") else "No deadline")
            + '</div></div>'
            f'<a class="aul-link" href="?view=auction&amp;id={html.escape(str(aid), quote=True)}">'
            'View auction &rarr;</a>'
            '</div>'
            for aid, auc in live
        )
    else:
        cards = '<p class="wl-soft">No live auctions right now.</p>'

    body = f"""
    <style>
      .aul-list {{ display:flex; flex-direction:column; gap:12px; margin-top:18px; }}
      .aul-card {{ display:flex; justify-content:space-between; align-items:center;
                   gap:16px; border:1px solid var(--line); border-radius:8px;
                   padding:16px 18px; background:#fff; }}
      .aul-title {{ font-size:16px; font-weight:600; }}
      .aul-structure {{ font-weight:400; color:#6b7280; }}
      .aul-close {{ font-size:13px; color:#6b7280; margin-top:4px; }}
      .aul-link {{ flex:none; font-size:14px; font-weight:600; color:var(--ink);
                   text-decoration:none; white-space:nowrap; }}
      .aul-link:hover {{ text-decoration:underline; }}
    </style>
    <h1>Live Auctions</h1>
    <div class="aul-list">{cards}</div>
    """
    return html_response(body, is_admin=is_admin, view="auction_list", client_id=client_id)


# The commission-tiers page's checklist styling (green tick, rules, status box),
# scoped under .cts so it can't touch the desk shell's own h1/p/table rules.
_CTS_CSS = """
  .cts { --ink: #16202b; --muted: #5b6673; --rule: #e2e6ea; --navy: #1d3a5c;
         --check: #2e7d4f; --tint: #f5f7f9; --paper: #ffffff;
         --serif: "Source Serif 4", Georgia, "Times New Roman", serif;
         --sans: "IBM Plex Sans", -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
         font-family: var(--sans); font-size: 15px; line-height: 1.55; color: var(--ink);
         margin-top: 18px; }
  .cts p { margin: 0; max-width: 68ch; }
  .cts a { color: var(--navy); }
  .cts ul.checks { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; border-top: 1px solid var(--rule); }
  .cts ul.checks li { display: grid; grid-template-columns: 26px 1fr; gap: 10px; padding: 9px 0; border-bottom: 1px solid var(--rule); align-items: start; }
  .cts ul.checks li > div { min-width: 0; }
  .cts .note { display: block; font-size: 13px; color: var(--muted); }
  .cts .mark { width: 20px; height: 20px; margin-top: 2px; border-radius: 50%; display: grid; place-items: center; }
  .cts .mark.on { background: var(--check); }
  .cts .mark.on svg { width: 12px; height: 12px; fill: none; stroke: var(--paper); stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round; }
  .cts .status { background: var(--tint); border: 1px solid var(--rule); border-radius: 4px; padding: 22px; display: flex; flex-direction: column; gap: 14px; }
  .cts .status-head { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 8px; }
  .cts .status-head .who { font-family: var(--serif); font-size: 19px; font-weight: 600; }
  .cts .pill { font-size: 12px; font-weight: 600; color: var(--navy); border: 1px solid var(--navy); border-radius: 999px; padding: 2px 11px; }
  .cts .next { font-size: 14px; }
  .cts .next b { color: var(--navy); }
  .cts .who-line { font-size: 14px; color: var(--muted); }
"""

_CTS_TICK = '<span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span>'


def _safe_href(url):
    """Only plain http(s) links make it into the page; anything else is dropped."""
    url = str(url or "").strip()
    if url.lower().startswith(("https://", "http://")):
        return html.escape(url, quote=True)
    return ""


def render_profile(client_id, is_admin, viewing_as=False, share_err=False):
    """Signed-in client's Profile: who they're signed in as plus the "Your
    status" card (_render_status_card, standing_json via the 5-minute cache)
    with the sellers-sharing toggle. Standing is never computed here; with no
    visible standing (or any error) the client sees one soft line."""
    email = ""
    try:
        rec = lookup_person(client_id)
        if rec.get("found"):
            email = (rec.get("email") or "").strip()
    except Exception as e:
        print(f"Profile: person lookup failed (non-fatal): {e}")
    who = html.escape(email) if email else html.escape(display_name(client_id))

    card = _render_status_card(client_id, viewing_as=viewing_as, share_err=share_err)
    if not card:
        card = ('<p>Your client status will appear here soon. Questions? Email '
                '<a href="mailto:cgracia@rainmakersecurities.com">cgracia@rainmakersecurities.com</a>.</p>')

    body = f"""
    <style>{_CTS_CSS}</style>
    <h1>Profile</h1>
    <div class="cts">
      <p class="who-line" style="margin-bottom:14px;">Signed in as {who}</p>
      {card}
    </div>
    """
    return html_response(body, is_admin=is_admin, view="profile", client_id=client_id)


def render_live_auctions_overview(client_id):
    """Client-facing sibling of render_auction: every currently live auction,
    same _auction_is_live rule the unified nav's Auctions tab uses, with no
    watchlist, indication, or holdings filtering -- every signed-in user sees
    the same book. Reserve stays admin-only (see render_auction's own gate on
    "ask"), so this only ever surfaces the current top bid."""
    live = [(aid, auc) for aid, auc in _load_auctions().items()
            if _auction_is_live(auc.get("close_date"))]
    live.sort(key=lambda kv: kv[1].get("close_date") or "9999-99-99")

    if not live:
        body_rows = '<p class="wl-soft">No live auctions.</p>'
    else:
        rows = ""
        for aid, auc in live:
            bids = _load_auction_bids(aid).values()
            amounts = [n for n in (_auc_num(b.get("gross")) for b in bids) if n]
            top = max(amounts) if amounts else None
            size_cell = (f'{_wl_money(auc.get("min_size"))} &ndash; {_wl_money(auc.get("max_size"))}'
                         if (auc.get("min_size") or auc.get("max_size")) else "&mdash;")
            close_cell = (html.escape(_auc_date(auc.get("close_date")))
                          if auc.get("close_date") else "No deadline")
            _aid_q = html.escape(str(aid), quote=True)
            rows += (
                "<tr>"
                f'<td><strong>{html.escape(auc.get("company") or "")}</strong></td>'
                f'<td>{html.escape(auc.get("structure") or "") or "&mdash;"}</td>'
                f'<td>{_wl_pps(top) if top else "&mdash;"}</td>'
                f'<td>{size_cell}</td>'
                f'<td>{close_cell}</td>'
                f'<td><a href="?view=auction&amp;id={_aid_q}">View auction &rarr;</a></td>'
                "</tr>"
            )
        body_rows = (
            '<table class="auc">'
            '<thead><tr><th>Company</th><th>Structure</th><th>Current bid</th>'
            '<th>Size</th><th>Close date</th><th></th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )

    body = f"""
    <style>
      table.auc {{ width:100%; border-collapse:collapse; font-size:14px; margin-top:18px; }}
      table.auc th, table.auc td {{ border:1px solid var(--line); padding:10px 12px; text-align:left; }}
      table.auc th {{ font-size:12px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); }}
      .wl-soft {{ color:#6b7280; }}
    </style>
    <h1>Live Auctions</h1>
    <p class="subtitle">Every auction currently open for bids.</p>
    {body_rows}
    """
    return html_response(body, view="auctions", client_id=client_id)


def render_auction(auction_id, client_id, is_admin, err="", min_bump=""):
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
    # Manually-entered auction values always win; the deal only fills gaps.
    deal_pre = _auction_deal_prefill(auc.get("deal_id"), company)
    _structure_val = (auc.get("structure") or "").strip() or deal_pre["structure"]
    _share_class_val = (auc.get("share_class") or "").strip() or deal_pre["share_class"]
    _shares_val = _auc_num(auc.get("shares"))
    if _shares_val is None:
        _shares_val = deal_pre["shares"]
    _min_size_val = _auc_num(auc.get("min_size"))
    if _min_size_val is None:
        _min_size_val = deal_pre["min_size"]
    _max_size_val = _auc_num(auc.get("max_size"))
    if _max_size_val is None:
        _max_size_val = deal_pre["max_size"]

    _f = []
    if _structure_val:
        _f.append(("Structure", html.escape(_structure_val)))
    if _share_class_val:
        _f.append(("Share class", html.escape(_share_class_val)))
    if _structure_val and ("fund" in _structure_val.lower() or "spv" in _structure_val.lower()):
        if deal_pre["management_fee"] is not None:
            _f.append(("Management Fee", f'{deal_pre["management_fee"]}%'))
        if deal_pre["seller_fee"] is not None:
            _f.append(("Seller Fee", f'{deal_pre["seller_fee"]}%'))
        if deal_pre["carry"] is not None:
            _f.append(("Carry", f'{deal_pre["carry"]}%'))
        if deal_pre["layers"]:
            _f.append(("Layers", html.escape(deal_pre["layers"])))
        if deal_pre["fund_exemption"]:
            _f.append(("Fund Exemption", html.escape(deal_pre["fund_exemption"])))
    if _min_size_val or _max_size_val:
        _f.append(("Size", f'{_wl_money(_min_size_val)} &ndash; {_wl_money(_max_size_val)}'))
    if _shares_val:
        _f.append(("Shares", f"{int(_shares_val):,}"))
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
    # Deal description/teaser: the cached deal summary (see _auction_deal_prefill)
    # takes priority over the live-fetched one, per the same cache-first rule as
    # the fields above; the live value only covers a deal not yet in the cache.
    _teaser = deal_pre["description"] or facts["notes"]
    notes_html = (f'<div class="au-cat"><div class="au-catlbl">Seller notes</div>'
                  f'<div>{html.escape(_teaser)}</div></div>'
                  if _teaser else "")
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
    if is_admin:
        _seller_url = (f"{DESK_URL}/?view=auction_seller&id={urllib.parse.quote(_aid_s)}"
                       f"&stoken={make_seller_token(_aid_s)}")
        _bits += (f'<button type="button" class="au-selllink"'
                  f' onclick="auCopyFeedback(\'{_js_lit(_seller_url)}\', this)">'
                  'Copy seller link</button>')
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
            _bell = ' &#128276;' if b.get("alert_on_higher_bid") else ""
            if b.get("person_id"):
                _name_html = (f'<a href="{html.escape(PD_PERSON_URL + urllib.parse.quote(str(b["person_id"])))}"'
                              f' target="_blank" rel="noopener">{html.escape(_bname)}</a>')
            else:
                _name_html = html.escape(_bname)
            _mail_icon = ""
            if _bmail:
                _mail_icon = (f'<button type="button" class="au-mailcopy"'
                              f' onclick="auCopyFeedback(\'{_js_lit(_bmail)}\', this)"'
                              f' title="Copy email">&#9993;</button>')
            _history = list(b.get("revision_history") or [])
            _revbadge = ""
            if len(_history) > 1:
                _tip = "&#10;".join(
                    f'{html.escape((h.get("timestamp") or "")[:16].replace("T", " "))} '
                    f'&mdash; {html.escape(_wl_pps(h.get("new_price")))}'
                    for h in _history)
                _revbadge = f' <span class="au-revs" title="{_tip}">&times;{len(_history)}</span>'
            rows += (
                "<tr>"
                f"<td>{i}</td>"
                f'<td>{_name_html}{_bell}<div class="au-namesub">{_mail_icon}</div></td>'
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
                f'<td>{html.escape((b.get("updated_at") or "")[:10])}{_revbadge}</td>'
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
            rows = '<tr><td colspan="9" class="wl-soft">No bids yet.</td></tr>'
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
                '<table class="auc"><thead><tr><th>#</th><th>Name</th>'
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
        if err == "increment":
            _bump = _auc_num(min_bump) or 0
            _err_html = (f'<p class="au-bad">That bid wasn\'t saved &mdash; bids must '
                        f'improve by at least {_wl_pps(_bump)}.</p>')
        # Active minimum increment, shown so a bidder knows the floor before typing:
        # the reference is their own current bid if they have one, else the top bid.
        _inc_ref = (_auc_num(me.get("gross")) if me else None) or top or 0
        _active_inc = _auc_increment(auc, _inc_ref)
        _mininc_html = (f'<p class="au-mininc">Minimum bid increment: '
                        f'{_wl_pps(_active_inc)}</p>')
        _alert_higher = bool(me and me.get("alert_on_higher_bid"))
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
                       value="{html.escape(str(_pv or ''), quote=True)}" required>
                {_mininc_html}</div>
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
              <div class="au-full au-higherbid">
                <label><input type="checkbox" name="alert_on_higher_bid"
                       {"checked" if _alert_higher else ""}>
                  Update me when a higher bid comes in</label>
              </div>
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
        def _v(k, fallback=""):
            x = auc.get(k)
            if x in (None, ""):
                x = fallback
            if x in (None, ""):
                return ""
            if isinstance(x, float) and x == int(x):
                x = int(x)
            return html.escape(str(x), quote=True)

        def _mmdd(d):
            try:
                return datetime.strptime(d, "%Y-%m-%d").strftime("%m/%d")
            except (ValueError, TypeError):
                return d or ""
        _ext_hist_html = ""
        _extensions = auc.get("extensions") or []
        if _extensions:
            _ext_lines = "".join(
                f'<div class="au-extline">Extended by seller: +{e.get("days_added")}d on '
                f'{html.escape(_mmdd(e.get("old_close")))} &rarr; '
                f'{html.escape(_mmdd(e.get("new_close")))}</div>'
                for e in _extensions
            )
            _ext_hist_html = f'<div class="au-full au-exthist">{_ext_lines}</div>'
        edit_html = f"""
        <details class="au-edit">
          <summary>Edit auction</summary>
          <form method="POST" action="?view=auction&amp;id={html.escape(str(auction_id), quote=True)}">
            <input type="hidden" name="action" value="auction_update">
            <input type="hidden" name="auction_id" value="{html.escape(str(auction_id), quote=True)}">
            <div class="au-egrid">
              <div><label>Structure</label><input name="structure" value="{_v('structure', deal_pre['structure'])}"></div>
              <div><label>Share class</label><input name="share_class" value="{_v('share_class', deal_pre['share_class'])}"></div>
              <div><label>Shares</label><input name="shares" value="{_v('shares', deal_pre['shares'])}"></div>
              <div><label>Min size ($)</label><input name="min_size" value="{_v('min_size', deal_pre['min_size'])}"></div>
              <div><label>Max size ($)</label><input name="max_size" value="{_v('max_size', deal_pre['max_size'])}"></div>
              <div><label>Reserve ($/share)</label><input name="ask" value="{_v('ask', deal_pre['price'])}"></div>
              <div><label title="Blank or 0 = automatic tick from the current bid price.">Min increment ($)</label>
                <input name="min_increment" value="{_v('min_increment')}" placeholder="Automatic"></div>
              <div><label>Bids close</label><input name="close_date" type="date" value="{_v('close_date')}"></div>
              {_ext_hist_html}
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
      .au-higherbid {{ font-size:13px; margin:0 0 6px; }}
      .au-higherbid label {{ display:flex; align-items:center; gap:6px; font-weight:400; }}
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
      .au-exthist {{ margin-top:-4px; }}
      .au-extline {{ font-size:12px; color:#6b7280; }}
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
      .au-namesub {{ margin-top:2px; }}
      .au-mailcopy {{ font-family:inherit; font-size:11px; border:none; background:none;
                      color:var(--muted); cursor:pointer; padding:0; }}
      .au-mailcopy:hover {{ color:var(--ink); }}
      .au-revs {{ font-size:11px; color:var(--muted); cursor:default; margin-left:4px; }}
      .au-selllink {{ margin-left:10px; padding:8px 14px; font-family:inherit; font-size:13px;
                      font-weight:600; border:1px solid var(--line); border-radius:6px;
                      background:#fff; color:var(--ink); cursor:pointer; }}
      .au-mininc {{ font-size:12px; color:var(--muted); margin:4px 0 0; }}
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
      // Same as auCopy, but shows a temporary "Copied" confirmation on the
      // triggering element and falls back to prompt() when the Clipboard API
      // isn't available (e.g. non-HTTPS or an older browser).
      function auCopyFeedback(t, el) {{
        function ok() {{
          if (!el) {{ return; }}
          var orig = el.textContent;
          el.textContent = 'Copied';
          setTimeout(function () {{ el.textContent = orig; }}, 1200);
        }}
        if (navigator.clipboard && navigator.clipboard.writeText) {{
          navigator.clipboard.writeText(t).then(ok, function () {{ prompt('Copy:', t); }});
        }} else {{
          prompt('Copy:', t);
        }}
      }}
    </script>
    """, eyebrow=("Auction: " + company +
                  ((" — " + auc.get("structure")) if auc.get("structure") else "")),
       is_admin=is_admin, view="auction", client_id=client_id)


def _seller_letter(i):
    """1-indexed rank -> A, B, ..., Z, AA, AB, ... (spreadsheet column style),
    so a book past 26 bidders still gets a distinct, sortable label."""
    s = ""
    n = i
    while n > 0:
        n, rem = divmod(n - 1, 26)
        s = chr(65 + rem) + s
    return s


def render_auction_seller(auction_id, stoken, msg="", err="", days=""):
    """Read-only, anonymized order book for the seller. Reachable with only a
    valid stoken -- no client magic link, no admin session -- and must never
    put a bidder's name, email or person_id anywhere in the response: not in
    visible text, not in an HTML comment, not in any JSON/JS embedded in the
    page. Bidders are identified purely by rank letter (Bidder A, B, ...)."""
    if not verify_seller_token(auction_id, stoken):
        return {"statusCode": 403, "headers": {"Content-Type": "text/plain"},
                "body": "forbidden"}

    auc = (_load_auctions() or {}).get(str(auction_id))
    if not auc:
        return html_response("<h1>Auction not found</h1>", 404, view="auction_seller")

    company = auc.get("company") or ""
    bids = _load_auction_bids(auction_id)
    ranked = sorted(bids.values(),
                    key=lambda b: (-(_auc_num(b.get("gross")) or 0),
                                   b.get("updated_at") or ""))
    top = _auc_num(ranked[0].get("gross")) if ranked else None

    _f = []
    if auc.get("structure"):
        _f.append(("Structure", html.escape(auc["structure"])))
    if auc.get("shares"):
        _f.append(("Shares", f"{int(_auc_num(auc['shares']) or 0):,}"))
    if auc.get("min_size"):
        _f.append(("Size", f'{_wl_money(auc.get("min_size"))} &ndash; '
                           f'{_wl_money(auc.get("max_size"))}'))
    _resv = _auc_num(auc.get("ask"))
    if _resv:
        _rmet = bool(top and top >= _resv)
        _f.append(("Reserve", f'<strong>{_wl_pps(_resv)}</strong> '
                              f'<span class="{"au-ok" if _rmet else "au-unmet"}">'
                              f'&middot; {"Met" if _rmet else "Unmet"}</span>'))
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

    header_html = (f'<div class="au-head"><div class="au-headtext"><h1>'
                   f'{html.escape(company)}'
                   f'{(" &mdash; " + html.escape(auc.get("structure"))) if auc.get("structure") else ""}'
                   f'</h1></div></div>')
    close_date = (auc.get("close_date") or "").strip()
    _is_past = bool(close_date) and not _auction_is_live(close_date)
    deadline_html = (f'<p class="au-deadline">Bids close '
                     f'{html.escape(_auc_date(auc.get("close_date")))}.</p>'
                     if auc.get("close_date") else "")

    _notice_html = ""
    if msg == "extended":
        _notice_html = (f'<p class="au-ok au-extnotice">Extended by {html.escape(str(days))} '
                        f'day{"" if str(days) == "1" else "s"} &mdash; bids now close '
                        f'{html.escape(_auc_date(auc.get("close_date")))}.</p>')
    elif err == "closed":
        _notice_html = ('<p class="au-bad au-extnotice">This auction has already closed '
                        'and can no longer be extended.</p>')
    elif err == "capped":
        _notice_html = ('<p class="au-bad au-extnotice">That extension would push bids '
                        'close more than 30 days past the original date, so it '
                        'wasn&#39;t applied.</p>')
    elif err == "invalid":
        _notice_html = '<p class="au-bad au-extnotice">That extension could not be applied.</p>'

    extend_html = ""
    if close_date and not _is_past:
        _sid = html.escape(str(auction_id), quote=True)
        _stok = html.escape(stoken, quote=True)
        _ext_btns = "".join(
            f'<form method="POST" action="?view=auction_seller&amp;id={_sid}&amp;stoken={_stok}"'
            ' class="au-extform">'
            f'<input type="hidden" name="auction_id" value="{_sid}">'
            f'<input type="hidden" name="stoken" value="{_stok}">'
            f'<input type="hidden" name="days" value="{d}">'
            f'<button type="submit" class="au-btn au-extbtn">+{d} days</button>'
            '</form>'
            for d in AUC_EXTEND_DAYS
        )
        extend_html = (
            '<div class="au-extend noprint">'
            '<div class="au-boxhead">Extend auction</div>'
            f'<div class="au-extrow">{_ext_btns}</div>'
            '</div>'
        )

    demand = sum(_auc_num(b.get("max_size")) or 0 for b in ranked)
    dem_line = (f'<p class="wl-soft">Total demand at max size: '
               f'<strong>{_wl_money(demand)}</strong> across {len(ranked)} '
               f'bid{"" if len(ranked) == 1 else "s"}.</p>') if ranked else ""

    rows = ""
    for i, b in enumerate(ranked, 1):
        if b.get("person_id"):
            cleared, _ = _auction_iqf(b["person_id"])
        else:
            cleared = False
        iqf_cell = ('<span class="au-ok">&#10003;</span>' if cleared
                    else '<span class="au-bad">&#10007;</span>')
        _coh = (b.get("cash_on_hand") or "")
        funding = "Funded" if _coh == "yes" else ("Syndicating" if _coh == "no" else "&mdash;")
        _gross = _auc_num(b.get("gross"))
        _mn = _auc_num(b.get("min_size"))
        _mx = _auc_num(b.get("max_size"))
        size_txt = (f'{_wl_money(_mn)} &ndash; {_wl_money(_mx)}' if (_mn or _mx) else "&mdash;")
        rows += (
            "<tr>"
            f"<td>{i}</td>"
            f"<td>Bidder {_seller_letter(i)}</td>"
            f'<td>{_wl_pps(_gross)}</td>'
            f"<td>{size_txt}</td>"
            f"<td>{iqf_cell}</td>"
            f"<td>{funding}</td>"
            f'<td>{html.escape((b.get("updated_at") or "")[:10])}</td>'
            "</tr>"
        )
    if not rows:
        rows = '<tr><td colspan="7" class="wl-soft">No bids yet.</td></tr>'
    book = ('<h2 class="wl-h2">Order book</h2>' + dem_line +
            '<table class="auc"><thead><tr><th>#</th><th>Bidder</th>'
            '<th>Bid ($/sh)</th><th>Size ($)</th><th>IQF</th><th>Funding</th>'
            '<th>Updated</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>')

    return html_response(f"""
    <style>
      .au-ok {{ color:#1f7a4d; font-weight:600; }}
      .au-bad {{ color:#b45309; font-weight:600; }}
      .au-unmet {{ color:#b91c1c; font-weight:600; }}
      .au-deadline {{ font-weight:600; margin:10px 0 0; }}
      .au-th {{ text-align:left; color:#6b7280; font-weight:600; padding:4px 12px 4px 0; }}
      .au-td {{ padding:4px 0; }}
      .au-ftable {{ margin:6px 0 16px; border-collapse:collapse; }}
      .auc {{ width:100%; border-collapse:collapse; margin-top:10px; }}
      .auc th, .auc td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }}
      .au-extend {{ margin:14px 0; padding:14px 16px; border:1px solid var(--line);
                    border-radius:10px; background:#fafaf8; }}
      .au-extrow {{ display:flex; gap:10px; margin-top:8px; flex-wrap:wrap; }}
      .au-extform {{ margin:0; }}
      .au-extbtn {{ padding:8px 16px; }}
      .au-extnotice {{ margin:0 0 12px; }}
      @media print {{
        .topnav, .gg-subnav, .gg-unav, button, .legal, .noprint {{ display:none !important; }}
        body {{ padding:0; }}
        .card {{ box-shadow:none; border:none; padding:0; max-width:none; }}
      }}
    </style>
    {header_html}
    {facts_rows}
    {deadline_html}
    {_notice_html}
    {extend_html}
    {book}
    """, eyebrow="Seller order book", view="auction_seller")


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

    # One slim tier line, only when a tier is set; the full status lives on Profile.
    tier_line = ""
    try:
        _st = _fetch_status_card_standing(client_id)
        if _st and _st.get("tier") is not None:
            _lbl = str(_st.get("tier_label") or _st.get("tier") or "").strip()
            try:
                _pct = f"{float(_st.get('discount_pct')):g}% off"
            except (TypeError, ValueError):
                _pct = ""
            _txt = " · ".join(x for x in (_lbl, _pct) if x)
            tier_line = ('<p class="wl-tierline" style="font-size:13px; margin-bottom:10px;">'
                         + html.escape(_txt) + (" · " if _txt else "")
                         + '<a href="?view=profile" style="color:var(--ink);">See your status &rarr;</a></p>')
    except Exception as e:
        print(f"watchlist status: tier line skipped: {e}")

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
    {tier_line}{body}
    """, is_admin=is_admin, view="watchlist_status", client_id=client_id)


def _handle_auction_seller_extend(event, qs):
    """POST from the seller view's own Extend auction buttons. Re-verifies
    the stoken -- constant-time, exactly like the GET -- before touching
    anything: the token is this route's only credential, so a forged or
    stale one gets the same flat 403 the GET would give, not a redirect
    that might echo it back. A rejected extension (already closed, over
    the 30-day cap, or a bad days value) still redirects back to the
    seller view, which shows a plain message -- never a stack trace."""
    form = _parse_body(event)
    auction_id = (qs.get("id") or form.get("auction_id") or "").strip()
    stoken = qs.get("stoken") or form.get("stoken") or ""
    if not auction_id or not verify_seller_token(auction_id, stoken):
        return {"statusCode": 403, "headers": {"Content-Type": "text/plain"},
                "body": "forbidden"}
    aucs = _load_auctions()
    auc = aucs.get(str(auction_id))
    if not auc:
        return {"statusCode": 404, "headers": {"Content-Type": "text/plain"},
                "body": "not found"}
    try:
        days = int(form.get("days") or "0")
    except ValueError:
        days = 0
    ok, err = _extend_auction(auc, days)
    _back = (f"?view=auction_seller&id={urllib.parse.quote(str(auction_id))}"
             f"&stoken={urllib.parse.quote(stoken)}")
    if ok:
        aucs[str(auction_id)] = auc
        _save_auctions(aucs)
        try:
            _notify_chad(
                f"Auction {auction_id} extended by seller to {_auc_date(auc['close_date'])}",
                (f"Company:    {auc.get('company') or '(unknown)'}\n"
                 f"Auction:    {auction_id}\n"
                 f"Extended:   +{days} days\n"
                 f"New close:  {auc['close_date']}\n"),
            )
        except Exception as e:
            print(f"auction_seller_extend: notify failed: {e}")
        _back += f"&msg=extended&days={days}"
    else:
        _back += f"&err={err}"
    return {"statusCode": 303, "headers": {"Location": _back}, "body": ""}


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

    # 1c) Seller view: read-only except for its own Extend-auction POST, both
    #     reachable with only a valid stoken -- no client magic link, no admin
    #     session. Must come before the session gate below.
    if qs.get("view") == "auction_seller" and qs.get("id"):
        if method == "POST":
            return _handle_auction_seller_extend(event, qs)
        return render_auction_seller(qs["id"], qs.get("stoken") or "",
                                     qs.get("msg") or "", qs.get("err") or "",
                                     qs.get("days") or "")

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
        # Sellers-sharing consent from the Profile card. Only ever the signed-in
        # client's OWN person_id; an admin viewing as a client (?as= or a
        # magic-link session swap) is refused -- consent must come from the client.
        if action == "standing_share":
            if is_admin and not effective_admin:
                return {"statusCode": 303, "headers": {"Location": raw_path + "?view=profile"}, "body": ""}
            ok = _post_standing_share(client_id, form.get("share") == "1") is not None
            return {"statusCode": 303,
                    "headers": {"Location": raw_path + "?view=profile" + ("" if ok else "&share_err=1")},
                    "body": ""}
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
            _min_bump = None       # set below when the increment rule rejects this bid
            if _aid and _email and not _bad_bid:
                _auc_rec = (_load_auctions() or {}).get(_aid) or {}
                _prior_bids = _load_auction_bids(_aid)
                _existing = _prior_bids.get(_email)
                _prior_top = max((_auc_num(b.get("gross")) or 0
                                  for b in _prior_bids.values()), default=0)
                # Minimum bid increment, bidder-facing submit only (admin's in-place
                # order-book edit calls _save_auction_bid directly and never runs this
                # check). A raise on an existing bid must clear old price + increment;
                # a brand-new bid only has to clear it when it would land ABOVE the
                # current top -- landing at or below the top is always allowed, since
                # this is an order book, not a single ascending clock.
                if _existing:
                    _old_gross = _auc_num(_existing.get("gross")) or 0
                    if _gross > _old_gross:
                        _inc = _auc_increment(_auc_rec, _old_gross)
                        if _gross < _old_gross + _inc:
                            _min_bump = _inc
                elif _prior_top and _gross > _prior_top:
                    _inc = _auc_increment(_auc_rec, _prior_top)
                    if _gross < _prior_top + _inc:
                        _min_bump = _inc
            if _aid and _email and not _bad_bid and _min_bump is None:
                _bid = {
                    "gross": _gross,
                    "min_size": _auc_num(form.get("min_size")),
                    "max_size": _auc_num(form.get("max_size")),
                    "cash_on_hand": "no" if (form.get("cash_on_hand") == "no") else "yes",
                    "note": (form.get("note") or "").strip(),
                    "alert_on_higher_bid": form.get("alert_on_higher_bid") == "on",
                    "person_id": str(_owner),
                }
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
            elif _min_bump is not None:
                _back += "&err=increment&min_bump=" + urllib.parse.quote(f"{_min_bump:.2f}")
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
                _rec["share_class"] = (form.get("share_class") or "").strip()
                _rec["note"] = (form.get("note") or "").strip()
                _rec["close_date"] = (form.get("close_date") or "").strip()
                for _k in ("shares", "min_size", "max_size", "ask", "min_increment"):
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
            _cr_company = (form.get("company") or "").strip()
            _cr_deal_id = (form.get("deal_id") or "").strip()
            # Any of these left blank on the create form get filled from the
            # seed deal; anything the admin actually typed is kept as-is.
            _cr_pre = _auction_deal_prefill(_cr_deal_id, _cr_company)
            _cr_ask = _auc_num(form.get("ask"))
            _cr_shares = _auc_num(form.get("shares"))
            _cr_structure = (form.get("structure") or "").strip()
            _cr_share_class = (form.get("share_class") or "").strip()
            _cr_min_size = _auc_num(form.get("min_size"))
            _cr_max_size = _auc_num(form.get("max_size"))
            _auc[_aid] = {
                "company": _cr_company,
                "deal_id": _cr_deal_id,
                "ask": _cr_ask if _cr_ask is not None else _cr_pre["price"],
                "shares": _cr_shares if _cr_shares is not None else _cr_pre["shares"],
                "structure": _cr_structure or _cr_pre["structure"],
                "share_class": _cr_share_class or _cr_pre["share_class"],
                "close_date": (form.get("close_date") or "").strip(),
                "buyers": _auc_num(form.get("buyers")),
                "min_size": _cr_min_size if _cr_min_size is not None else _cr_pre["min_size"],
                "max_size": _cr_max_size if _cr_max_size is not None else _cr_pre["max_size"],
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
                              qs.get("err") or "", qs.get("min_bump") or "")
    if qs.get("view") == "auction_list":
        return render_auction_list(view_id, effective_admin)
    if qs.get("view") == "demand":
        return render_demand_board(view_id, effective_admin)
    if qs.get("view") == "profile":
        return render_profile(view_id, effective_admin, viewing_as=(is_admin and not effective_admin),
                              share_err=qs.get("share_err") == "1")
    if qs.get("view") == "admin" and is_admin:
        return render_admin_hub()
    if qs.get("view") == "auctions" and is_admin:
        return render_auctions_admin()
    if qs.get("view") == "auctions":
        return render_live_auctions_overview(view_id)
    if qs.get("view") == "sendlink" and is_admin:
        return render_send_link()
    if qs.get("view") == "engagement" and is_admin:
        return _engagement_route(qs)
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
                      f"&token={sign_id(TRADE_UPDATE_SECRET, _dl_id)}") if (_dl_id and TRADE_UPDATE_SECRET) else ""
        _dl_update_err = "" if TRADE_UPDATE_SECRET else (
            "The FORM_HMAC_SECRET environment variable is not set on this Lambda, "
            "so update-form links can't be signed here.")
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
                                    "update_error": _dl_update_err,
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


# Hidden static page at ?view=commission-tiers. Public (no cookie/token), not
# linked from anywhere. Plain string, not an f-string: the CSS braces are literal.
COMMISSION_TIERS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Client Commission Tiers — Chad Gracia</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">
<style>
/* Layout: two letter-size sheets on a document-viewer grey, set like a formal client memo */
:root {
  --desk: #e6e8eb;
  --paper: #ffffff;
  --ink: #16202b;
  --muted: #5b6673;
  --rule: #e2e6ea;
  --navy: #1d3a5c;
  --check: #2e7d4f;
  --open: #aab3bd;
  --tint: #f5f7f9;
  --serif: "Source Serif 4", Georgia, "Times New Roman", serif;
  --sans: "IBM Plex Sans", -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace;
  color-scheme: light;
}
*, *::before, *::after { box-sizing: border-box; }
body { margin: 0; background: var(--desk); color: var(--ink); font-family: var(--sans); font-size: 15px; line-height: 1.55; }
.viewer { padding-inline: 16px; padding-block: 32px 48px; display: flex; flex-direction: column; align-items: center; gap: 28px; }
.sheet { background: var(--paper); width: 100%; max-width: 816px; min-height: 1056px; box-shadow: 0 1px 3px rgba(20,30,45,.12), 0 8px 24px rgba(20,30,45,.10); padding-inline: clamp(24px, 8vw, 72px); padding-block: 56px 40px; display: flex; flex-direction: column; gap: 32px; }
.sheet-body { display: flex; flex-direction: column; gap: 32px; flex: 1; }
.head { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); border-bottom: 2px solid var(--navy); padding-bottom: 10px; }
.head b { color: var(--navy); font-weight: 600; }
.foot { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; font-size: 11px; color: var(--muted); border-top: 1px solid var(--rule); padding-top: 10px; font-variant-numeric: tabular-nums; }
h1, h2 { font-family: var(--serif); font-weight: 600; text-wrap: balance; color: var(--ink); margin: 0; }
h1 { font-size: clamp(28px, 5vw, 36px); line-height: 1.15; }
h2 { font-size: 21px; line-height: 1.25; }
p { margin: 0; max-width: 68ch; }
.stack { display: flex; flex-direction: column; gap: 12px; }
.lede { font-family: var(--serif); font-size: 18px; line-height: 1.6; }
.sig { font-family: var(--serif); font-style: italic; color: var(--muted); }
.eyebrow { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); font-weight: 500; }

ul.checks { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; border-top: 1px solid var(--rule); }
ul.checks li { display: grid; grid-template-columns: 26px 1fr; gap: 10px; padding: 9px 0; border-bottom: 1px solid var(--rule); align-items: start; }
ul.checks li > div { min-width: 0; }
.note { display: block; font-size: 13px; color: var(--muted); }
.mark { width: 20px; height: 20px; margin-top: 2px; border-radius: 50%; display: grid; place-items: center; }
.mark.on { background: var(--check); }
.mark.on svg { width: 12px; height: 12px; fill: none; stroke: var(--paper); stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round; }
.mark.off { border: 2px solid var(--open); }

.tiers { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
@media (max-width: 640px) { .tiers { grid-template-columns: 1fr; } }
.tier { border: 1px solid var(--rule); border-radius: 4px; padding: 18px; display: flex; flex-direction: column; gap: 8px; }
.tier .name { font-family: var(--serif); font-size: 19px; font-weight: 600; }
.tier .pct { font-family: var(--mono); font-size: 24px; color: var(--navy); font-weight: 500; line-height: 1.1; }
.tier .pct small { font-family: var(--sans); font-size: 12px; color: var(--muted); font-weight: 400; }
.tier ul { margin: 0; padding-left: 16px; font-size: 14px; display: flex; flex-direction: column; gap: 5px; }
.tier .req { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); }

.twotables { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr); gap: 28px; }
@media (max-width: 640px) { .twotables { grid-template-columns: 1fr; } }
.tablebox { overflow-x: auto; display: flex; flex-direction: column; gap: 8px; }
.tablebox .cap { font-size: 12px; font-weight: 600; color: var(--navy); }
table { border-collapse: collapse; width: 100%; font-size: 14px; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: 7px 10px 7px 0; border-bottom: 1px solid var(--rule); white-space: nowrap; }
th { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); font-weight: 500; }
td.num, th.num { text-align: right; font-family: var(--mono); padding-right: 0; padding-left: 10px; }
tr.base td { font-weight: 600; }

.status { background: var(--tint); border: 1px solid var(--rule); border-radius: 4px; padding: 22px; display: flex; flex-direction: column; gap: 14px; }
.status-head { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 8px; }
.status-head .who { font-family: var(--serif); font-size: 19px; font-weight: 600; }
.pill { font-size: 12px; font-weight: 600; color: var(--navy); border: 1px solid var(--navy); border-radius: 999px; padding: 2px 11px; }
.sample { font-size: 11px; color: var(--muted); letter-spacing: .06em; text-transform: uppercase; }
.status ul.checks, .status ul.checks li { border-color: #dde2e7; }
.next { font-size: 14px; }
.next b { color: var(--navy); }

.fine { font-size: 12px; color: var(--muted); display: flex; flex-direction: column; gap: 8px; }
.fine p { max-width: none; }
.disc { font-size: 10.5px; line-height: 1.5; color: var(--muted); border-top: 1px solid var(--rule); padding-top: 14px; display: flex; flex-direction: column; gap: 7px; }
.disc p { max-width: none; }
.disc .h { font-weight: 600; letter-spacing: .06em; color: var(--ink); }
</style>
</head>
<body>
<div class="viewer">

  <!-- Page 1 -->
  <article class="sheet">
    <div class="sheet-body">
      <section class="stack">
        <h1>Client Commission Tiers</h1>
        <p class="lede">For years, I've reduced commissions for clients who make transactions smooth for everyone involved. To make that process fair and consistent, I've written down what goes into the decision.</p>
        <p>As always, every trade and commission goes through Rainmaker Securities, LLC and is documented on Rainmaker's forms. The criteria below are the same for every client. <strong>These reductions apply only to trades handled by Chad Gracia, a registered representative of Rainmaker Securities, LLC. They do not apply to trades with any other Rainmaker representative, and they do not change any other agreement you have with Rainmaker.</strong></p>
        <p class="sig">— Chad Gracia</p>
      </section>

      <section class="stack">
        <div class="eyebrow">Required for every tier</div>
        <h2>Good standing</h2>
        <p>These are the basics that let sellers take an introduction seriously. Many are required by Rainmaker before any work can be done on your behalf or introductions made. New clients start in good standing on everything except the two forms.</p>
        <ul class="checks">
          <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Identity and compliance forms complete</div></li>
          <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Investor qualification on file</div></li>
          <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Honors agreed terms through closing<span class="note">Price, size and commission stay as agreed once terms are set.</span></div></li>
          <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Meets all payment deadlines<span class="note">Both the investment and the commission.</span></div></li>
          <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Responds promptly after an introduction<span class="note">A reply to the seller within 3 business days. A clear "pass" counts as a reply.</span></div></li>
        </ul>
      </section>

      <section class="stack">
        <div class="eyebrow">Reductions from the original commission</div>
        <h2>Three tiers</h2>
        <div class="tiers">
          <div class="tier">
            <div class="name">Preferred</div>
            <div class="pct">10% <small>off</small></div>
            <div class="req">Requires</div>
            <ul>
              <li>Good standing</li>
              <li>Introduced another new accredited investor who completed onboarding with Rainmaker</li>
            </ul>
            <div class="req">Includes</div>
            <ul>
              <li>A 30-minute strategy call on your goals and how I can help</li>
            </ul>
          </div>
          <div class="tier">
            <div class="name">Gold</div>
            <div class="pct">15% <small>off</small></div>
            <div class="req">Requires</div>
            <ul>
              <li>Good standing</li>
              <li>$5M or more in completed trades</li>
            </ul>
            <div class="req">Includes</div>
            <ul>
              <li>Early look at new blocks</li>
              <li>Strategy calls whenever you need them</li>
            </ul>
          </div>
          <div class="tier">
            <div class="name">Platinum</div>
            <div class="pct">20% <small>off</small></div>
            <div class="req">Requires</div>
            <ul>
              <li>Good standing</li>
              <li>$10M or more in completed trades, or 3 or more trades</li>
            </ul>
            <div class="req">Includes</div>
            <ul>
              <li>Everything in Gold</li>
              <li>When you ask me to find a specific position, I won't offer what I find to my other buyers for 30 days</li>
            </ul>
          </div>
        </div>
      </section>
    </div>
    <div class="foot"><span>Client Commission Tiers · September 2026</span><span>Page 1 of 2</span></div>
  </article>

  <!-- Page 2 -->
  <article class="sheet">
    <div class="sheet-body">
      <section class="stack">
        <div class="eyebrow">Worked example</div>
        <h2>A $2M purchase</h2>
        <p>Reductions apply only to trades handled by Chad Gracia through Rainmaker Securities, LLC.</p>
        <div class="twotables">
          <div class="tablebox">
            <div class="cap">Usual commission</div>
            <table>
              <thead><tr><th>Transaction size</th><th class="num">Rate</th></tr></thead>
              <tbody>
                <tr><td>Up to $1M</td><td class="num">5.0%</td></tr>
                <tr><td>$1M – $5M</td><td class="num">4.0%</td></tr>
                <tr><td>$5M – $10M</td><td class="num">3.5%</td></tr>
                <tr><td>Over $10M</td><td class="num">2.5%</td></tr>
              </tbody>
            </table>
            <p class="note">Each deal's commission is set in its agreement with the seller and may differ from these.</p>
          </div>
          <div class="tablebox">
            <div class="cap">On a $2M purchase</div>
            <table>
              <thead><tr><th>Status</th><th class="num">Rate</th><th class="num">Commission</th><th class="num">Savings</th></tr></thead>
              <tbody>
                <tr class="base"><td>Original commission</td><td class="num">4.00%</td><td class="num">$80,000</td><td class="num">—</td></tr>
                <tr><td>Preferred</td><td class="num">3.60%</td><td class="num">$72,000</td><td class="num">$8,000</td></tr>
                <tr><td>Gold</td><td class="num">3.40%</td><td class="num">$68,000</td><td class="num">$12,000</td></tr>
                <tr><td>Platinum</td><td class="num">3.20%</td><td class="num">$64,000</td><td class="num">$16,000</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section class="stack">
        <div class="status">
          <div class="status-head">
            <span class="who">Sample status</span>
            <span class="pill">Preferred</span>
          </div>
          <ul class="checks">
            <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Identity and compliance forms complete</div></li>
            <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Investor qualification on file</div></li>
            <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Honors agreed terms through closing</div></li>
            <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Meets all payment deadlines</div></li>
            <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Responds promptly after an introduction</div></li>
            <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Introduced a new accredited investor<span class="note">1 completed onboarding with Rainmaker</span></div></li>
            <li><span class="mark on"><svg viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 5"/></svg></span><div>Completed trades</div></li>
          </ul>
          <p class="next">See something that looks wrong? Reply to any of my emails and I'll correct it.</p>
        </div>
      </section>

      <section class="fine">
        <p>An introduced investor counts once they complete onboarding with Rainmaker and are verified as accredited or higher. Introductions of household members, related entities or colleagues at the same firm don't count.</p>
        <p>Each deal's commission is set in Rainmaker's agreement with the seller and is usually built into the purchase price. Reductions apply only to Rainmaker commissions on trades handled by Chad Gracia and are confirmed in writing with the seller through a revised commission schedule or side letter, which lowers the price you pay without changing the seller's proceeds. They do not apply to trades with other Rainmaker representatives.</p>
        <p>Before or after introducing you to a seller, I may mention which good-standing items you've completed and whether you've completed trades with me, as sellers often ask about these when deciding on allocations. I never share trade sizes, referral information or anything else about your account.</p>
      </section>

      <section class="disc">
        <p>DISCLOSURE: Chad Gracia ("Gracia") is a principal of The Gracia Group, Inc. ("Gracia Group") and a registered agent of Rainmaker Securities, LLC ("RMS"). Gracia Group is a consulting firm and outside business activity of Gracia. Gracia Group is not affiliated with RMS. RMS is a FINRA registered broker-dealer and SIPC member. Find this broker-dealer and its agents on BrokerCheck. Our relationship summary can be found on the RMS website. All securities transactions conducted by Chad Gracia will be conducted via RMS.</p>
        <p>RMS is engaged by its clients to make referrals to buyers or sellers of private securities ("Securities"). If such client closes a Securities transaction with a buyer or seller so referred, RMS is entitled to a success fee from the client. Such success fee may be in the form of cash or in warrants to purchase securities of the client or client's affiliate. RMS or RMS representatives may hold equity in its issuer clients or in the issuers of securities purchased or sold by the parties to a transaction.</p>
        <p>This communication is confidential and is addressed only to its intended recipient. This communication does not represent an offer or solicitation to buy or sell Securities. Such an offer must be made via definitive legal documentation by the seller of securities. RMS does not recommend the purchase or sale of Securities. Potential buyers or sellers of the Securities should seek professional counsel prior to entering into any transaction.</p>
        <p class="h">RISK FACTORS</p>
        <p>Investments in the Securities are speculative and involve a high degree of risk. Companies engaging in private placements may be early stage and high risk. You should be able to afford the increased risk of loss with such investments, including the potential of a total loss. An investor in the Securities should have little to no need for liquidity in the foreseeable future. Unlike an investment purchased on a stock exchange, an investment in a private placement is highly illiquid. You will most likely be investing in restricted securities, may have difficulty finding a buyer for the securities when you can resell and, as a result, may need to hold the securities indefinitely.</p>
        <p>Limited disclosure information. Companies engaging in private placements are not required to provide the disclosure that would be required in a registered offering. You may have less information to make an informed investment decision than, for example, stock purchased on a stock exchange, including information that may help you determine whether the price asked for the investment is a fair price.</p>
      </section>
    </div>
    <div class="foot"><span>Client Commission Tiers · September 2026</span><span>Page 2 of 2</span></div>
  </article>

</div>
</body>
</html>
"""


def lambda_handler(event, context):
    """Thin shell around _route: renders the "viewing as" bar whenever the browser
    carries a valid admin cookie but the session cookie points at somebody else.
    Done here, once, rather than threaded through every render_* function — the bar
    is a property of the request, not of any particular page. Failures are swallowed:
    a missing bar must never cost the user their page."""
    # Old Syndicate Dash address: permanent redirect to /blockbook, ahead of all
    # other routing. Exact prefix only (/dashboards, /dashboard-x fall through).
    raw_path = event.get("rawPath") or "/"
    if raw_path == "/dashboard" or raw_path.startswith("/dashboard/"):
        dest = "https://desk.graciagroup.com/blockbook" + raw_path[len("/dashboard"):]
        qs = event.get("rawQueryString") or ""
        if qs:
            dest += "?" + qs
        return {"statusCode": 301, "headers": {"Location": dest}, "body": ""}
    # Hidden static page: served before any session/magic-link/admin handling and
    # before the viewing-as bar, so no cookie is read or set. GET only.
    method = (event.get("requestContext", {}).get("http", {}).get("method") or "GET").upper()
    if method == "GET" and (event.get("queryStringParameters") or {}).get("view") == "commission-tiers":
        return {"statusCode": 200,
                "headers": {"Content-Type": "text/html; charset=utf-8",
                            "Cache-Control": "max-age=300",
                            "X-Robots-Tag": "noindex, nofollow"},
                "body": COMMISSION_TIERS_HTML}
    # Admin "view as" persistence. An admin's explicit ?as=<id> is remembered in
    # a signed gg_view_as cookie so every desk tab and in-page link (which carry
    # no ?as=) keeps the viewed client until "back to admin" (resume_admin) or
    # sign-out clears it. For anyone without admin privilege the param is
    # dropped and the cookie is never read or set.
    qs_in = event.get("queryStringParameters") or {}
    own_admin = None
    view_as = None
    va_cookie = None
    try:
        own_admin = _request_admin_id(event)
        if qs_in.get("view") == "resume_admin" or qs_in.get("signout") == "1":
            va_cookie = _cookie(VIEW_AS_COOKIE_NAME, "", 0)
        elif own_admin:
            explicit = (qs_in.get("as") or "").strip()
            if explicit == own_admin:
                va_cookie = _cookie(VIEW_AS_COOKIE_NAME, "", 0)
            elif explicit:
                view_as = explicit
                if explicit.isdigit():
                    va_cookie = _cookie(VIEW_AS_COOKIE_NAME, make_view_as_cookie(own_admin, explicit),
                                        VIEW_AS_DAYS)
            else:
                view_as = read_view_as_cookie(get_cookie(event, VIEW_AS_COOKIE_NAME), own_admin)
                if view_as:
                    event = dict(event, queryStringParameters=dict(qs_in, **{"as": view_as}))
        elif "as" in qs_in:
            event = dict(event, queryStringParameters={k: v for k, v in qs_in.items() if k != "as"})
    except Exception as e:
        print(f"view-as handling skipped: {e}")
        view_as = None
    resp = _route(event, context)
    if va_cookie:
        resp["cookies"] = list(resp.get("cookies") or []) + [va_cookie]
    try:
        if own_admin and view_as and view_as != own_admin:
            headers = resp.get("headers") or {}
            body = resp.get("body") or ""
            anchor = '<div class="card">'
            if "text/html" in headers.get("Content-Type", "") and anchor in body:
                resp["body"] = body.replace(anchor, anchor + _viewing_as_bar(view_as), 1)
            return resp
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
