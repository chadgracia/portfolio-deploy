"""Admin hub layout and the Blockbook card.

lambda_function.py reads S3 at import time, so the hub's code is pulled out with
ast and run on its own, with html_response, _people_index and urlopen stubbed.
Run: python3 tests/test_admin_hub.py"""
import ast
import html
import io
import json
import os
import re
import sys
import urllib.parse
import urllib.request

SRC = os.path.join(os.path.dirname(__file__), "..", "lambda_function.py")
NEEDED = {"ADMIN_BRIEF_URL", "ADMIN_MAILER_URL", "ADMIN_PRICING_URL", "ADMIN_KEY", "_ADMIN_KEY_QS",
          "ADMIN_ALERTS_URL", "SYNDICATE_DASH_URL", "WHATSAPP_ADMIN_KEY", "WHATSAPP_CAPTURE_URL",
          "BLOCKBOOK_SEARCH_SCRIPT", "_blockbook_tenants", "_blockbook_card_html",
          "_hub_cards_html", "render_admin_hub"}
SRC_TEXT = open(SRC).read()
tree = ast.parse(SRC_TEXT)
nodes = []
for n in tree.body:
    names = ({n.name} if isinstance(n, ast.FunctionDef) else
             {t.id for t in getattr(n, "targets", []) if isinstance(t, ast.Name)})
    if names & NEEDED:
        nodes.append(n)
CODE = compile(ast.Module(body=nodes, type_ignores=[]), SRC, "exec")

PEOPLE = {"by_email": {"natoli@mangustacap.com": "7"},
          "by_id": {"7": {"email": "natoli@mangustacap.com", "first_name": "Nat", "name": "Nat Oli"}}}


def load(admin_key="k*1", whatsapp_key="w1", payload=None, fail=False):
    os.environ["ADMIN_KEY"] = admin_key
    os.environ["WHATSAPP_ADMIN_KEY"] = whatsapp_key
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        if fail:
            raise OSError("boom")
        return io.BytesIO(json.dumps(payload).encode())

    class FakeUrllib:
        parse = urllib.parse
        request = type("R", (), {"Request": urllib.request.Request, "urlopen": staticmethod(fake_urlopen)})

    ns = {"html": html, "json": json, "os": os, "urllib": FakeUrllib,
          "html_response": lambda body, **kw: body, "_people_index": lambda: PEOPLE}
    exec(CODE, ns)
    return ns, calls


failures = 0


def check(name, cond):
    global failures
    print(("PASS: " if cond else "FAIL: ") + name)
    failures += 0 if cond else 1


PAYLOAD = {"count": 4, "tenants": [
    {"email": "michael@nonpublic.io", "name": "Michael Smith", "firm": "Nonpublic"},
    {"email": "a@alignvc.com", "name": "Zed Able", "firm": "Align Ventures", "group": "x"},
    {"email": "b@alignvc.com", "name": "Amy Bee", "firm": "Align Ventures"},
    {"email": "natoli@mangustacap.com", "name": "", "firm": ""},
    {"email": "x@y.com"},
]}

ns, calls = load(payload=PAYLOAD)
page = ns["render_admin_hub"]()
dash = ns["SYNDICATE_DASH_URL"]

# Section order + archived <details>
labels = re.findall(r'class="hub-label">([^<]*)<', page)
check("section labels in order",
      labels == ["Blockbook", "Daily", "Mailers", "Clients &amp; pricing", "Archived (2)"])
check("archived is a collapsed <details> at the bottom",
      re.search(r'<details class="hub-archived"><summary[^>]*>Archived \(2\)</summary>', page) is not None
      and " open" not in page.split("<details")[1].split(">")[0])
titles = re.findall(r'class="hub-title">(?:<span class="hub-icon">[^<]*</span>)?([^<]*)<', page)
check("card order", titles == ["Blockbook", "Daily brief", "Deal alerts", "Deal List Writer", "Send a link",
                               "WhatsApp capture", "News mailer composer", "Weekly mailer recipients",
                               "Client Standing", "Research gaps", "Auctions", "Third-party pricing",
                               "Engagement Docs", "All portfolios"])
archived = page.split("<details")[1]
check("archived cards muted but still links",
      archived.count('class="hub-card hub-card-muted" href=') == 2 and ".hub-card-muted {{ opacity:.6; }}" in SRC_TEXT)
check("Engagement Docs description carries 'Not approved for use.'",
      "Preview only for now. Not approved for use." in archived)
check("Third-party pricing title + description unchanged",
      '<div class="hub-title">Third-party pricing</div>'
      '<div class="hub-desc">Update Hiive bid, ask and mark for tracked names.</div>' in page)
check("no 'Syndicator Dashboard' card left", "Syndicator Dashboard" not in page)

# Blockbook card from a mocked tenants=list payload
check("fetched syndicate-dash ?tenants=list", calls == [dash + "&tenants=list"])
check("count shows N sellers", "5 sellers" in page)
check("search input present and enabled",
      re.search(r'<input id="bb-search"[^>]*>', page) and "disabled" not in re.search(r'<input id="bb-search"[^>]*>', page).group(0))
rows = re.findall(r'<li class="syn-row"[^>]*>.*?</li>', page)
check("one row per tenant", len(rows) == 5)
for email in ("michael@nonpublic.io", "a@alignvc.com", "natoli@mangustacap.com"):
    mine = dash + "&view_as=" + urllib.parse.quote(email)
    check(f"{email}: My Deals + Intros links, new tab",
          f'href="{html.escape(mine, quote=True)}" target="_blank" rel="noopener">My Deals</a>' in page
          and f'href="{html.escape(mine + "&tab=intros", quote=True)}" target="_blank" rel="noopener">Intros</a>' in page)
names = [re.search(r'class="syn-name">([^<]*)<', r).group(1) for r in rows]
check("sorted by company then name (blank company first)",
      names == ["Nat Oli", "x@y.com", "Amy Bee", "Zed Able", "Michael Smith"])
check("missing name filled from _people_index by email", "Nat Oli" in names)
check("missing everywhere: email alone", '<span class="syn-name">x@y.com</span> &middot; <a' in page)
check("rows carry lowercase search text incl. email",
      'data-q="michael smith nonpublic michael@nonpublic.io"' in page)
check("search script filters and opens first visible My Deals on Enter",
      "data-q" in ns["BLOCKBOOK_SEARCH_SCRIPT"] and '"Enter"' in ns["BLOCKBOOK_SEARCH_SCRIPT"]
      and "a.syn-deals" in ns["BLOCKBOOK_SEARCH_SCRIPT"] and "_blank" in ns["BLOCKBOOK_SEARCH_SCRIPT"])
check("scroll box kept", ".syn-list {{ list-style:none; max-height:280px; overflow-y:auto;" in SRC_TEXT)

# No card URL changed
k = urllib.parse.quote("k*1", safe="")
EXPECTED = [
    f"https://ws4stw4iul75a7yx5dra2wmnq40kipav.lambda-url.us-east-1.on.aws/?key={k}",
    "https://bddpwqsqvt32ritxpjqlqwhaim0ykbol.lambda-url.us-east-1.on.aws/?key=alkj%2A707q235-qjdf",
    f"https://3m3tx5bqrdvddzsyjitnjiipjy0hftoe.lambda-url.us-east-1.on.aws/?key={k}",
    "https://izahxskgeee5mihwi7y62v333q0ajkji.lambda-url.us-east-1.on.aws/?key=Vq83RkPnZ2wYhT6d",
    "?view=sendlink",
    "https://scrqjg5mbppzctgagxbslh7yve0fbzyp.lambda-url.us-east-1.on.aws/?key=w1",
    "https://bddpwqsqvt32ritxpjqlqwhaim0ykbol.lambda-url.us-east-1.on.aws/?view=news&key=alkj%2A707q235-qjdf",
    "https://bddpwqsqvt32ritxpjqlqwhaim0ykbol.lambda-url.us-east-1.on.aws/?key=alkj%2A707q235-qjdf&view=mailer",
    f"https://ws4stw4iul75a7yx5dra2wmnq40kipav.lambda-url.us-east-1.on.aws/?key={k}&view=standing",
    f"https://ws4stw4iul75a7yx5dra2wmnq40kipav.lambda-url.us-east-1.on.aws/?key={k}&view=research_gaps",
    "?view=auctions",
    "https://jw2kk4a73jbft32yf5lr7u22bm0bgkiy.lambda-url.us-east-1.on.aws/",
    "?view=engagement",
    "?view=portfolios",
]
card_links = re.findall(r'<a class="(?:hub-card[^"]*|syn-admin)" href="([^"]*)" target="_blank" rel="noopener">', page)
check("every card URL unchanged, all target=_blank",
      [html.unescape(u) for u in card_links] == EXPECTED)

# Failed and empty fetch -> disabled state, page still renders
for label, kw in (("failed fetch", {"fail": True}), ("empty list", {"payload": {"count": 0, "tenants": []}}),
                  ("bad payload", {"payload": ["nope"]})):
    ns2, _ = load(**kw)
    p2 = ns2["render_admin_hub"]()
    inp = re.search(r'<input id="bb-search"[^>]*>', p2)
    check(f"{label}: card renders with disabled input + 'Tenant list unavailable'",
          inp is not None and "disabled" in inp.group(0) and "Tenant list unavailable" in p2
          and "<li class=\"syn-row\"" not in p2 and "Daily brief" in p2)

# ADMIN_KEY unset -> Blockbook greyed out, no input, no fetch; Client Standing greyed as before
ns3, calls3 = load(admin_key="", payload=PAYLOAD)
p3 = ns3["render_admin_hub"]()
check("no key: Blockbook greyed out, no input, no fetch",
      '<div class="hub-card hub-card-off syn-card"><div class="hub-title">Blockbook</div></div>' in p3
      and "bb-search" not in p3 and calls3 == [])
check("no key: Client Standing greyed out, Deal alerts omitted",
      '<div class="hub-card hub-card-off"><div class="hub-title"><span class="hub-icon">🏆</span>Client Standing</div>' in p3
      and "Deal alerts" not in p3)

check("syndicator_eligible_sellers removed", "def syndicator_eligible_sellers" not in SRC_TEXT)

sys.exit(1 if failures else 0)
