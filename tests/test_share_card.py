"""Profile sharing card copy (where a client's badges/standing are shown).

lambda_function.py reads S3 at import time, so the card's code is pulled out
with ast and run on its own. Run: python3 tests/test_share_card.py"""
import ast
import html
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "lambda_function.py")
NEEDED = {"_CTS_TICK", "_SHARE_PREVIEW_SKIP_KEYS", "_SHARE_PREVIEW_SKIP",
          "SHARE_COPY_NAMED", "_share_audience", "_share_card_html"}

tree = ast.parse(open(SRC).read())
nodes = []
for n in tree.body:
    names = ({n.name} if isinstance(n, ast.FunctionDef) else
             {t.id for t in getattr(n, "targets", []) if isinstance(t, ast.Name)})
    if names & NEEDED:
        nodes.append(n)
ns = {"html": html}
exec(compile(ast.Module(body=nodes, type_ignores=[]), SRC, "exec"), ns)

failures = 0


def check(name, cond):
    global failures
    print(("PASS: " if cond else "FAIL: ") + name)
    failures += 0 if cond else 1


NAMED = "Your name and track record are shared only with counterparties you\u2019re introduced to."
check("copy constant matches the agreed wording", ns["SHARE_COPY_NAMED"] == NAMED)
check("no qualification-visibility constant left", "SHARE_COPY_QUALIFICATION" not in open(SRC).read())

buyer = ns["_share_card_html"]({"roles": {"buyer": True, "seller": False}, "items": []})
seller = ns["_share_card_html"]({"roles": {"buyer": False, "seller": True}, "items": []})
on = ns["_share_card_html"]({"roles": {"buyer": True}, "share_with_sellers": True,
                             "items": [{"key": "terms", "label": "Honors agreed terms", "done": True}]})
FORBIDDEN = ("qp", "accredited", "qualification level", "shown anonymously", "anonymous", "no one else",
             "nothing is shown", "nothing else", "not visible", "never sees", "matched", "without your name")
for label, card in (("buyer", buyer), ("seller-only", seller), ("sharing on", on)):
    low = card.lower()
    check(f"{label} card: carries the name/track-record line", html.escape(NAMED) in card)
    check(f"{label} card: no QP/Accredited visibility copy and nothing implying zero visibility before introduction",
          not any(t in low for t in FORBIDDEN))

src_text = open(SRC).read()
check("Commission Tiers page: no 'anything else about your account' (would imply nothing else is visible)",
      "anything else about your account" not in src_text
      and "I never share trade sizes or referral information." in src_text)

sys.exit(1 if failures else 0)
