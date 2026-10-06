"""Profile sharing card copy (where a client's badges/standing are shown).

lambda_function.py reads S3 at import time, so the card's code is pulled out
with ast and run on its own. Run: python3 tests/test_share_card.py"""
import ast
import html
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "lambda_function.py")
NEEDED = {"_CTS_TICK", "_SHARE_PREVIEW_SKIP_KEYS", "_SHARE_PREVIEW_SKIP", "SHARE_COPY_QUALIFICATION",
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


QUAL = ("Your qualification level (QP or Accredited) is shown anonymously to sellers "
        "so they can confirm you’re eligible for their deal.")
NAMED = "Your name and track record are shared only with counterparties you’re introduced to."
check("copy constants match the agreed wording",
      ns["SHARE_COPY_QUALIFICATION"] == QUAL and ns["SHARE_COPY_NAMED"] == NAMED)

buyer = ns["_share_card_html"]({"roles": {"buyer": True, "seller": False}, "items": []})
seller = ns["_share_card_html"]({"roles": {"buyer": False, "seller": True}, "items": []})
check("buyer card: both lines (qualification shown anonymously; name + track record only to introduced)",
      html.escape(QUAL) in buyer and html.escape(NAMED) in buyer)
check("seller-only card: only the name/track-record line (no qualification pill is shown to buyers)",
      html.escape(QUAL) not in seller and html.escape(NAMED) in seller)
for label, card in (("buyer", buyer), ("seller-only", seller)):
    check(f"{label} card: no 'matched' wording left (title, aria-label, preview heading, fine print)",
          "matched" not in card.lower() and "without your name" not in card and "introduced to" in card)

sys.exit(1 if failures else 0)
