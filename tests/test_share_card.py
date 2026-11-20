"""Profile sharing card copy (where a client's badges/standing are shown).

lambda_function.py reads S3 at import time, so the card's code is pulled out
with ast and run on its own. Run: python3 tests/test_share_card.py"""
import ast
import html
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "lambda_function.py")
NEEDED = {"_CTS_TICK", "_SHARE_PREVIEW_SKIP_KEYS", "_SHARE_PREVIEW_SKIP",
          "SHARE_COPY_NAMED", "_share_audience", "_share_card_html",
          "COMMISSION_TIERS", "TIERS_REFERRAL_CTA", "_tiers_card_html",
          "_fmt_trade_total", "_trades_status_note"}

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

CTA = "Introduce a new client who completes onboarding to reach Preferred and lower your commissions."
tierless = ns["_tiers_card_html"]({"tier": None, "good_standing": False, "items": []}, "https://example.com/tiers")
empty_tier = ns["_tiers_card_html"]({"tier": "", "items": []}, "https://example.com/tiers")
preferred = ns["_tiers_card_html"]({"tier": "preferred", "items": []}, "https://example.com/tiers")
check("Tiers card: referral line renders for a tierless client, as the card's last element after the tiers link",
      f'How tiers work &rarr;</a></p><p class="tc-cta">{html.escape(CTA)}</p></div>' in tierless
      and f'<p class="tc-cta">{html.escape(CTA)}</p>' in empty_tier)
check("Tiers card: referral line absent for a Preferred client", "tc-cta" not in preferred and CTA not in preferred)

# Current-tier line + "Current" card label.
gold = ns["_tiers_card_html"]({"tier": "gold", "items": []}, "")
platinum = ns["_tiers_card_html"]({"tier": "platinum", "items": []}, "")
check("Tiers card: current line for Preferred, directly under the heading",
      '<h2 class="sc-title">Commission tiers</h2><p class="tc-current">Your current tier: Preferred &mdash; '
      '10% off standard commission.</p><div class="tc-grid">' in preferred)
check("Tiers card: current line for Gold / Platinum",
      "Your current tier: Gold &mdash; 15% off standard commission." in gold
      and "Your current tier: Platinum &mdash; 20% off standard commission." in platinum)
check("Tiers card: current line for no tier (None, blank, unknown key)",
      all("Your current tier: none yet &mdash; standard commission applies." in h for h in
          (tierless, empty_tier, ns["_tiers_card_html"]({"tier": "bogus", "items": []}, ""))))
check("Tiers card: exactly one card marked Current, at its top",
      gold.count('class="tc-tier cur"') == 1 and gold.count(">Current</span>") == 1
      and '<div class="tc-tier cur"><span class="tc-tag">Current</span><div class="tc-head"><span class="tc-name">Gold<' in gold
      and "Current</span>" not in tierless)
check("Tiers card: next-step line kept for a tierless client in good standing",
      "Introduce a new client who completes onboarding to reach Preferred." in
      ns["_tiers_card_html"]({"tier": None, "good_standing": True, "items": []}, ""))

# Completed-trades total.
f = ns["_fmt_trade_total"]
check("trade total: < $1K -> $0", f(0) == "$0" and f(999) == "$0")
check("trade total: K band rounds to nearest 1,000",
      f(1000) == "$1K" and f(100000) == "$100K" and f(149499) == "$149K" and f(149500) == "$150K")
check("trade total: >= $1M unchanged M format", f(1_000_000) == "$1.0M" and f(2_500_000) == "$2.5M"
      and f(10_100_000) == "$10.1M")
tn = ns["_trades_status_note"]
check("trades note: amount from volume_usd, count text unchanged",
      tn({"note": "1 trade \u00b7 $0.1M", "volume_usd": 100000}) == "1 trade \u00b7 $100K"
      and tn({"note": "4 trades \u00b7 $10.1M", "volume_usd": 10_100_000}) == "4 trades \u00b7 $10.1M"
      and tn({"note": "0 trades \u00b7 $0.0M", "volume_usd": 0}) == "0 trades \u00b7 $0")
check("trades note: no volume_usd (older syndicate-dash) -> note unchanged",
      tn({"note": "1 trade \u00b7 $0.1M"}) == "1 trade \u00b7 $0.1M"
      and tn({"note": "1 trade \u00b7 $0.1M", "volume_usd": "x"}) == "1 trade \u00b7 $0.1M")

# Next-step line uses the same K/M amount as the trade total row.
def _gold(note, vol=None):
    it = {"key": "trades", "note": note}
    if vol is not None:
        it["volume_usd"] = vol
    return ns["_tiers_card_html"]({"tier": "preferred", "items": [it]}, "")
check("next-step line: $100K from volume_usd",
      "You&rsquo;re at 1 trade \u00b7 $100K." in _gold("1 trade \u00b7 $0.1M", 100000))
check("next-step line: $2.5M from volume_usd",
      "You&rsquo;re at 3 trades \u00b7 $2.5M." in _gold("3 trades \u00b7 $2.5M", 2_500_000))
check("next-step line: no volume_usd -> note unchanged",
      "You&rsquo;re at 1 trade \u00b7 $0.1M." in _gold("1 trade \u00b7 $0.1M"))

sys.exit(1 if failures else 0)
