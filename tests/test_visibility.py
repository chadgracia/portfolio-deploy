"""Deal Visibility filter for client-facing live offers (watchlist page).

lambda_function.py reads S3 at import time, so the visibility helpers are pulled
out with ast and run with a fake boto3 (no AWS calls).
Run: python3.12 tests/test_visibility.py  (or unittest discover -s tests)"""
import ast
import io
import json
import os
import time
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "lambda_function.py")
NEEDED = {"COMPANIES_BUCKET", "DEALS_KEY", "VISIBILITY_FIELD", "VIS_ALL", "VIS_INTERESTED",
          "VIS_PRIVATE", "VIS_OVERRIDES_KEY", "VIS_OVERRIDES_SECONDS", "VIS_DEALS_SECONDS",
          "_vis_cache", "_vis_norm", "_vis_s3_json", "_vis_build_map", "_visibility_map",
          "_vis_client_deals"}
tree = ast.parse(open(SRC).read())
nodes = []
for n in tree.body:
    names = ({n.name} if isinstance(n, ast.FunctionDef) else
             {t.id for t in getattr(n, "targets", []) if isinstance(t, ast.Name)})
    if names & NEEDED:
        nodes.append(n)
CODE = compile(ast.Module(body=nodes, type_ignores=[]), SRC, "exec")

ALL, INT, PRIV = 7223456, 7223457, 7223458
FIELD = "custom_label_4013323"


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def __init__(self, files, calls):
        self.files, self.calls = files, calls

    def get_object(self, Bucket, Key):
        self.calls.append(Key)
        v = self.files.get(Key)
        if v is None:
            raise FakeClientError("NoSuchKey")
        if isinstance(v, Exception):
            raise v
        return {"Body": io.BytesIO(json.dumps(v).encode())}


def load(files):
    calls = []
    boto = type("B", (), {"client": staticmethod(lambda _n: FakeS3(files, calls))})
    ns = {"json": json, "time": time, "boto3": boto, "ClientError": FakeClientError}
    exec(CODE, ns)
    return ns, calls


def deals_json(*pairs):
    return {"deals": [{"id": i, "custom_fields": ({FIELD: v} if v is not ...
                                                  else {})} for i, v in pairs]}


OFFERS = [{"id": 1, "company": "A"}, {"id": 2, "company": "B"},
          {"id": 3, "company": "C"}, {"id": 4, "company": "D"}, {"id": 99, "company": "E"}]


class VisibilityTests(unittest.TestCase):
    def setUp(self):
        # 1 = blank, 2 = All, 3 = Interested, 4 = Private; 99 not in deals.json.
        self.ns, self.calls = load({"deals.json": deals_json((1, ...), (2, ALL), (3, [INT]),
                                                             (4, "7223458.0"))})

    def ids(self, rows):
        return [d["id"] for d in rows]

    def test_norm(self):
        n = self.ns["_vis_norm"]
        for v in (None, "", [], "x", 123, ALL, str(ALL)):
            self.assertEqual(n(v), ALL)
        self.assertEqual(n(PRIV), PRIV)
        self.assertEqual(n(" 7223458 "), PRIV)
        self.assertEqual(n("7223457.0"), INT)
        self.assertEqual(n([INT]), INT)

    def test_watchlist_rows_keep_interested_drop_private(self):
        vis = self.ns["_visibility_map"]()
        out = self.ns["_vis_client_deals"](OFFERS, vis, via_watchlist=True)
        self.assertEqual(self.ids(out), [1, 2, 3, 99])

    def test_general_list_drops_interested_and_private(self):
        vis = self.ns["_visibility_map"]()
        out = self.ns["_vis_client_deals"](OFFERS, vis, via_watchlist=False)
        self.assertEqual(self.ids(out), [1, 2, 99])

    def test_override_wins(self):
        ns, _ = load({"deals.json": deals_json((1, ...), (4, PRIV)),
                      "visibility-overrides.json": {"1": {"v": PRIV, "at": "2026-11-14T00:00:00Z"},
                                                    "4": {"v": ALL, "at": "2026-11-14T00:00:00Z"}}})
        vis = ns["_visibility_map"]()
        self.assertEqual(vis["1"], PRIV)
        self.assertEqual(vis["4"], ALL)
        out = ns["_vis_client_deals"]([{"id": 1}, {"id": 4}], vis, via_watchlist=True)
        self.assertEqual(self.ids(out), [4])

    def test_missing_overrides_is_empty_and_cached(self):
        self.ns["_visibility_map"]()
        self.ns["_visibility_map"]()
        self.assertEqual(self.calls.count("deals.json"), 1)
        self.assertEqual(self.calls.count("visibility-overrides.json"), 1)

    def test_fail_soft_no_filtering(self):
        ns, _ = load({"deals.json": FakeClientError("AccessDenied")})
        vis = ns["_visibility_map"]()
        self.assertIsNone(vis)
        self.assertEqual(self.ids(ns["_vis_client_deals"](OFFERS, vis, True)),
                         self.ids(OFFERS))


if __name__ == "__main__":
    unittest.main()
