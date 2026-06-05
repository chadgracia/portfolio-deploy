#!/usr/bin/env python3
"""Build people_index.json — the small email->id / id->{email,first_name} index the
portfolio Lambda reads — from the full 113 MB people.json.

The Lambda must NEVER load people.json at request time (a 113 MB parse OOMs/times
out the function). Instead it reads this tiny pre-built index. Run this wherever
people.json is produced/refreshed, AFTER the new people.json is written to S3 — or
fold build() into that upstream job directly.

Usage:
  python build_people_index.py                     # read+write via S3 (default keys)
  python build_people_index.py in.json out.json    # local files, for testing

Index shape (matches lambda_function.py's _people_index()):
  {"by_id":    {id_str: {"email": ..., "first_name": ...}},
   "by_email": {email_lower: id_str}}
"""
import json
import sys

# Keep these in sync with lambda_function.py.
BUCKET     = "full-pipeline-cache"
PEOPLE_KEY = "people.json"
INDEX_KEY  = "people_index.json"


def _email(rec):
    """Normalized email, tolerating the Pipeline record variants (belt-and-suspenders
    lives here now, not in the Lambda)."""
    email = rec.get("email") or rec.get("primary_email") or ""
    if not email:
        emails = rec.get("emails")
        if isinstance(emails, list) and emails:
            first = emails[0]
            email = first if isinstance(first, str) else (
                (first or {}).get("address") or (first or {}).get("email") or "")
    return (email or "").strip()


def _first_name(rec):
    first_name = (rec.get("first_name") or "").strip()
    if not first_name:
        full = (rec.get("name") or rec.get("full_name") or "").strip()
        first_name = full.split()[0] if full else ""
    return first_name


def build(data):
    """data (parsed people.json) -> the small index dict."""
    people = data.get("people", []) if isinstance(data, dict) else (data or [])
    by_id, by_email = {}, {}
    for rec in people:
        rid = rec.get("id")
        if rid is None:
            continue
        email = _email(rec)
        by_id[str(rid)] = {"email": email, "first_name": _first_name(rec)}
        if email:
            by_email[email.lower()] = str(rid)   # last write wins on duplicate emails
    return {"by_id": by_id, "by_email": by_email}


def main():
    if len(sys.argv) == 3:                         # local files (testing)
        with open(sys.argv[1]) as f:
            idx = build(json.load(f))
        with open(sys.argv[2], "w") as f:
            json.dump(idx, f)
        print(f"wrote {sys.argv[2]}: {len(idx['by_id'])} people, "
              f"{len(idx['by_email'])} emails")
        return

    import boto3
    s3 = boto3.client("s3")
    data = json.loads(s3.get_object(Bucket=BUCKET, Key=PEOPLE_KEY)["Body"].read())
    idx = build(data)
    s3.put_object(Bucket=BUCKET, Key=INDEX_KEY,
                  ContentType="application/json", Body=json.dumps(idx).encode("utf-8"))
    print(f"wrote s3://{BUCKET}/{INDEX_KEY}: {len(idx['by_id'])} people, "
          f"{len(idx['by_email'])} emails")


if __name__ == "__main__":
    main()
