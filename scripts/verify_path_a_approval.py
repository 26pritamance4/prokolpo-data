#!/usr/bin/env python3
"""PIP Path A Fidelity Gate — verifier. TRUSTED CODE. Runs from the base branch.

Deployment: this file belongs in the prokolpo-data repository at
``scripts/verify_path_a_approval.py``, alongside a copy of
``pip_path_a_approval.py``. Both are checked out from the BASE revision by the
gate workflow, never from the pull request.

It reads the candidate and the approval as DATA. It executes nothing from the
pull request, imports nothing from the pull request, and installs nothing the
pull request supplies.

Every failure is fatal and exits non-zero. There is no partial pass.

Usage:
  verify_path_a_approval.py --candidate <file> --approval <file> --signature <file>
                            --public-key-b64 <key> --base-generation N
                            [--repo R] [--ref R] [--path P] [--max-age-days N]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pip_path_a_approval as approval          # noqa: E402

DEFAULT_REPO = "26pritamance4/prokolpo-data"
DEFAULT_REF = "refs/heads/main"
DEFAULT_PATH = "schemes.json"

STEPS = 9


def fail(step: int, msg: str) -> None:
    print(f"\n  [{step}/{STEPS}] FAIL  {msg}")
    print("\nPIP Path A Fidelity Gate: FAIL — publication is not authorised.")
    raise SystemExit(1)


def ok(step: int, msg: str) -> None:
    print(f"  [{step}/{STEPS}] pass  {msg}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate", required=True)
    ap.add_argument("--approval", required=True)
    ap.add_argument("--signature", required=True)
    ap.add_argument("--public-key-b64", required=True)
    ap.add_argument("--base-generation", required=True, type=int)
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--ref", default=DEFAULT_REF)
    ap.add_argument("--path", default=DEFAULT_PATH)
    ap.add_argument("--max-age-days", type=int, default=approval.FRESHNESS_DAYS)
    args = ap.parse_args(argv[1:])

    print("PIP Path A Fidelity Gate")
    print("=" * 62)

    # 1 — all three inputs must be present
    paths = {}
    for name, value in (("candidate", args.candidate), ("approval", args.approval),
                        ("signature", args.signature)):
        p = Path(value)
        if not p.is_file():
            fail(1, f"{name} file is missing: {value}")
        paths[name] = p
    ok(1, "candidate, approval and signature are all present")

    approval_bytes = paths["approval"].read_bytes()
    signature_text = paths["signature"].read_text(encoding="utf-8", errors="replace")
    candidate_bytes = paths["candidate"].read_bytes()

    # 2 — VERIFY BEFORE PARSE. The trusted key comes from the caller, never
    #     from the approval. Nothing in the approval selects the key.
    try:
        fields = approval.verify(approval_bytes, signature_text, args.public_key_b64)
    except approval.ApprovalError as exc:
        fail(2, str(exc))
    ok(2, "Ed25519 signature verifies against the pinned trusted public key")

    # 3 — the fields now in hand came out of verified bytes
    ok(3, f"approval parsed from verified bytes (generation {fields['generation']}, "
          f"run {fields['run_id']}, key {fields['key_id']})")

    # 4 — provenance binding
    try:
        approval.check_binding(fields, repo=args.repo, ref=args.ref, path=args.path)
    except approval.ApprovalError as exc:
        fail(4, str(exc))
    ok(4, f"binding matches {args.repo} {args.ref} {args.path}")

    # 5/6 — exact bytes, exact length, record count
    try:
        doc = json.loads(candidate_bytes.decode("utf-8"))
    except Exception as exc:
        fail(5, f"candidate is not valid UTF-8 JSON: {exc}")
    records = doc.get("schemes") if isinstance(doc, dict) else doc
    if not isinstance(records, list):
        fail(5, "candidate has no 'schemes' array")
    try:
        approval.check_candidate(fields, candidate_bytes, len(records))
    except approval.ApprovalError as exc:
        fail(5, str(exc))
    ok(5, f"candidate SHA-256 matches the approved digest exactly ({fields['sha256'][:16]}…)")
    ok(6, f"byte length {fields['bytes']} and record count {fields['records']} agree")

    # 7 — monotonic generation: rollback and replay defence
    try:
        approval.check_generation(fields, args.base_generation)
    except approval.ApprovalError as exc:
        fail(7, str(exc))
    ok(7, f"generation {fields['generation']} advances past published {args.base_generation}")

    # 8 — freshness
    try:
        approval.check_freshness(fields, max_age_days=args.max_age_days)
    except approval.ApprovalError as exc:
        fail(8, str(exc))
    ok(8, f"approved_at {fields['approved_at']} is within {args.max_age_days} days")

    # 9 — structural cross-check; a digest alone would faithfully approve rubbish
    envelope = ["schema_version", "project", "dataset_type", "total_records",
                "verified_records", "needs_review_records", "last_verified_at", "schemes"]
    if not isinstance(doc, dict) or list(doc.keys()) != envelope:
        fail(9, f"envelope keys or order are unexpected: {list(doc)[:10]}")
    ids = [r.get("id") for r in records if isinstance(r, dict)]
    if len(ids) != len(records):
        fail(9, "every record must be an object")
    if len(set(ids)) != len(ids):
        fail(9, "duplicate record ids")
    if any(not isinstance(i, str) or not i for i in ids):
        fail(9, "record ids must be non-empty strings")
    ok(9, f"envelope shape and {len(ids)} unique record ids are consistent")

    print("\nPIP Path A Fidelity Gate: PASS")
    print(f"  the candidate bytes are exactly the bytes approved by key {fields['key_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
