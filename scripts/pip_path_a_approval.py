#!/usr/bin/env python3
"""PIP Path A approval artifact — format, signing helpers and verification.

Single source of truth for the approval message. The operator signing tool and
the repository-side "PIP Path A Fidelity Gate" both use this module, so the two
sides cannot drift apart.

SECURITY CONTRACT
-----------------
1. The signed object is the EXACT RAW BYTES of the candidate file. Not parsed
   JSON, not a record-aggregate hash, not normalised or re-serialised JSON.
2. The signed message is deterministic plain text: UTF-8, LF, one field per
   line, fixed order. No JSON canonicalisation is involved, so there is no
   canonicalisation ambiguity to exploit.
3. VERIFY BEFORE PARSE. ``verify()`` checks the signature over the literal
   bytes it was given and only then parses fields out of the verified text.
   Nothing in the approval may influence which key is trusted: the trusted
   public key is a parameter supplied by the caller from trusted configuration.
4. Fail closed. Every problem raises ApprovalError. There is no partial pass,
   no "close enough", no JSON-equivalence fallback.

This module never touches a private key except in ``sign()``, which is called
only by the operator signing tool with a key loaded from outside the project
workspace.
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone

FORMAT = "PIP-PATH-A-APPROVAL-v1"

# Exact field order. Changing this is a format change and needs a new FORMAT tag.
FIELDS = ("repo", "ref", "path", "sha256", "bytes", "records",
          "generation", "run_id", "approved_at", "key_id")

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX16 = re.compile(r"\A[0-9a-f]{16}\Z")
_DEC = re.compile(r"\A(0|[1-9][0-9]{0,17})\Z")
_REPO = re.compile(r"\A[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_REF = re.compile(r"\Arefs/heads/[A-Za-z0-9_./-]{1,200}\Z")
_PATH = re.compile(r"\A[A-Za-z0-9_./-]{1,200}\Z")
_RUNID = re.compile(r"\A[A-Za-z0-9_.:-]{1,120}\Z")
_TS = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

FRESHNESS_DAYS = 30          # authorised value


class ApprovalError(Exception):
    """Any failure to build, verify or interpret an approval. Always fatal."""


# ----------------------------------------------------------------- artifact --
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path) -> tuple[str, int]:
    """Return (sha256 hex, byte length) of a file's EXACT bytes."""
    with open(path, "rb") as fh:
        data = fh.read()
    return sha256_bytes(data), len(data)


def key_id_for(public_key_bytes: bytes) -> str:
    """Stable short identifier for a public key: first 16 hex of its SHA-256."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]


def build_message(fields: dict) -> bytes:
    """Render the deterministic signed message. Rejects anything malformed."""
    missing = [k for k in FIELDS if k not in fields]
    if missing:
        raise ApprovalError(f"approval is missing field(s): {', '.join(missing)}")
    extra = [k for k in fields if k not in FIELDS]
    if extra:
        raise ApprovalError(f"approval has unexpected field(s): {', '.join(extra)}")
    values = {k: str(fields[k]) for k in FIELDS}
    _validate(values)
    lines = [FORMAT] + [f"{k}={values[k]}" for k in FIELDS]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _validate(v: dict) -> None:
    checks = (
        ("repo", _REPO), ("ref", _REF), ("path", _PATH), ("sha256", _HEX64),
        ("bytes", _DEC), ("records", _DEC), ("generation", _DEC),
        ("run_id", _RUNID), ("approved_at", _TS), ("key_id", _HEX16),
    )
    for name, pattern in checks:
        if not pattern.match(v[name]):
            raise ApprovalError(f"field {name!r} is malformed: {v[name]!r}")


def parse_message(raw: bytes) -> dict:
    """Parse a VERIFIED message. Never call this on unverified bytes.

    Strict by construction: exact header, exact field set, exact order, no
    duplicates, no extra lines, no missing trailing newline.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise ApprovalError("approval must be bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApprovalError(f"approval is not valid UTF-8: {exc}") from None
    if "\r" in text:
        raise ApprovalError("approval contains CR; LF line endings are required")
    if not text.endswith("\n"):
        raise ApprovalError("approval is missing its trailing newline")
    lines = text[:-1].split("\n")
    if len(lines) != len(FIELDS) + 1:
        raise ApprovalError(f"approval has {len(lines)} lines, expected {len(FIELDS) + 1}")
    if lines[0] != FORMAT:
        raise ApprovalError(f"unexpected format header: {lines[0]!r}")
    values: dict[str, str] = {}
    for line, expected in zip(lines[1:], FIELDS):
        key, sep, value = line.partition("=")
        if not sep:
            raise ApprovalError(f"malformed line: {line!r}")
        if key != expected:
            raise ApprovalError(f"field out of order: expected {expected!r}, found {key!r}")
        if key in values:
            raise ApprovalError(f"duplicate field: {key!r}")
        values[key] = value
    _validate(values)
    return values


# ------------------------------------------------------------ crypto layer ---
def _backend():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
    except ImportError as exc:                       # pragma: no cover
        raise ApprovalError(
            "the 'cryptography' package is required for Ed25519 approval "
            "signatures and is not installed. Install it before signing or "
            "verifying; do not substitute another implementation."
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey


def public_key_from_b64(pub_b64: str) -> bytes:
    """Decode a pinned public key. Rejects anything that is not 32 raw bytes."""
    try:
        raw = base64.b64decode(pub_b64.strip(), validate=True)
    except Exception as exc:
        raise ApprovalError(f"trusted public key is not valid base64: {exc}") from None
    if len(raw) != 32:
        raise ApprovalError(f"trusted public key is {len(raw)} bytes, expected 32")
    return raw


def sign(message: bytes, private_key_bytes: bytes) -> str:
    """Sign a message. Called ONLY by the operator signing tool."""
    Ed25519PrivateKey, _ = _backend()
    if len(private_key_bytes) != 32:
        raise ApprovalError("private key seed must be 32 bytes")
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return base64.b64encode(key.sign(message)).decode("ascii")


def verify(approval_bytes: bytes, signature_b64: str, trusted_public_key_b64: str) -> dict:
    """Verify THEN parse. Returns the verified fields, or raises ApprovalError.

    ``trusted_public_key_b64`` must come from trusted configuration supplied by
    the caller. Nothing inside the approval selects the key.
    """
    _, Ed25519PublicKey = _backend()
    raw_pub = public_key_from_b64(trusted_public_key_b64)
    try:
        sig = base64.b64decode(signature_b64.strip(), validate=True)
    except Exception as exc:
        raise ApprovalError(f"signature is not valid base64: {exc}") from None
    if len(sig) != 64:
        raise ApprovalError(f"signature is {len(sig)} bytes, expected 64")
    pub = Ed25519PublicKey.from_public_bytes(raw_pub)
    try:
        pub.verify(sig, bytes(approval_bytes))       # ← verification happens first
    except Exception:
        raise ApprovalError("signature does not verify against the trusted public key") from None

    fields = parse_message(approval_bytes)            # ← only now do we parse
    expected_kid = key_id_for(raw_pub)
    if fields["key_id"] != expected_kid:
        raise ApprovalError(
            f"key_id {fields['key_id']!r} does not match the trusted key {expected_kid!r}")
    return fields


# ------------------------------------------------------------- gate checks ---
def check_binding(fields: dict, *, repo: str, ref: str, path: str) -> None:
    for name, expected in (("repo", repo), ("ref", ref), ("path", path)):
        if fields[name] != expected:
            raise ApprovalError(
                f"approval {name} {fields[name]!r} does not match expected {expected!r}")


def check_candidate(fields: dict, candidate_bytes: bytes, record_count: int) -> None:
    digest = sha256_bytes(candidate_bytes)
    if digest != fields["sha256"]:
        raise ApprovalError(
            f"candidate sha256 {digest} does not match approved {fields['sha256']}")
    if len(candidate_bytes) != int(fields["bytes"]):
        raise ApprovalError(
            f"candidate is {len(candidate_bytes)} bytes, approval says {fields['bytes']}")
    if record_count != int(fields["records"]):
        raise ApprovalError(
            f"candidate has {record_count} records, approval says {fields['records']}")


def check_generation(fields: dict, base_generation: int) -> None:
    """Monotonic. base_generation is 0 when the base branch carries no approval."""
    gen = int(fields["generation"])
    if gen <= base_generation:
        raise ApprovalError(
            f"generation {gen} does not advance past the published generation "
            f"{base_generation} (rollback or replay)")


def check_freshness(fields: dict, now: datetime | None = None,
                    max_age_days: int = FRESHNESS_DAYS) -> None:
    now = now or datetime.now(timezone.utc)
    approved = datetime.strptime(fields["approved_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc)
    age = (now - approved).total_seconds()
    if age > max_age_days * 86400:
        raise ApprovalError(
            f"approval is {age / 86400:.1f} days old, exceeding the "
            f"{max_age_days}-day freshness window")
    if age < -300:
        raise ApprovalError("approval is dated in the future")
