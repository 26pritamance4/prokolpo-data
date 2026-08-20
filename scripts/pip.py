#!/usr/bin/env python3
"""
Prokolpo Bondhu — PIP Monitor (single-file build).

Runs Monday & Thursday 05:30 IST via .github/workflows/pip-monitor.yml.

Phases implemented here:
  0  validate before touching anything (§9/§12/§14) — abort on error
  1  link health + cheap change detection (§7 Step 1, §15)
  6  regenerate wrapper counts from the array (§12/§13)
  7  run report -> reports/YYYY-MM-DD.json (§17)
  8  write run summary to the Actions job summary (§18)

Phases 2-5 (LLM verification, video discovery, Bengali generation) plug in
between phase 1 and phase 6 inside main().
"""
from __future__ import annotations

from collections import Counter
from collections import defaultdict
from datetime import date
from datetime import date, datetime
from datetime import datetime, timezone
from pathlib import Path
from requests.adapters import HTTPAdapter
from requests.exceptions import SSLError, Timeout, ConnectionError as ReqConnError
from urllib.parse import urlparse
import hashlib
import json
import os
import random
import re
import requests
import ssl
import warnings
import sys
import time


# ======================================================================
# VALIDATION (§9, §12, §14)
# ======================================================================
#!/usr/bin/env python3
"""
PIP schema + integrity validator.

Implements spec sections:
  §9  schema validation
  §12 production count calculation
  §14 review-queue separation
  §7 Step 4 URL-purpose validation

ERRORS  block the run (dataset is structurally unsound - change nothing).
WARNINGS are reported but do not abort.
"""


# --- §8 exact field order -------------------------------------------------
FIELDS = [
    "id", "name_en", "name_bn", "category", "dept", "description_bn", "benefit",
    "eligibility", "documents", "application_process", "official_website",
    "official_scheme_url", "apply_online_url", "form_pdf_url", "video_url",
    "source", "government_level", "scheme_status", "verification_status",
    "verification_notes", "change_type", "detected_change_summary_bn",
    "last_updated", "last_verified_at", "start_date",
]
SOURCE_FIELDS = ["title", "url", "source_type", "published_or_updated_date"]

SENTINEL = "অফিসিয়াল উৎসে স্পষ্টভাবে উল্লেখ নেই"

CATEGORIES = {"central", "west_bengal"}
STATUSES = {"active", "application_open", "application_closed",
            "paused", "discontinued", "unknown"}
VERIFICATION = {"verified", "needs_review"}
CHANGE_TYPES = {
    "new_scheme", "application_opened", "application_closed", "deadline_changed",
    "benefit_changed", "eligibility_changed", "documents_changed", "process_changed",
    "form_added", "source_changed", "status_changed", "correction", "no_change",
}
SOURCE_TYPES = {
    "official_scheme_page", "official_department_page", "official_application_portal",
    "official_notification", "official_pdf", "official_press_release",
}

# §12 - statuses that count toward production
PUBLISHABLE = {"active", "application_open", "application_closed"}

# §3 - statutory bodies administering programmes, outside *.gov.in.
# Extend deliberately; do NOT loosen this into a suffix rule.
STATUTORY_ALLOWLIST = {
    "pfrda.org.in",        # Pension Fund Regulatory and Development Authority
    "www.pfrda.org.in",
    "wbmdfc.net",          # WB Minorities' Development & Finance Corporation
    "www.wbmdfc.net",
}

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

STALE_DAYS = 30  # last_verified_at older than this raises a warning


def _is_gov(host: str) -> bool:
    host = host.lower()
    return (host.endswith(".gov.in") or host.endswith(".nic.in")
            or host in STATUTORY_ALLOWLIST)


def _valid_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def _valid_date(v: str) -> bool:
    if v == "":
        return True
    if not DATE_RE.match(v):
        return False
    try:
        datetime.strptime(v, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def validate(path: Path):
    errors: list[str] = []
    warnings: list[str] = []

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        return [f"FATAL: file is not valid UTF-8 ({e})"], [], {}

    try:
        raw = json.loads(text)
    except json.JSONDecodeError as e:
        return [f"FATAL: invalid JSON at line {e.lineno} col {e.colno}: {e.msg}"], [], {}

    # --- root shape -------------------------------------------------------
    if isinstance(raw, list):
        records, wrapper = raw, None
    elif isinstance(raw, dict) and isinstance(raw.get("schemes"), list):
        records, wrapper = raw["schemes"], raw
    else:
        return ["FATAL: root must be an array, or an object with a 'schemes' array"], [], {}

    seen_ids: Counter = Counter()
    today = date.today()

    for i, r in enumerate(records):
        tag = r.get("id", f"<index {i}>") if isinstance(r, dict) else f"<index {i}>"

        if not isinstance(r, dict):
            errors.append(f"{tag}: element is not an object")
            continue

        keys = list(r.keys())
        if len(keys) != len(FIELDS):
            errors.append(f"{tag}: has {len(keys)} fields, expected {len(FIELDS)}")
        if keys != FIELDS:
            extra = set(keys) - set(FIELDS)
            missing = set(FIELDS) - set(keys)
            if extra:
                errors.append(f"{tag}: unexpected field(s) {sorted(extra)}")
            if missing:
                errors.append(f"{tag}: missing field(s) {sorted(missing)}")
            if not extra and not missing:
                errors.append(f"{tag}: fields present but out of §8 order")

        # --- id -----------------------------------------------------------
        rid = r.get("id", "")
        if not isinstance(rid, str) or not SLUG_RE.match(rid or ""):
            errors.append(f"{tag}: id is not a lowercase slug")
        seen_ids[rid] += 1

        # --- enums --------------------------------------------------------
        if r.get("category") not in CATEGORIES:
            errors.append(f"{tag}: invalid category {r.get('category')!r}")
        if r.get("government_level") not in CATEGORIES:
            errors.append(f"{tag}: invalid government_level {r.get('government_level')!r}")
        if r.get("category") != r.get("government_level"):
            errors.append(f"{tag}: category != government_level")
        if r.get("scheme_status") not in STATUSES:
            errors.append(f"{tag}: invalid scheme_status {r.get('scheme_status')!r}")
        if r.get("verification_status") not in VERIFICATION:
            errors.append(f"{tag}: invalid verification_status {r.get('verification_status')!r}")
        if r.get("change_type") not in CHANGE_TYPES:
            errors.append(f"{tag}: invalid change_type {r.get('change_type')!r}")

        # --- arrays -------------------------------------------------------
        for af in ("eligibility", "documents", "application_process", "video_url", "source"):
            if not isinstance(r.get(af), list):
                errors.append(f"{tag}: {af} must be an array")

        # --- dates --------------------------------------------------------
        for df in ("last_updated", "last_verified_at", "start_date"):
            if not _valid_date(r.get(df, "")):
                errors.append(f"{tag}: {df} is not YYYY-MM-DD or empty ({r.get(df)!r})")

        lv = r.get("last_verified_at", "")
        if DATE_RE.match(lv or ""):
            age = (today - datetime.strptime(lv, "%Y-%m-%d").date()).days
            if age > STALE_DAYS:
                warnings.append(f"{tag}: last verified {age} days ago")

        # --- urls ---------------------------------------------------------
        ow = r.get("official_website", "")
        osu = r.get("official_scheme_url", "")
        aou = r.get("apply_online_url", "")
        fpu = r.get("form_pdf_url", "")

        for uf, u in (("official_website", ow), ("official_scheme_url", osu),
                      ("apply_online_url", aou), ("form_pdf_url", fpu)):
            if u and not _valid_url(u):
                errors.append(f"{tag}: {uf} is not a valid URL")
            elif u and not _is_gov(urlparse(u).netloc):
                warnings.append(f"{tag}: {uf} on non-allowlisted domain "
                                f"{urlparse(u).netloc}")

        # §7 Step 4 - URL purpose
        if aou and aou == ow:
            warnings.append(f"{tag}: apply_online_url is the homepage (§7 Step 4)")
        if aou and aou == osu:
            warnings.append(f"{tag}: apply_online_url == official_scheme_url (§7 Step 4)")
        if ow and ow == osu:
            warnings.append(f"{tag}: official_website == official_scheme_url (§7 Step 4)")

        # --- sources ------------------------------------------------------
        srcs = r.get("source", [])
        if isinstance(srcs, list):
            if not srcs:
                warnings.append(f"{tag}: no source entries")
            for s in srcs:
                if not isinstance(s, dict):
                    errors.append(f"{tag}: source entry is not an object")
                    continue
                if list(s.keys()) != SOURCE_FIELDS:
                    errors.append(f"{tag}: source entry fields != {SOURCE_FIELDS}")
                if s.get("source_type") not in SOURCE_TYPES:
                    errors.append(f"{tag}: invalid source_type {s.get('source_type')!r}")
                su = s.get("url", "")
                if not _valid_url(su):
                    errors.append(f"{tag}: source url invalid ({su!r})")
                elif not _is_gov(urlparse(su).netloc):
                    warnings.append(f"{tag}: source on non-allowlisted domain "
                                    f"{urlparse(su).netloc}")
                if not _valid_date(s.get("published_or_updated_date", "")):
                    errors.append(f"{tag}: source date not YYYY-MM-DD or empty")

        # --- sentinel semantics -------------------------------------------
        for af in ("eligibility", "documents", "application_process"):
            arr = r.get(af, [])
            if isinstance(arr, list) and SENTINEL in arr and len(arr) > 1:
                warnings.append(f"{tag}: {af} mixes the 'not stated' sentinel "
                                f"with real values (§7 Step 3)")

        # --- §14 review separation ----------------------------------------
        if r.get("verification_status") == "needs_review":
            warnings.append(f"{tag}: needs_review record sitting in production (§14)")

    for rid, n in seen_ids.items():
        if n > 1:
            errors.append(f"duplicate id {rid!r} appears {n} times")

    # --- §12 counts (always calculated, never trusted) --------------------
    production_count = sum(
        1 for r in records
        if isinstance(r, dict)
        and r.get("verification_status") == "verified"
        and r.get("scheme_status") in PUBLISHABLE
    )
    needs_review = [r.get("id") for r in records
                    if isinstance(r, dict)
                    and r.get("verification_status") == "needs_review"]

    stats = {
        "total_records": len(records),
        "production_count": production_count,
        "needs_review_count": len(needs_review),
        "needs_review_ids": needs_review,
        "status_spread": dict(Counter(r.get("scheme_status") for r in records
                                      if isinstance(r, dict))),
        "change_type_spread": dict(Counter(r.get("change_type") for r in records
                                           if isinstance(r, dict))),
        "records_with_video": sum(1 for r in records
                                  if isinstance(r, dict) and r.get("video_url")),
        "wrapper_present": wrapper is not None,
    }

    # --- wrapper counts must match reality (§13) --------------------------
    if wrapper is not None:
        claimed = {
            "total_records": wrapper.get("total_records"),
            "verified_records": wrapper.get("verified_records"),
            "needs_review_records": wrapper.get("needs_review_records"),
        }
        actual = {
            "total_records": len(records),
            "verified_records": production_count,
            "needs_review_records": len(needs_review),
        }
        for k in claimed:
            if claimed[k] != actual[k]:
                warnings.append(
                    f"wrapper.{k} claims {claimed[k]} but actual is {actual[k]} "
                    f"(§13 - will be regenerated)"
                )
        stats["wrapper_claimed"] = claimed
        stats["wrapper_actual"] = actual

    return errors, warnings, stats


def regenerate_counts(path: Path, stats: dict) -> bool:
    """Rewrite wrapper counts from the array. Returns True if the file changed."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return False
    before = json.dumps(raw, ensure_ascii=False, sort_keys=True)
    raw["total_records"] = stats["total_records"]
    raw["verified_records"] = stats["production_count"]
    raw["needs_review_records"] = stats["needs_review_count"]
    raw["last_verified_at"] = date.today().isoformat()
    after = json.dumps(raw, ensure_ascii=False, sort_keys=True)
    if before != after:
        path.write_text(
            json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        return True
    return False


# ======================================================================
# LINK HEALTH (§7 Step 1, §15)
# ======================================================================
#!/usr/bin/env python3
"""
PIP link health + cheap change detection (§7 Step 1, §15).

Every URL in the dataset is checked with a conditional GET. Results are
classified so the run report can distinguish "page changed" from "portal
is down" from "certificate expired" — three very different situations
that a naive status-code check collapses into one.

State is kept in state/link_state.json so the next run can send
If-None-Match / If-Modified-Since and detect real changes cheaply,
without any LLM involvement.
"""



UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0 Safari/537.36 ProkolpoBondhu-PIP/1.1")
TIMEOUT = 45              # Indian government portals are frequently slow
PER_HOST_DELAY = 1.5      # politeness toward government servers
MAX_RETRIES = 2
MIN_SANE_BYTES = 500      # below this, a 200 is suspicious

# Pages that return HTTP 200 while carrying no real content.
SOFT_FAIL_MARKERS = re.compile(
    r"(session\s+expired|under\s+maintenance|service\s+unavailable|"
    r"page\s+not\s+found|access\s+denied|error\s+occurred|"
    r"enable\s+javascript\s+to\s+continue)",
    re.I,
)

STATE_PATH = Path("state/link_state.json")


class LegacyTLSAdapter(HTTPAdapter):
    """
    Many .gov.in / .wb.gov.in hosts still terminate TLS on old stacks:
    TLS 1.0/1.1, small DH parameters, or ciphers that OpenSSL 3 on Ubuntu 24
    refuses outright at SECLEVEL=2. The handshake dies before HTTP happens,
    which surfaces as 'Max retries exceeded' and looks like the host is down
    when it is actually up and serving.

    This adapter lowers the security level far enough to complete those
    handshakes. It is used ONLY as a second attempt, after a strict verified
    connection has already failed, and anything fetched through it is tagged
    tls_unverified so the report never implies the certificate was checked.
    """

    def init_poolmanager(self, connections, maxsize, block=False, **kw):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        except ssl.SSLError:
            ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (AttributeError, ValueError):
            pass
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        kw["ssl_context"] = ctx
        return super().init_poolmanager(connections, maxsize, block=block, **kw)


def _make_sessions() -> tuple[requests.Session, requests.Session]:
    strict = requests.Session()
    legacy = requests.Session()
    legacy.mount("https://", LegacyTLSAdapter())
    return strict, legacy


SESSION_STRICT, SESSION_LEGACY = _make_sessions()


def collect_urls(records: list[dict]) -> dict[str, list[str]]:
    """Map each URL to the record ids that reference it."""
    urls: dict[str, list[str]] = defaultdict(list)
    for r in records:
        rid = r.get("id", "?")
        for f in ("official_website", "official_scheme_url",
                  "apply_online_url", "form_pdf_url"):
            u = r.get(f, "")
            if u:
                urls[u].append(f"{rid}.{f}")
        for s in r.get("source", []):
            u = s.get("url", "")
            if u:
                urls[u].append(f"{rid}.source")
    return dict(urls)


def _sanity(resp) -> tuple[bool, str]:
    """Did a 200 actually carry usable content?"""
    ctype = resp.headers.get("Content-Type", "").lower()
    body = resp.content or b""

    if "pdf" in ctype or body[:5] == b"%PDF-":
        return (len(body) > 1000, "pdf too small" if len(body) <= 1000 else "")

    if len(body) < MIN_SANE_BYTES:
        return False, f"body only {len(body)} bytes"

    try:
        text = body.decode(resp.encoding or "utf-8", errors="ignore")
    except Exception:
        return True, ""

    m = SOFT_FAIL_MARKERS.search(text[:8000])
    if m:
        return False, f"soft-fail marker: {m.group(0)[:40]}"
    return True, ""


def check_url(url: str, prior: dict) -> dict:
    """Check one URL. Never raises."""
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "application/pdf,*/*;q=0.8",
        "Accept-Language": "en-IN,en-GB;q=0.9,en;q=0.8,bn;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }
    if prior.get("etag"):
        headers["If-None-Match"] = prior["etag"]
    if prior.get("last_modified"):
        headers["If-Modified-Since"] = prior["last_modified"]

    out = {
        "url": url,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "outcome": "unknown",
        "status": None,
        "note": "",
        "etag": prior.get("etag"),
        "last_modified": prior.get("last_modified"),
        "content_hash": prior.get("content_hash"),
    }

    last_err = ""
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = SESSION_STRICT.get(url, headers=headers, timeout=TIMEOUT,
                                      allow_redirects=True)
            out["status"] = resp.status_code

            if resp.status_code == 304:
                out["outcome"] = "unchanged"
                return out

            if resp.status_code in (401, 403, 429):
                out["outcome"] = "blocked"
                out["note"] = f"HTTP {resp.status_code}"
                return out

            if resp.status_code >= 500:
                last_err = f"HTTP {resp.status_code}"
                time.sleep(2 ** attempt + random.random())
                continue

            if resp.status_code >= 400:
                out["outcome"] = "dead"
                out["note"] = f"HTTP {resp.status_code}"
                return out

            ok, why = _sanity(resp)
            if not ok:
                out["outcome"] = "soft_fail"
                out["note"] = why
                return out

            digest = hashlib.sha256(resp.content).hexdigest()
            out["etag"] = resp.headers.get("ETag")
            out["last_modified"] = resp.headers.get("Last-Modified")
            out["content_hash"] = digest
            prior_hash = prior.get("content_hash")
            out["outcome"] = ("unchanged" if prior_hash == digest
                              else ("changed" if prior_hash else "new"))
            return out

        except SSLError as e:
            # Many wb.gov.in hosts serve broken certificate chains. Refusing
            # outright loses real coverage; accepting silently would be
            # dishonest. So: retry unverified, and mark the record so the
            # report says plainly that the certificate could not be checked.
            try:
                import urllib3
                urllib3.disable_warnings()
                resp = SESSION_LEGACY.get(url, headers=headers, timeout=TIMEOUT,
                                          allow_redirects=True, verify=False)
                out["status"] = resp.status_code
                out["tls_unverified"] = True
                if resp.status_code < 400:
                    ok, why = _sanity(resp)
                    if ok:
                        digest = hashlib.sha256(resp.content).hexdigest()
                        out["content_hash"] = digest
                        prior_hash = prior.get("content_hash")
                        out["outcome"] = ("unchanged" if prior_hash == digest
                                          else ("changed" if prior_hash else "new"))
                        out["note"] = f"certificate NOT verified: {str(e)[:80]}"
                        return out
                out["outcome"] = "tls_error"
                out["note"] = str(e)[:120]
                return out
            except Exception:                        # noqa: BLE001
                out["outcome"] = "tls_error"
                out["note"] = str(e)[:120]
                return out
        except Timeout:
            last_err = "timeout"
        except ReqConnError as e:
            last_err = f"connection: {str(e)[:80]}"
        except Exception as e:               # noqa: BLE001
            last_err = f"{type(e).__name__}: {str(e)[:80]}"
        time.sleep(2 ** attempt + random.random())

    out["outcome"] = "unreachable"
    out["note"] = last_err
    return out


def link_run(records: list[dict]) -> dict:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    state = {}
    if STATE_PATH.exists():
        try:
            state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            state = {}

    urls = collect_urls(records)
    results: dict[str, dict] = {}
    last_hit: dict[str, float] = {}

    for url in sorted(urls):
        host = urlparse(url).netloc
        gap = time.time() - last_hit.get(host, 0)
        if gap < PER_HOST_DELAY:
            time.sleep(PER_HOST_DELAY - gap)
        results[url] = check_url(url, state.get(url, {}))
        results[url]["referenced_by"] = urls[url]
        last_hit[host] = time.time()

    STATE_PATH.write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    spread = defaultdict(list)
    for url, res in results.items():
        spread[res["outcome"]].append(url)

    # Two different situations, previously conflated:
    #   systemic  - nearly everything failed => the runner is blocked, abort
    #   partial   - some portals are down => normal for .gov.in, carry on
    broken = (len(spread["dead"]) + len(spread["unreachable"])
              + len(spread["soft_fail"]) + len(spread["tls_error"])
              + len(spread["blocked"]))
    tls_unverified = [u for u, r in results.items() if r.get("tls_unverified")]
    total = max(len(results), 1)

    return {
        "total_urls": len(results),
        "outcomes": {k: len(v) for k, v in spread.items()},
        "broken_ratio": round(broken / total, 3),
        "changed": spread["changed"],
        "dead": spread["dead"],
        "soft_fail": spread["soft_fail"],
        "tls_error": spread["tls_error"],
        "unreachable": spread["unreachable"],
        "blocked": spread["blocked"],
        "tls_unverified": tls_unverified,
        "results": results,
    }


# ======================================================================
# ORCHESTRATOR
# ======================================================================
#!/usr/bin/env python3
"""
PIP run orchestrator — Monday & Thursday, 05:30 IST.

Phase 0  validate BEFORE touching anything (§13). Fail -> abort, change nothing.
Phase 1  cheap link health + change detection (§7 Step 1, §15).
Phase 6  regenerate wrapper counts from the array (§12/§13).
Phase 7  write the run report (§17).
Phase 8  notify (§18, amended: always send, so silence means breakage).

Phases 2-5 (LLM extraction, video discovery, Bengali generation) are not in
this layer. They plug in between phase 1 and phase 6.
"""




SCHEMES = Path("schemes.json")
REPORTS = Path("reports")
PHASE_1_TARGET = 40

# Systemic failure: nearly every URL failed, so the runner is almost certainly
# blocked or offline. Abort and change nothing.
BREAKER_SYSTEMIC = 0.80
# Partial failure: some government portals are down. Normal. Report and carry on.
BREAKER_PARTIAL = 0.30


def notify(text: str) -> None:
    """Write to the Actions job summary and stdout. No external services."""
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)


def main() -> int:
    today = date.today().isoformat()
    REPORTS.mkdir(parents=True, exist_ok=True)

    # ---- Phase 0 --------------------------------------------------------
    errors, warnings, stats = validate(SCHEMES)
    if errors:
        notify(
            f"🔴 <b>PIP run ABORTED — {today}</b>\n\n"
            f"Dataset failed validation before any work began. "
            f"Nothing was changed.\n\n"
            + "\n".join(f"• {e}" for e in errors[:15])
            + (f"\n…and {len(errors) - 15} more" if len(errors) > 15 else "")
        )
        return 1

    # ---- Phase 1 --------------------------------------------------------
    raw = json.loads(SCHEMES.read_text(encoding="utf-8"))
    records = raw["schemes"] if isinstance(raw, dict) else raw
    links = link_run(records)

    systemic = links["broken_ratio"] > BREAKER_SYSTEMIC
    partial = links["broken_ratio"] > BREAKER_PARTIAL

    # ---- Phase 6 --------------------------------------------------------
    counts_rewritten = False
    if not systemic:
        counts_rewritten = regenerate_counts(SCHEMES, stats)

    # ---- Phase 7 : §17 run report ---------------------------------------
    report = {
        "run_date": today,
        "checked_at": today,
        "sources_checked": links["total_urls"],
        "new_candidates": 0,
        "new_verified_records": 0,
        "changed_records": 0,
        "needs_review_records": stats["needs_review_count"],
        "unchanged_records": stats["total_records"],
        "excluded_discontinued_or_replaced": 0,
        "duplicate_candidates": 0,
        "production_count": stats["production_count"],
        "phase_1_target": PHASE_1_TARGET,
        "remaining_to_target": max(0, PHASE_1_TARGET - stats["production_count"]),
        "sources_unavailable": links["dead"] + links["unreachable"]
                               + links["tls_error"] + links["soft_fail"],
        "important_notes": warnings,
        "link_outcomes": links["outcomes"],
        "broken_ratio": links["broken_ratio"],
        "pages_changed": links["changed"],
        "tls_unverified": links["tls_unverified"],
        "circuit_breaker_tripped": systemic,
        "partial_degradation": partial and not systemic,
        "url_diagnostics": {
            u: {"outcome": r["outcome"], "status": r.get("status"),
                "note": r.get("note", ""), "referenced_by": r.get("referenced_by", [])}
            for u, r in links["results"].items()
            if r["outcome"] not in ("unchanged", "new", "changed")
        },
    }
    (REPORTS / f"{today}.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    # ---- Phase 8 --------------------------------------------------------
    if systemic:
        notify(
            f"## 🔴 PIP circuit breaker — {today}\n\n"
            f"**{links['broken_ratio']:.0%} of {links['total_urls']} URLs failed.** "
            f"That is almost certainly the runner being blocked, not the schemes.\n\n"
            f"`schemes.json` was **not modified**. The full per-URL breakdown was "
            f"still written to `reports/{today}.json` so the cause can be diagnosed.\n\n"
            f"Outcomes: `{links['outcomes']}`\n"
        )
        # Deliberately exit 0: a non-zero exit would skip the commit step and
        # throw away the diagnostic report at exactly the moment it is needed.
        return 0

    lines = [
        f"## 🌅 PIP run — {today}",
        "",
        f"- **Production count:** {stats['production_count']} / {PHASE_1_TARGET} (§12 calculated)",
        f"- **Needs review:** {stats['needs_review_count']}"
        + (f" — {', '.join(stats['needs_review_ids'])}"
           if stats["needs_review_ids"] else ""),
        f"- **URLs checked:** {links['total_urls']} "
        f"({links['broken_ratio']:.0%} failing)",
    ]

    if partial:
        lines += ["", f"⚠️ **Partial degradation** — {links['broken_ratio']:.0%} of "
                      f"sources unreachable. Counts were still updated; treat "
                      f"unreachable records as unverified this run."]

    if links["tls_unverified"]:
        lines += ["", f"🔓 **{len(links['tls_unverified'])} host(s) served an "
                      f"unverifiable certificate** — content was read but the "
                      f"certificate was NOT validated:"]
        lines += [f"  - `{u}`" for u in links["tls_unverified"][:8]]

    if links["changed"]:
        lines += ["", f"### 📄 {len(links['changed'])} page(s) changed — need verification"]
        lines += [f"- `{u}`" for u in links["changed"][:12]]

    trouble = [("dead", "🔗 dead"), ("soft_fail", "⚠️ 200-but-empty"),
               ("tls_error", "🔒 TLS failure"), ("unreachable", "📡 unreachable"),
               ("blocked", "🚫 blocked")]
    problems = [(lbl, links[k]) for k, lbl in trouble if links[k]]
    if problems:
        lines.append("\n### Source problems")
        for lbl, urls in problems:
            lines.append(f"**{lbl}: {len(urls)}**")
            lines += [f"- `{u}`" for u in urls[:6]]

    if warnings:
        lines += ["", f"📋 {len(warnings)} spec warning(s) — see "
                      f"`reports/{today}.json`"]
    if counts_rewritten:
        lines += ["", "✏️ Wrapper counts corrected from the array"]
    if not (links["changed"] or problems):
        lines += ["", "✅ No changes. All sources healthy."]

    notify("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
