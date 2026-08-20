
#!/usr/bin/env python3
"""
Prokolpo Bondhu — PIP Monitor (single-file build).

Runs Monday & Thursday 05:30 IST via .github/workflows/pip-monitor.yml.

Phases implemented here:
  0  validate before touching anything (§9/§12/§14) — abort on error
  1  link health + cheap change detection (§7 Step 1, §15)
  6  regenerate wrapper counts from the array (§12/§13)
  7  run report -> reports/YYYY-MM-DD.json (§17)
  8  notify via Telegram (§18, amended: always send)

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
from requests.exceptions import SSLError, Timeout, ConnectionError as ReqConnError
from urllib.parse import urlparse
import hashlib
import json
import os
import random
import re
import requests
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



UA = "ProkolpoBondhu-PIP/1.0 (public scheme monitoring; +https://github.com/26pritamance4/prokolpo-data)"
TIMEOUT = 25
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
    headers = {"User-Agent": UA, "Accept": "*/*"}
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
            resp = requests.get(url, headers=headers, timeout=TIMEOUT,
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
            out["outcome"] = "tls_error"
            out["note"] = str(e)[:120]
            return out                       # never silently disable verification
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

    # "blocked" counts here: a runner IP being rate-limited or firewalled
    # looks exactly like this, and is precisely what the breaker is for.
    broken = (len(spread["dead"]) + len(spread["unreachable"])
              + len(spread["soft_fail"]) + len(spread["tls_error"])
              + len(spread["blocked"]))
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

# If more than this share of URLs break in one run, assume the runner or the
# network is at fault rather than the government of India. Abort, commit nothing.
BREAKER_RATIO = 0.30

TG_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TG_CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")


def notify(text: str) -> None:
    """Telegram if configured, always the Actions job summary."""
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")

    if not (TG_TOKEN and TG_CHAT):
        print("[notify] Telegram secrets absent — job summary only")
        print(text)
        return

    body = text if len(text) <= 4000 else text[:3900] + "\n…(truncated)"
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT, "text": body,
                  "parse_mode": "HTML", "disable_web_page_preview": True},
            timeout=20,
        )
        if r.status_code != 200:
            print(f"[notify] Telegram failed: {r.status_code} {r.text[:200]}")
    except Exception as e:                                   # noqa: BLE001
        print(f"[notify] Telegram error: {e}")


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

    breaker_tripped = links["broken_ratio"] > BREAKER_RATIO

    # ---- Phase 6 --------------------------------------------------------
    counts_rewritten = False
    if not breaker_tripped:
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
        "pages_changed": links["changed"],
        "circuit_breaker_tripped": breaker_tripped,
    }
    (REPORTS / f"{today}.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    # ---- Phase 8 --------------------------------------------------------
    if breaker_tripped:
        notify(
            f"🔴 <b>PIP circuit breaker — {today}</b>\n\n"
            f"{links['broken_ratio']:.0%} of URLs failed "
            f"({links['total_urls']} checked). That is almost certainly a "
            f"network or runner fault, not the schemes.\n\n"
            f"<b>Nothing was committed.</b>"
        )
        return 1

    lines = [
        f"🌅 <b>PIP run — {today}</b>",
        "",
        f"Production count: <b>{stats['production_count']}</b> / {PHASE_1_TARGET}"
        f"  (§12 calculated)",
        f"Needs review: {stats['needs_review_count']}"
        + (f" — {', '.join(stats['needs_review_ids'])}"
           if stats["needs_review_ids"] else ""),
        f"URLs checked: {links['total_urls']}",
    ]

    if links["changed"]:
        lines += ["", f"📄 <b>{len(links['changed'])} page(s) changed</b> "
                      f"— need verification:"]
        lines += [f"• {u}" for u in links["changed"][:10]]

    trouble = [("dead", "🔗 dead"), ("soft_fail", "⚠️ 200-but-empty"),
               ("tls_error", "🔒 TLS"), ("unreachable", "📡 unreachable"),
               ("blocked", "🚫 blocked")]
    problems = [(lbl, links[k]) for k, lbl in trouble if links[k]]
    if problems:
        lines.append("")
        for lbl, urls in problems:
            lines.append(f"{lbl}: {len(urls)}")
            lines += [f"  • {u}" for u in urls[:5]]

    if warnings:
        lines += ["", f"📋 {len(warnings)} spec warning(s) — see report"]
    if counts_rewritten:
        lines += ["", "✏️ Wrapper counts corrected from the array"]
    if not (links["changed"] or problems):
        lines += ["", "✅ No changes. All sources healthy."]

    notify("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
