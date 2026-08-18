from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from consent_runtime_core import (
    ContractError,
    extract_source_section,
    load_profile,
    normalize_visible_text,
    read_json,
    registrable_domain,
    sha256_bytes,
    source_rule_index,
    utc_now,
    validate_schema,
    visible_text_from_html,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mechanically verify a versioned rule profile's source snapshots.")
    parser.add_argument("profile", help="Profile ID or JSON path")
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--update-run", type=Path, help="Update source_checks in an existing audit-run.json")
    parser.add_argument("--offline-source-dir", type=Path, help="Read <source_id>.html fixtures instead of the network")
    parser.add_argument("--require-matched", action="store_true", help="Exit 1 when any source is not MATCHED")
    return parser.parse_args()


def parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def fetch_source(url: str) -> tuple[str, str]:
    original = urlsplit(url)
    request = Request(url, headers={"User-Agent": "consent-privacy-audit-source-check/1.0"})
    with urlopen(request, timeout=45) as response:
        status = int(getattr(response, "status", 200))
        final_url = response.geturl()
        final = urlsplit(final_url)
        if status != 200:
            raise ContractError(f"HTTP {status}")
        if original.scheme != "https" or final.scheme != "https":
            raise ContractError("Rule sources must use HTTPS")
        if registrable_domain(original.hostname or "") != registrable_domain(final.hostname or ""):
            raise ContractError("Source redirected outside its registrable domain")
        charset = response.headers.get_content_charset() or "utf-8"
        raw = response.read().decode(charset, "replace")
        return final_url, raw


def verify(profile: dict, *, offline_source_dir: Path | None = None) -> dict:
    now = datetime.now(timezone.utc)
    dependencies = source_rule_index(profile)
    checks: list[dict] = []
    tasks: list[dict] = []
    for source in profile["sources"]:
        source_id = str(source["source_id"])
        checked_at = utc_now()
        note: str | None = None
        status = "NOT_CHECKED"
        observed_fingerprint: str | None = None
        final_url: str | None = source.get("url")
        try:
            if source["verification_method"] == "LOCAL_IMMUTABLE":
                section = extract_source_section("", source["section_locator"])
            else:
                if offline_source_dir:
                    fixture = offline_source_dir / f"{source_id}.html"
                    if not fixture.exists():
                        raise FileNotFoundError(f"Offline source fixture missing: {fixture}")
                    raw_html = fixture.read_text(encoding="utf-8-sig")
                else:
                    if not source.get("url"):
                        raise ContractError("Network source has no URL")
                    final_url, raw_html = fetch_source(str(source["url"]))
                visible = visible_text_from_html(raw_html)
                section = extract_source_section(visible, source["section_locator"])
            observed_fingerprint = sha256_bytes(normalize_visible_text(section).encode("utf-8"))
            if observed_fingerprint != source["content_fingerprint"]:
                status = "CHANGED"
                note = "Bounded source content no longer matches the human-verified fingerprint"
            else:
                last_verified = parse_datetime(str(source["last_human_verified_at"]))
                threshold = timedelta(days=int(source["staleness_threshold_days"]))
                if now - last_verified > threshold:
                    status = "STALE"
                    note = "Human verification is older than the source staleness threshold"
                else:
                    status = "MATCHED"
        except FileNotFoundError as exc:
            status = "NOT_CHECKED"
            note = str(exc)
        except Exception as exc:
            status = "UNREACHABLE"
            note = f"{type(exc).__name__}: {exc}"
        check = {
            "source_id": source_id,
            "status": status,
            "checked_at": checked_at,
            "dependent_rule_ids": dependencies.get(source_id, []),
            "task_required": status != "MATCHED",
            "note": note,
            "final_url": final_url,
            "expected_fingerprint": source["content_fingerprint"],
            "observed_fingerprint": observed_fingerprint,
        }
        checks.append(check)
        if status != "MATCHED":
            tasks.append(
                {
                    "task_id": f"SOURCE-REVERIFY-{source_id}",
                    "source_id": source_id,
                    "reason": status,
                    "required_action": "Human-review the bounded source, dates, applicability, expectation, and exceptions; version changed meaning rather than overwriting history.",
                }
            )
    return {
        "schema_version": "1.0.0",
        "profile_id": profile["profile_id"],
        "profile_version": profile["profile_version"],
        "checked_at": utc_now(),
        "overall_status": "MATCHED" if all(item["status"] == "MATCHED" for item in checks) else "INCONCLUSIVE",
        "checks": checks,
        "human_reverification_tasks": tasks,
    }


def update_run(path: Path, result: dict) -> None:
    run = read_json(path)
    by_id = {str(item["source_id"]): item for item in run.get("source_checks", [])}
    for item in result["checks"]:
        by_id[item["source_id"]] = {key: item[key] for key in ["source_id", "status", "checked_at", "dependent_rule_ids", "task_required", "note"]}
    run["source_checks"] = sorted(by_id.values(), key=lambda item: item["source_id"])
    validate_schema(run, "audit-run.schema.json", label=str(path))
    write_json(path, run)


def main() -> int:
    args = parse_args()
    try:
        profile = load_profile(args.profile)
        result = verify(profile, offline_source_dir=args.offline_source_dir)
        write_json(args.output, result)
        if args.update_run:
            update_run(args.update_run, result)
    except (ContractError, OSError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    for check in result["checks"]:
        print(f"{check['status']} {check['source_id']}")
    if args.require_matched and result["overall_status"] != "MATCHED":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
