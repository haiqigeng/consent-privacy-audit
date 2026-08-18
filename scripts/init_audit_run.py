from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit

from consent_runtime_core import (
    FINGERPRINT_ALGO_VERSION,
    IDENTITY_NORMALIZATION_VERSION,
    PRIORITY_RUBRIC_VERSION,
    REQUIRED_CORE_SCENARIOS,
    ROOT,
    SCENARIO_CONTRACT_VERSION,
    ContractError,
    load_profile,
    load_vendor_registry,
    read_json,
    utc_now,
    validate_schema,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize a canonical consent runtime audit run.")
    parser.add_argument("intake", type=Path, help="Consolidated intake JSON")
    parser.add_argument("--output", "-o", type=Path, required=True)
    return parser.parse_args()


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise ContractError(f"URL must be public HTTP(S) without embedded credentials: {url}")
    netloc = parts.hostname.lower()
    if parts.port and not ((parts.scheme == "https" and parts.port == 443) or (parts.scheme == "http" and parts.port == 80)):
        netloc += f":{parts.port}"
    return f"{parts.scheme.lower()}://{netloc}"


def require_list(value: object, label: str, *, allow_empty: bool = True) -> list:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ContractError(f"{label} must be {'a non-empty ' if not allow_empty else 'a '}list")
    return value


def build(intake: dict) -> dict:
    urls = [str(item) for item in require_list(intake.get("urls"), "urls", allow_empty=False)]
    origins = {origin_of(url) for url in urls}
    if len(origins) != 1:
        raise ContractError("V1 intake supports one exact origin per audit run")
    origin = next(iter(origins))
    environment = str(intake.get("environment", "unknown"))
    if environment not in {"production", "staging", "preproduction", "test", "unknown"}:
        raise ContractError(f"Unsupported environment: {environment}")
    deployment_verified = intake.get("deployment_verified")
    if not isinstance(deployment_verified, bool):
        raise ContractError("deployment_verified must be boolean")
    deployment_evidence = [str(item) for item in require_list(intake.get("deployment_evidence", []), "deployment_evidence")]
    selected_profiles = intake.get("rule_profiles", [{"profile_id": "neutral-technical", "applicability": "CONFIRMED"}])
    require_list(selected_profiles, "rule_profiles", allow_empty=False)
    profile_rows: list[dict] = []
    source_checks: list[dict] = []
    for selection in selected_profiles:
        if not isinstance(selection, dict) or not selection.get("profile_id"):
            raise ContractError("Each rule profile selection requires profile_id")
        profile = load_profile(str(selection["profile_id"]))
        applicability = str(selection.get("applicability", "UNKNOWN"))
        profile_rows.append({"profile_id": profile["profile_id"], "version": profile["profile_version"], "applicability": applicability})
        for source in profile["sources"]:
            source_checks.append(
                {
                    "source_id": source["source_id"],
                    "status": "NOT_CHECKED",
                    "checked_at": None,
                    "dependent_rule_ids": sorted(
                        rule["rule_id"] for rule in profile["rules"] if source["source_id"] in rule["source_ids"]
                    ),
                    "task_required": True,
                    "note": "Run-time verification has not executed",
                }
            )
    actions_by_scenario = intake.get("actions_by_scenario", {})
    if not isinstance(actions_by_scenario, dict):
        raise ContractError("actions_by_scenario must be an object")
    scenarios = [
        {
            "scenario_id": scenario_id,
            "scenario_class": scenario_class,
            "status": "REGISTERED",
            "context_id": None,
            "pages": list(urls),
            "actions": [str(value) for value in actions_by_scenario.get(scenario_class, [])],
            "state_verified": None,
            "capture_status": {key: "REGISTERED" for key in ["network", "cookies", "storage", "cmp_state", "scripts_embeds", "screenshot", "attribution", "service_workers"]},
            "limitations": [],
        }
        for scenario_id, scenario_class in REQUIRED_CORE_SCENARIOS
    ]
    for conditional in intake.get("conditional_scenarios", []):
        scenario_class = str(conditional)
        if scenario_class not in {"GRANULAR_DENIED", "REJECTED_TO_ACCEPTED"}:
            raise ContractError(f"Unsupported v1 conditional scenario: {scenario_class}")
        scenarios.append(
            {
                "scenario_id": f"SCN-{scenario_class}",
                "scenario_class": scenario_class,
                "status": "REGISTERED",
                "context_id": None,
                "pages": list(urls),
                "actions": [str(value) for value in actions_by_scenario.get(scenario_class, [])],
                "state_verified": None,
                "capture_status": {key: "REGISTERED" for key in ["network", "cookies", "storage", "cmp_state", "scripts_embeds", "screenshot", "attribution", "service_workers"]},
                "limitations": [],
            }
        )
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    now = utc_now()
    value = {
        "schema_version": "1.0.0",
        "run_id": str(intake.get("run_id") or f"CONSENT-{now.replace(':', '').replace('+', '').replace('.', '-') }"),
        "skill_version": version,
        "status": "PLANNED",
        "created_at": now,
        "started_at": None,
        "completed_at": None,
        "abort_reason": None,
        "site": {
            "origin": origin,
            "environment": environment,
            "deployment_verified": deployment_verified,
            "deployment_evidence": deployment_evidence,
        },
        "scope": {
            "urls": urls,
            "markets": [str(item) for item in require_list(intake.get("markets", []), "markets")],
            "declaration_urls": [str(item) for item in require_list(intake.get("declaration_urls", []), "declaration_urls")],
            "exclusions": [str(item) for item in require_list(intake.get("exclusions", []), "exclusions")],
            "authenticated_boundaries": [str(item) for item in require_list(intake.get("authenticated_boundaries", []), "authenticated_boundaries")],
        },
        "browser": {
            "engine": "chromium",
            "version": "PENDING_READINESS",
            "headed": bool(intake.get("headed", True)),
            "viewport": {"width": int(intake.get("viewport_width", 1440)), "height": int(intake.get("viewport_height", 1000)), "device_scale_factor": 1.0},
            "locale": str(intake.get("locale", "fr-FR")),
            "timezone": str(intake.get("timezone", "Europe/Paris")),
            "user_agent": "PENDING_READINESS",
            "cache_policy": "fresh_context",
            "service_worker_policy": "allow_and_capture",
            "extensions": [],
        },
        "network_route": {
            "route_id": str(intake.get("network_route_id", "DIRECT-UNVERIFIED")),
            "proxy": intake.get("proxy"),
            "externally_verified_region": intake.get("externally_verified_region"),
            "browser_geolocation_emulated": bool(intake.get("browser_geolocation_emulated", False)),
        },
        "rule_profiles": profile_rows,
        "source_checks": source_checks,
        "cmp": {"adapter_id": None, "adapter_version": None, "provider": None, "detection_confidence": "UNKNOWN", "interaction_method": "NONE", "limitations": []},
        "scenarios": scenarios,
        "capture_capabilities": {"network": False, "cookies": False, "storage": False, "cmp_state": False, "scripts_embeds": False, "service_workers": False, "screenshots": False, "initiators": False},
        "evidence_policy": {"raw_har_delivered": False, "request_bodies_retained": False, "cookie_values_retained": False, "canary_values_retained": False, "restricted_evidence_authorized": bool(intake.get("restricted_evidence_authorized", False))},
        "technical_priority_rubric_version": PRIORITY_RUBRIC_VERSION,
        "finding_fingerprint_algo_version": FINGERPRINT_ALGO_VERSION,
        "identity_normalization_version": IDENTITY_NORMALIZATION_VERSION,
        "vendor_signature_registry_version": str(load_vendor_registry()["registry_version"]),
        "scenario_contract_version": SCENARIO_CONTRACT_VERSION,
        "outputs": {},
        "overall_technical_outcome": None,
    }
    validate_schema(value, "audit-run.schema.json", label="initialized audit run")
    return value


def main() -> int:
    args = parse_args()
    try:
        intake = read_json(args.intake)
        if not isinstance(intake, dict):
            raise ContractError("Intake root must be an object")
        value = build(intake)
        write_json(args.output, value)
    except (ContractError, OSError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
