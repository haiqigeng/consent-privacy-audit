from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from consent_runtime_core import sha256_file, write_json, write_jsonl  # noqa: E402
from init_audit_run import build as build_run  # noqa: E402


NOW = "2026-08-18T12:00:00+00:00"


def complete_run(*, urls: list[str] | None = None, profiles: bool = True) -> dict[str, Any]:
    selections = [{"profile_id": "neutral-technical", "applicability": "CONFIRMED"}]
    if profiles:
        selections.append({"profile_id": "cnil-fr", "applicability": "CONFIRMED"})
    run = build_run(
        {
            "run_id": "TEST-RUN-001",
            "urls": urls or ["https://example.test/"],
            "environment": "test",
            "deployment_verified": True,
            "deployment_evidence": ["controlled fixture build 1"],
            "rule_profiles": selections,
            "markets": [],
            "declaration_urls": ["https://example.test/cookies"],
            "exclusions": [],
            "authenticated_boundaries": ["/account"],
            "network_route_id": "FIXTURE-LOCAL",
            "externally_verified_region": None,
            "headed": False,
        }
    )
    run["status"] = "COMPLETE"
    run["started_at"] = NOW
    run["completed_at"] = NOW
    run["browser"]["version"] = "fixture-chromium"
    run["browser"]["user_agent"] = "fixture-user-agent"
    run["cmp"] = {
        "adapter_id": "generic-custom-banner",
        "adapter_version": "1.0.0",
        "provider": "Controlled CMP",
        "detection_confidence": "PROBABLE",
        "interaction_method": "UI",
        "limitations": [],
    }
    for check in run["source_checks"]:
        check.update({"status": "MATCHED", "checked_at": NOW, "task_required": False, "note": None})
    for index, scenario in enumerate(run["scenarios"]):
        scenario.update({"status": "COMPLETE", "context_id": f"CTX-{index}", "state_verified": True, "limitations": []})
        scenario["capture_status"] = {
            "network": "COMPLETE", "cookies": "COMPLETE", "storage": "COMPLETE", "cmp_state": "COMPLETE",
            "scripts_embeds": "COMPLETE", "screenshot": "NOT_TESTED", "attribution": "COMPLETE", "service_workers": "COMPLETE",
        }
    run["capture_capabilities"] = {
        "network": True, "cookies": True, "storage": True, "cmp_state": True,
        "scripts_embeds": True, "service_workers": True, "screenshots": False, "initiators": True,
    }
    run["overall_technical_outcome"] = "NO_SAMPLED_CONTRADICTION"
    return run


def observation(
    run: dict[str, Any], *, index: int, scenario_id: str, scenario_class: str,
    action_window: str, page_url: str = "https://example.test/", surface: str = "NETWORK",
    vendor_id: str | None = "google", product_id: str | None = "google-analytics",
    display_name: str = "Google Analytics", confidence: str = "CONFIRMED",
    purpose: str = "ANALYTICS", layer: str = "HARDCODED_OR_BUNDLED",
    url: str = "https://www.google-analytics.com/g/collect?en=page_view&cid=fixture",
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    observation_id = f"OBS-fixture-{index}"
    payload = data if data is not None else {
        "method": "GET", "url": url, "query_parameter_names": ["cid", "en"], "resource_type": "fetch",
        "response_status": 204, "failure": None, "service_worker": layer == "SERVICE_WORKER", "canary_detected": surface == "CANARY",
    }
    return {
        "schema_version": "1.0.0",
        "observation_id": observation_id,
        "run_id": run["run_id"],
        "scenario_id": scenario_id,
        "scenario_class": scenario_class,
        "action_window": action_window,
        "observed_at": f"2026-08-18T12:00:{index:02d}+00:00",
        "page_url": page_url,
        "surface": surface,
        "fact_class": "BROWSER_OBSERVED",
        "technical_test_status": "UNEXPECTED_BEHAVIOUR_OBSERVED" if surface == "CANARY" else "INCONCLUSIVE",
        "rule_applicability": "CONFIRMED",
        "vendor_product": {"vendor_id": vendor_id, "product_id": product_id, "display_name": display_name, "confidence": confidence},
        "purpose_candidate": purpose,
        "observed_initiator": "https://example.test/app.js",
        "suspected_implementation_layer": layer,
        "data": payload,
        "evidence_id": f"EVD-fixture-{index}",
    }


def write_canonical(directory: Path, run: dict[str, Any], observations: list[dict[str, Any]], findings: list[dict[str, Any]], declaration: dict[str, Any]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    run_path = directory / "audit-run.json"
    observation_path = directory / "observations.jsonl"
    finding_path = directory / "findings.json"
    declaration_path = directory / "declaration-diff.json"
    write_jsonl(observation_path, observations)
    write_json(finding_path, findings)
    write_json(declaration_path, declaration)
    run["outputs"]["observations"] = {"path": observation_path.name, "sha256": sha256_file(observation_path)}
    run["outputs"]["findings"] = {"path": finding_path.name, "sha256": sha256_file(finding_path)}
    run["outputs"]["declaration_diff"] = {"path": declaration_path.name, "sha256": sha256_file(declaration_path)}
    write_json(run_path, run)


def clone(value: Any) -> Any:
    return deepcopy(value)
