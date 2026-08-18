from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from consent_runtime_core import (
    ContractError,
    normalized_location_pattern,
    read_json,
    sha256_file,
    utc_now,
    validate_schema,
    write_json,
)


GLOBAL_REASON_ORDER = [
    "DIFFERENT_ORIGIN_OR_ENVIRONMENT",
    "FINGERPRINT_ALGORITHM_CHANGED",
    "RULE_MEANING_OR_APPLICABILITY_CHANGED",
    "REQUIRED_PROFILE_OR_SOURCE_NOT_VERIFIED",
    "SCENARIO_DEFINITION_CHANGED",
    "MARKET_OR_NETWORK_ROUTE_CHANGED",
    "REQUIRED_CAPTURE_CAPABILITY_MISSING",
    "REQUIRED_SCENARIO_NOT_EXECUTED",
    "LOCATION_NOT_SAMPLED_IN_BOTH_RUNS",
    "IDENTITY_NORMALIZATION_CHANGED",
    "CONSENT_ADAPTER_SEMANTICS_CHANGED",
]
CORE_SCENARIOS = {"UNTOUCHED", "REJECTED", "ACCEPTED", "ACCEPTED_TO_WITHDRAWN", "PERSISTENCE_ACCEPTED", "PERSISTENCE_REJECTED"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare two independently validated consent audit deliveries.")
    parser.add_argument("previous", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    return parser.parse_args()


def load_run(directory: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run = read_json(directory / "audit-run.json")
    findings = read_json(directory / "findings.json")
    validate_schema(run, "audit-run.schema.json", label=str(directory / "audit-run.json"))
    if run["status"] != "COMPLETE":
        raise ContractError(f"Run is not complete: {directory}")
    if not isinstance(findings, list):
        raise ContractError(f"findings.json must be an array: {directory}")
    for finding in findings:
        validate_schema(finding, "finding.schema.json", label=finding.get("finding_fingerprint", "finding"))
    return run, findings


def profiles(run: dict[str, Any]) -> list[tuple[str, str, str]]:
    return sorted((str(item["profile_id"]), str(item["version"]), str(item["applicability"])) for item in run["rule_profiles"])


def scenario_definitions(run: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    return sorted((str(item["scenario_class"]), tuple(sorted(str(action) for action in item["actions"]))) for item in run["scenarios"])


def completed_classes(run: dict[str, Any]) -> set[str]:
    return {str(item["scenario_class"]) for item in run["scenarios"] if item["status"] == "COMPLETE" and item.get("state_verified") is True}


def sample_bases(run: dict[str, Any]) -> set[str]:
    return {normalized_location_pattern(str(url), "page").split("#", 1)[0] for item in run["scenarios"] for url in item["pages"]}


def slice_id(finding: dict[str, Any]) -> str:
    inputs = finding["fingerprint_inputs"]
    base = str(inputs["location_pattern"]).split("#", 1)[0]
    return f"{inputs['scenario_class']}|{base}"


def compatibility(previous: dict[str, Any], current: dict[str, Any]) -> tuple[str, list[str], set[str]]:
    reasons: set[str] = set()
    if (previous["site"]["origin"], previous["site"]["environment"]) != (current["site"]["origin"], current["site"]["environment"]):
        reasons.add("DIFFERENT_ORIGIN_OR_ENVIRONMENT")
    if previous["finding_fingerprint_algo_version"] != current["finding_fingerprint_algo_version"]:
        reasons.add("FINGERPRINT_ALGORITHM_CHANGED")
    if profiles(previous) != profiles(current):
        reasons.add("RULE_MEANING_OR_APPLICABILITY_CHANGED")
    if any(item["status"] != "MATCHED" for item in previous["source_checks"] + current["source_checks"]):
        reasons.add("REQUIRED_PROFILE_OR_SOURCE_NOT_VERIFIED")
    if previous["scenario_contract_version"] != current["scenario_contract_version"] or scenario_definitions(previous) != scenario_definitions(current):
        reasons.add("SCENARIO_DEFINITION_CHANGED")
    previous_route = (tuple(sorted(previous["scope"]["markets"])), previous["network_route"]["route_id"], previous["network_route"]["externally_verified_region"])
    current_route = (tuple(sorted(current["scope"]["markets"])), current["network_route"]["route_id"], current["network_route"]["externally_verified_region"])
    if previous_route != current_route:
        reasons.add("MARKET_OR_NETWORK_ROUTE_CHANGED")
    required_capture = {"network", "cookies", "storage", "cmp_state", "scripts_embeds", "service_workers", "initiators"}
    if any(not run["capture_capabilities"].get(key, False) for run in (previous, current) for key in required_capture):
        reasons.add("REQUIRED_CAPTURE_CAPABILITY_MISSING")
    if not CORE_SCENARIOS <= completed_classes(previous) or not CORE_SCENARIOS <= completed_classes(current):
        reasons.add("REQUIRED_SCENARIO_NOT_EXECUTED")
    if (previous["identity_normalization_version"], previous["vendor_signature_registry_version"]) != (current["identity_normalization_version"], current["vendor_signature_registry_version"]):
        reasons.add("IDENTITY_NORMALIZATION_CHANGED")
    previous_adapter = (previous["cmp"]["adapter_id"], previous["cmp"]["adapter_version"])
    current_adapter = (current["cmp"]["adapter_id"], current["cmp"]["adapter_version"])
    if previous_adapter != current_adapter:
        reasons.add("CONSENT_ADAPTER_SEMANTICS_CHANGED")
    previous_bases, current_bases = sample_bases(previous), sample_bases(current)
    overlap_bases = previous_bases & current_bases
    overlap_classes = completed_classes(previous) & completed_classes(current)
    slices = {f"{scenario}|{base}" for scenario in overlap_classes for base in overlap_bases}
    if not slices or previous_bases != current_bases:
        reasons.add("LOCATION_NOT_SAMPLED_IN_BOTH_RUNS")
    fatal = reasons - {"LOCATION_NOT_SAMPLED_IN_BOTH_RUNS"}
    if fatal or not slices:
        scope = "NOT_COMPARABLE"
    elif reasons:
        scope = "PARTIALLY_COMPARABLE"
    else:
        scope = "FULLY_COMPARABLE"
    ordered = [reason for reason in GLOBAL_REASON_ORDER if reason in reasons]
    return scope, ordered, slices


def previous_fixed_fingerprints(directory: Path) -> set[str]:
    path = directory / "delta.json"
    if not path.exists():
        return set()
    value = read_json(path)
    validate_schema(value, "delta.schema.json", label=str(path))
    return {str(item["finding_fingerprint"]) for item in value["items"] if item["classification"] == "FIXED"}


def compare(previous_dir: Path, current_dir: Path) -> dict[str, Any]:
    previous, previous_findings = load_run(previous_dir)
    current, current_findings = load_run(current_dir)
    scope, reasons, slices = compatibility(previous, current)
    previous_by_fp = {str(item["finding_fingerprint"]): item for item in previous_findings}
    current_by_fp = {str(item["finding_fingerprint"]): item for item in current_findings}
    formerly_fixed = previous_fixed_fingerprints(previous_dir)
    items: list[dict[str, Any]] = []
    all_fingerprints = sorted(set(previous_by_fp) | set(current_by_fp))
    for fingerprint in all_fingerprints:
        earlier = previous_by_fp.get(fingerprint)
        later = current_by_fp.get(fingerprint)
        finding = later or earlier
        assert finding is not None
        item_slice = slice_id(finding)
        item_reasons: list[str] = []
        if scope == "NOT_COMPARABLE":
            classification = "NOT_COMPARABLE"
            item_reasons = list(reasons)
        elif item_slice not in slices:
            classification = "NOT_COMPARABLE"
            item_reasons = ["LOCATION_NOT_SAMPLED_IN_BOTH_RUNS"]
        elif earlier and later:
            classification = "PERSISTENT"
        elif earlier:
            classification = "FIXED"
        elif fingerprint in formerly_fixed:
            classification = "REGRESSED"
        else:
            classification = "NEW"
        items.append(
            {
                "finding_fingerprint": fingerprint,
                "classification": classification,
                "previous_present": earlier is not None,
                "current_present": later is not None,
                "slice_id": item_slice,
                "reason_codes": item_reasons,
            }
        )
    priority_changes = []
    for fingerprint in sorted(set(previous_by_fp) & set(current_by_fp)):
        before = previous_by_fp[fingerprint]["technical_priority"]
        after = current_by_fp[fingerprint]["technical_priority"]
        if before != after:
            priority_changes.append({"finding_fingerprint": fingerprint, "previous_priority": before, "current_priority": after, "comparable": scope != "NOT_COMPARABLE" and previous["technical_priority_rubric_version"] == current["technical_priority_rubric_version"]})
    result = {
        "schema_version": "1.0.0",
        "previous_run_id": previous["run_id"],
        "current_run_id": current["run_id"],
        "generated_at": utc_now(),
        "comparison_scope": scope,
        "reason_codes": reasons,
        "versions": {
            "previous": {
                "fingerprint": previous["finding_fingerprint_algo_version"],
                "priority": previous["technical_priority_rubric_version"],
                "identity": previous["identity_normalization_version"],
                "registry": previous["vendor_signature_registry_version"],
                "profiles": profiles(previous),
                "adapter": [previous["cmp"]["adapter_id"], previous["cmp"]["adapter_version"]],
            },
            "current": {
                "fingerprint": current["finding_fingerprint_algo_version"],
                "priority": current["technical_priority_rubric_version"],
                "identity": current["identity_normalization_version"],
                "registry": current["vendor_signature_registry_version"],
                "profiles": profiles(current),
                "adapter": [current["cmp"]["adapter_id"], current["cmp"]["adapter_version"]],
            },
        },
        "compared_slices": sorted(slices),
        "items": items,
        "priority_changes": priority_changes,
    }
    validate_schema(result, "delta.schema.json", label="delta")
    return result


def render_markdown(delta: dict[str, Any]) -> str:
    lines = [
        "# Consent Runtime Rescan Delta", "",
        f"Comparison scope: `{delta['comparison_scope']}`.", "",
        f"Reason codes: {', '.join(f'`{item}`' for item in delta['reason_codes']) or 'none'}.", "",
        "| Classification | Finding fingerprint | Slice |",
        "| --- | --- | --- |",
    ]
    for item in delta["items"]:
        lines.append(f"| {item['classification']} | `{item['finding_fingerprint']}` | `{item['slice_id']}` |")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    try:
        result = compare(args.previous.resolve(), args.current.resolve())
        write_json(args.output, result)
        markdown_path = args.output.with_suffix(".md")
        markdown_path.write_text(render_markdown(result), encoding="utf-8", newline="\n")
        current_run_path = args.current.resolve() / "audit-run.json"
        current = read_json(current_run_path)
        current["outputs"]["delta"] = {"path": args.output.name, "sha256": sha256_file(args.output)}
        current["outputs"]["delta_report"] = {"path": markdown_path.name, "sha256": sha256_file(markdown_path)}
        validate_schema(current, "audit-run.schema.json", label=str(current_run_path))
        write_json(current_run_path, current)
    except (ContractError, OSError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
