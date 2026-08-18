from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from consent_runtime_core import (
    ContractError,
    assert_privacy_safe,
    iter_jsonl,
    read_json,
    sha256_file,
    utc_now,
    validate_schema,
    write_json,
)


KIND_BY_SURFACE = {
    "NETWORK": "REQUEST_EXCERPT",
    "CANARY": "REQUEST_EXCERPT",
    "CMP_STATE": "STATE_TIMING",
    "CONSENT_SIGNAL": "STATE_TIMING",
    "DOM": "DOM_EXCERPT",
    "VISUAL": "OTHER",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Materialize sanitized evidence excerpts and their validated index.")
    parser.add_argument("run", type=Path)
    parser.add_argument("observations", type=Path)
    parser.add_argument("findings", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    return parser.parse_args()


def observation_excerpt(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "evidence_id": row["evidence_id"],
        "fact_class": row["fact_class"],
        "scenario_id": row["scenario_id"],
        "scenario_class": row["scenario_class"],
        "action_window": row["action_window"],
        "observed_at": row["observed_at"],
        "page_url": row["page_url"],
        "surface": row["surface"],
        "technical_test_status": row["technical_test_status"],
        "rule_applicability": row["rule_applicability"],
        "vendor_product": row["vendor_product"],
        "purpose_candidate": row["purpose_candidate"],
        "observed_initiator": row["observed_initiator"],
        "suspected_implementation_layer": row["suspected_implementation_layer"],
        "data": row["data"],
    }


def build_index(
    run: dict[str, Any], observations: list[dict[str, Any]], findings: list[dict[str, Any]],
    *, output: Path, evidence_dir: Path,
) -> dict[str, Any]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    artifacts: dict[str, dict[str, Any]] = {}
    for row in observations:
        excerpt = observation_excerpt(row)
        assert_privacy_safe(excerpt, label=str(row["evidence_id"]))
        path = evidence_dir / f"{row['evidence_id']}.json"
        write_json(path, excerpt)
        try:
            relative = path.resolve().relative_to(output.parent.resolve()).as_posix()
        except ValueError as exc:
            raise ContractError("Evidence directory must be inside the delivery directory") from exc
        artifacts[str(row["evidence_id"])] = {
            "evidence_id": row["evidence_id"],
            "kind": KIND_BY_SURFACE.get(str(row["surface"]), "OTHER"),
            "path": relative,
            "sha256": sha256_file(path),
            "restricted": False,
            "sanitization_status": "PASSED",
            "contains_canary_value": False,
            "contains_personal_data": False,
            "screenshot_review": None,
        }
    scenario_by_id = {str(item["scenario_id"]): item for item in run["scenarios"]}
    referenced = {str(evidence_id) for finding in findings for evidence_id in finding["evidence_ids"]}
    for evidence_id in sorted(referenced - set(artifacts)):
        scenario_id = evidence_id.removeprefix("EVD-").removesuffix("-manifest")
        scenario = scenario_by_id.get(scenario_id)
        if not scenario:
            raise ContractError(f"Finding references unknown evidence with no observation: {evidence_id}")
        excerpt = {
            "schema_version": "1.0.0",
            "evidence_id": evidence_id,
            "fact_class": "BROWSER_OBSERVED",
            "source": "audit-run scenario manifest",
            "scenario_id": scenario["scenario_id"],
            "scenario_class": scenario["scenario_class"],
            "status": scenario["status"],
            "state_verified": scenario["state_verified"],
            "pages": scenario["pages"],
            "limitations": scenario["limitations"],
        }
        assert_privacy_safe(excerpt, label=evidence_id)
        path = evidence_dir / f"{evidence_id}.json"
        write_json(path, excerpt)
        relative = path.resolve().relative_to(output.parent.resolve()).as_posix()
        artifacts[evidence_id] = {
            "evidence_id": evidence_id,
            "kind": "STATE_TIMING",
            "path": relative,
            "sha256": sha256_file(path),
            "restricted": False,
            "sanitization_status": "PASSED",
            "contains_canary_value": False,
            "contains_personal_data": False,
            "screenshot_review": None,
        }
    result = {
        "schema_version": "1.0.0",
        "run_id": run["run_id"],
        "generated_at": utc_now(),
        "artifacts": [artifacts[key] for key in sorted(artifacts)],
    }
    validate_schema(result, "evidence-index.schema.json", label="evidence index")
    assert_privacy_safe(result, label="evidence index")
    write_json(output, result)
    return result


def main() -> int:
    args = parse_args()
    try:
        run = read_json(args.run)
        validate_schema(run, "audit-run.schema.json", label=str(args.run))
        observations = list(iter_jsonl(args.observations))
        findings = read_json(args.findings)
        if not isinstance(findings, list):
            raise ContractError("findings.json must be an array")
        for row in observations:
            validate_schema(row, "observation.schema.json", label=row["observation_id"])
        for finding in findings:
            validate_schema(finding, "finding.schema.json", label=finding.get("finding_fingerprint", "finding"))
        result = build_index(run, observations, findings, output=args.output, evidence_dir=args.evidence_dir)
        run["outputs"]["evidence_index"] = {"path": args.output.name, "sha256": sha256_file(args.output)}
        validate_schema(run, "audit-run.schema.json", label=str(args.run))
        write_json(args.run, run)
    except (ContractError, OSError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(f"{args.output} ({len(result['artifacts'])} artifact(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
