from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from consent_runtime_core import (
    ContractError,
    FINGERPRINT_ALGO_VERSION,
    PRIORITY_RUBRIC_VERSION,
    default_priority_inputs,
    finding_fingerprint,
    iter_jsonl,
    load_profile,
    normalized_location_pattern,
    read_json,
    registrable_domain,
    sha256_file,
    technical_priority,
    validate_schema,
    vendor_product_key,
    write_json,
)


TRACKING_PATH_RE = re.compile(r"/(?:collect|track|tracking|event|events|beacon|pixel|analytics)(?:/|$)", re.I)
STABLE_ID_NAMES = {"cid", "client_id", "clientid", "uid", "user_id", "userid", "_ga", "fbp", "fbc", "gclid", "dclid"}
EXCLUDED_PURPOSES = {"CMP", "TAG_MANAGER", "FUNCTIONAL", "SECURITY"}
CORE_SCENARIOS = {"UNTOUCHED", "REJECTED", "ACCEPTED", "ACCEPTED_TO_WITHDRAWN", "PERSISTENCE_ACCEPTED", "PERSISTENCE_REJECTED"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Turn minimized browser observations into deterministic technical findings.")
    parser.add_argument("run", type=Path)
    parser.add_argument("observations", type=Path)
    parser.add_argument("--declaration-diff", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    return parser.parse_args()


def profile_rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    source_checks = {str(item["source_id"]): item for item in run.get("source_checks", [])}
    result: dict[str, dict[str, Any]] = {}
    for selection in run["rule_profiles"]:
        profile = load_profile(str(selection["profile_id"]))
        if profile["profile_version"] != selection["version"]:
            raise ContractError(f"Selected profile version drift: {profile['profile_id']}")
        source_by_id = {str(item["source_id"]): item for item in profile["sources"]}
        for rule in profile["rules"]:
            if rule.get("superseded"):
                continue
            statuses = [source_checks.get(source_id, {"status": "NOT_CHECKED"})["status"] for source_id in rule["source_ids"]]
            authorities = sorted({str(source_by_id[source_id]["authority"]) for source_id in rule["source_ids"]})
            result[str(rule["rule_id"])] = {
                "rule": rule,
                "profile_id": profile["profile_id"],
                "applicability": selection["applicability"],
                "sources_ready": all(status == "MATCHED" for status in statuses),
                "source_statuses": statuses,
                "authority": "; ".join(authorities),
            }
    return result


def evaluation_scenario(observation: dict[str, Any]) -> str | None:
    scenario_class = str(observation["scenario_class"])
    window = str(observation["action_window"])
    if window == "initial_load":
        return "UNTOUCHED"
    if scenario_class == "REJECTED" and ("reject" in window or window.startswith(("page_", "synthetic_", "final_"))):
        return "REJECTED"
    if scenario_class == "PERSISTENCE_REJECTED" and ("reject" in window or window == "persistence_revisit"):
        return "PERSISTENCE_REJECTED" if window == "persistence_revisit" else "REJECTED"
    if scenario_class == "ACCEPTED_TO_WITHDRAWN" and ("withdraw" in window or window.startswith(("page_", "synthetic_", "final_"))):
        return "ACCEPTED_TO_WITHDRAWN"
    if scenario_class == "GRANULAR_DENIED" and window != "initial_load":
        return "GRANULAR_DENIED"
    return None


def tracking_candidate(observation: dict[str, Any]) -> bool:
    if observation["surface"] != "NETWORK":
        return False
    purpose = str(observation["purpose_candidate"])
    if purpose in EXCLUDED_PURPOSES:
        return False
    if purpose in {"ADVERTISING", "PERSONALIZATION", "ANALYTICS"}:
        return True
    data = observation.get("data", {})
    url = str(data.get("url") or "")
    if observation["suspected_implementation_layer"] in {"FIRST_PARTY_PROXY_OR_GATEWAY", "SERVICE_WORKER"}:
        return True
    if data.get("canary_detected"):
        return True
    return bool(TRACKING_PATH_RE.search(url)) and str(data.get("resource_type")) in {"fetch", "xhr", "beacon", "ping", "image", "script"}


def stable_identifier(observations: Iterable[dict[str, Any]]) -> bool:
    for row in observations:
        names = {str(item).casefold() for item in row.get("data", {}).get("query_parameter_names", [])}
        if names & STABLE_ID_NAMES:
            return True
    return False


def observed_key(row: dict[str, Any]) -> str:
    data = row.get("data", {})
    return vendor_product_key(row["vendor_product"], fallback_url=str(data.get("url") or data.get("destination_url") or ""))


def interaction_identity(row: dict[str, Any], evaluated: str | None = None) -> str:
    window = str(row["action_window"])
    if evaluated == "UNTOUCHED" and window == "initial_load":
        return "pre-choice"
    if "withdraw" in window:
        return "withdraw"
    if "reject" in window:
        return "reject"
    if "accept" in window:
        return "accept"
    if window == "persistence_revisit":
        return "persistence-revisit"
    return window


def rule_status(rule_context: dict[str, Any]) -> tuple[str, str, list[str]]:
    applicability = str(rule_context["applicability"])
    limitations: list[str] = []
    if applicability == "NOT_APPLICABLE":
        return "NOT_APPLICABLE", applicability, limitations
    if not rule_context["sources_ready"]:
        limitations.append("One or more dependent rule sources were not MATCHED at run time")
        return "INCONCLUSIVE", applicability, limitations
    if applicability not in {"CONFIRMED", "CLIENT_ASSERTED"}:
        limitations.append("Rule applicability is not confirmed for this tested visitor context")
        return "INCONCLUSIVE", applicability, limitations
    return "UNEXPECTED_BEHAVIOUR_OBSERVED", applicability, limitations


def owner_for(layer: str, *, declaration: bool = False) -> tuple[str, list[str]]:
    if declaration:
        return "DPO_LEGAL", ["ANALYST_INVESTIGATION"]
    mapping = {
        "GTM_CONTAINER": "GTM_OWNER",
        "HARDCODED_OR_BUNDLED": "DEVELOPER",
        "CMS_THEME_PLUGIN": "CMS_OWNER",
        "EMBED_OR_IFRAME": "VENDOR_OWNER",
        "CMP": "CMP_ADMIN",
        "SERVICE_WORKER": "DEVELOPER",
        "FIRST_PARTY_PROXY_OR_GATEWAY": "SERVER_SIDE_OWNER",
        "POLICY_OR_ORGANIZATIONAL": "DPO_LEGAL",
    }
    primary = mapping.get(layer, "ANALYST_INVESTIGATION")
    contributing = ["DPO_LEGAL"] if primary not in {"DPO_LEGAL", "ANALYST_INVESTIGATION"} else []
    return primary, contributing


def make_finding(
    *, run: dict[str, Any], rows: list[dict[str, Any]], rule_id: str, finding_kind: str,
    title: str, observed_fact: str, expected: str, rule_context: dict[str, Any],
    evaluation_class: str, location_pattern: str, priority_inputs: dict[str, Any],
    technical_status: str, limitations: list[str], layer: str | None = None,
    vendor_key_override: str | None = None, declaration: bool = False,
) -> dict[str, Any]:
    vendor_key = vendor_key_override or observed_key(rows[0])
    fingerprint_inputs = {
        "rule_id": rule_id,
        "finding_kind": finding_kind,
        "vendor_product_key": vendor_key,
        "scenario_class": evaluation_class,
        "location_pattern": location_pattern,
    }
    layer = layer or str(rows[0]["suspected_implementation_layer"])
    primary_owner, contributing = owner_for(layer, declaration=declaration)
    priority = technical_priority(priority_inputs)
    evidence_ids = sorted({str(row["evidence_id"]) for row in rows})
    contexts = {item["scenario_id"]: item.get("context_id") for item in run["scenarios"]}
    context_count = len({contexts.get(str(row["scenario_id"])) for row in rows if contexts.get(str(row["scenario_id"]))})
    if priority_inputs["reproduced"] and context_count < 2 and not declaration:
        raise ContractError("A finding cannot claim reproduced without two isolated context identities")
    initiators = sorted({str(row["observed_initiator"]) for row in rows if row.get("observed_initiator")})
    confidence = rows[0]["vendor_product"]["confidence"]
    if layer == "GTM_CONTAINER" and confidence == "CONFIRMED":
        confidence = "PROBABLE"
    first_seen = min(str(row["observed_at"]) for row in rows)
    last_seen = max(str(row["observed_at"]) for row in rows)
    return {
        "schema_version": "1.0.0",
        "finding_fingerprint": finding_fingerprint(fingerprint_inputs),
        "finding_fingerprint_algo_version": FINGERPRINT_ALGO_VERSION,
        "fingerprint_inputs": fingerprint_inputs,
        "finding_kind": finding_kind,
        "rule_id": rule_id,
        "title": title,
        "observed_fact": observed_fact,
        "expected_technical_behaviour": expected,
        "technical_test_status": technical_status,
        "technical_priority": priority,
        "technical_priority_rubric_version": PRIORITY_RUBRIC_VERSION,
        "technical_priority_inputs": priority_inputs,
        "rule_applicability": rule_context["applicability"],
        "rule_source_ids": sorted(rule_context["rule"]["source_ids"]),
        "rule_authority": rule_context["authority"],
        "fact_class": "BROWSER_OBSERVED",
        "scenario_classes": sorted({str(row["scenario_class"]) for row in rows}),
        "action_windows": sorted({str(row["action_window"]) for row in rows}),
        "locations": sorted({str(row["page_url"]) for row in rows}),
        "test_context": {
            "browser_engine": run["browser"]["engine"],
            "browser_version": run["browser"]["version"],
            "network_route_id": run["network_route"]["route_id"],
            "verified_region": run["network_route"]["externally_verified_region"],
            "market_claim_supported": bool(run["network_route"]["externally_verified_region"]) or not run["scope"]["markets"],
        },
        "evidence_ids": evidence_ids,
        "observed_initiator": initiators[0] if len(initiators) == 1 else None,
        "attribution_confidence": confidence,
        "suspected_implementation_layer": layer,
        "root_cause_status": "SUSPECTED" if layer != "UNKNOWN" else "UNKNOWN",
        "confirmed_root_cause_evidence": [],
        "primary_owner": primary_owner,
        "contributing_owners": contributing,
        "dependencies": ["Confirm the implementation owner before mutation"] if layer != "UNKNOWN" else ["Identify the smallest missing initiator or configuration evidence"],
        "proposed_outcome": "Stop the technically contradictory browser operation in the affected state, or document and approve a narrower applicable technical model before retest.",
        "retest_steps": [
            f"Start a new clean Chromium context on {location_pattern.split('#', 1)[0]}.",
            f"Reproduce the {evaluation_class} state and verify the CMP state independently.",
            "Capture the same network/storage window without GTM Preview and compare the normalized vendor/product operation.",
        ],
        "legal_review_required": bool(rule_context["rule"]["legal_review_required"] or declaration),
        "limitations": sorted(set(limitations)),
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def network_findings(run: dict[str, Any], observations: list[dict[str, Any]], rules: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rule_id = "CNIL.FR.PRIOR.CHOICE"
    if rule_id not in rules:
        return []
    rule_context = rules[rule_id]
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    locations_by_base: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in observations:
        evaluated = evaluation_scenario(row)
        if not evaluated or not tracking_candidate(row):
            continue
        location = normalized_location_pattern(str(row["page_url"]), interaction_identity(row, evaluated))
        key = observed_key(row)
        grouped[(key, evaluated, location)].append(row)
        locations_by_base[(key, evaluated)].add(location)
    findings: list[dict[str, Any]] = []
    context_by_scenario = {str(item["scenario_id"]): item.get("context_id") for item in run["scenarios"]}
    for (key, evaluated, location), rows in sorted(grouped.items()):
        technical_status, applicability, limitations = rule_status(rule_context)
        context_ids = {context_by_scenario.get(str(row["scenario_id"])) for row in rows}
        context_ids.discard(None)
        reproduced = len(context_ids) >= 2
        purpose = str(rows[0]["purpose_candidate"])
        systemic = len(locations_by_base[(key, evaluated)]) >= 2
        priority_inputs = default_priority_inputs()
        priority_inputs.update(
            {
                "unintended_collection": technical_status == "UNEXPECTED_BEHAVIOUR_OBSERVED",
                "reproduced": reproduced,
                "consent_state_contradiction": technical_status == "UNEXPECTED_BEHAVIOUR_OBSERVED",
                "scenario_class": evaluated,
                "purpose_candidate": purpose,
                "stable_identifier": stable_identifier(rows),
                "systemic": systemic,
                "choice_withdrawal_persistence_failure": technical_status == "UNEXPECTED_BEHAVIOUR_OBSERVED" and evaluated == "UNTOUCHED",
                "unresolved_proxy_worker": rows[0]["suspected_implementation_layer"] in {"FIRST_PARTY_PROXY_OR_GATEWAY", "SERVICE_WORKER"},
                "localized_defect": technical_status == "UNEXPECTED_BEHAVIOUR_OBSERVED" and not reproduced,
                "optional_inconclusive": technical_status == "INCONCLUSIVE",
                "not_applicable": technical_status == "NOT_APPLICABLE",
            }
        )
        expected = str(rule_context["rule"]["expected_by_scenario"].get(evaluated, "No applicable non-necessary operation in the denied or pre-choice state"))
        display = rows[0]["vendor_product"]["display_name"]
        status_word = "was observed" if technical_status == "UNEXPECTED_BEHAVIOUR_OBSERVED" else "requires an applicability or source decision"
        findings.append(
            make_finding(
                run=run,
                rows=rows,
                rule_id=rule_id,
                finding_kind="CONSENT_STATE_CONTRADICTION",
                title=f"{display} browser operation in {evaluated}",
                observed_fact=f"{display} {status_word} in {len(rows)} minimized browser request observation(s) at the normalized {evaluated} slice.",
                expected=expected,
                rule_context={**rule_context, "applicability": applicability},
                evaluation_class=evaluated,
                location_pattern=location,
                priority_inputs=priority_inputs,
                technical_status=technical_status,
                limitations=limitations + ([] if reproduced else ["The normalized contradiction was not repeated in two isolated contexts; priority is capped by the rubric"]),
                vendor_key_override=key,
            )
        )
    return findings


def state_findings(run: dict[str, Any], observations: list[dict[str, Any]], rules: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rule_id = "TECH.STATE.VERIFIED"
    if rule_id not in rules:
        return []
    rule_context = rules[rule_id]
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in observations:
        if row["surface"] == "CMP_STATE":
            by_scenario[str(row["scenario_id"])].append(row)
    findings: list[dict[str, Any]] = []
    for scenario in run["scenarios"]:
        scenario_class = str(scenario["scenario_class"])
        material = scenario_class in CORE_SCENARIOS
        failed = scenario["status"] != "COMPLETE" or scenario.get("state_verified") is not True
        if not failed:
            continue
        rows = by_scenario.get(str(scenario["scenario_id"]), [])
        if not rows:
            # A schema-valid synthetic row lets the failure remain evidence-addressable.
            now = run.get("completed_at") or run.get("started_at") or run["created_at"]
            rows = [{
                "scenario_id": scenario["scenario_id"], "scenario_class": scenario_class,
                "action_window": "scenario_close", "observed_at": now, "page_url": scenario["pages"][0],
                "evidence_id": f"EVD-{scenario['scenario_id']}-manifest", "observed_initiator": None,
                "vendor_product": {"vendor_id": None, "product_id": None, "display_name": run["cmp"].get("provider") or "Consent interface", "confidence": run["cmp"]["detection_confidence"]},
                "purpose_candidate": "CMP", "suspected_implementation_layer": "CMP", "data": {},
            }]
        location = normalized_location_pattern(str(scenario["pages"][0]), "consent-state")
        priority_inputs = default_priority_inputs()
        priority_inputs.update({
            "scenario_class": scenario_class,
            "purpose_candidate": "CMP",
            "required_state_inconclusive": material,
            "optional_inconclusive": not material,
        })
        status = "INCONCLUSIVE" if scenario["status"] != "NOT_TESTED" else "NOT_TESTED"
        findings.append(
            make_finding(
                run=run,
                rows=rows,
                rule_id=rule_id,
                finding_kind="STATE_VERIFICATION_GAP",
                title=f"Consent state not verified for {scenario_class}",
                observed_fact=f"Scenario {scenario['scenario_id']} ended as {scenario['status']} with state_verified={scenario.get('state_verified')}.",
                expected=str(rule_context["rule"]["expected_by_scenario"].get(scenario_class, "Resulting state is independently verified")),
                rule_context=rule_context,
                evaluation_class=scenario_class,
                location_pattern=location,
                priority_inputs=priority_inputs,
                technical_status=status,
                limitations=list(scenario.get("limitations", [])),
                layer="CMP",
                vendor_key_override=f"cmp:{run['cmp'].get('adapter_id') or 'unknown'}",
            )
        )
    return findings


def canary_findings(run: dict[str, Any], observations: list[dict[str, Any]], rules: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rule_id = "TECH.CANARY.EXTERNAL.DISCLOSURE"
    if rule_id not in rules:
        return []
    rule_context = rules[rule_id]
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    site_domain = registrable_domain(urlsplit(run["site"]["origin"]).hostname or "")
    for row in observations:
        if row["surface"] != "CANARY":
            continue
        data = row["data"]
        evaluated = evaluation_scenario(row) or str(row["scenario_class"])
        location = normalized_location_pattern(str(row["page_url"]), interaction_identity(row, evaluated))
        grouped[(observed_key(row), evaluated, location, str(data.get("category", "OTHER")))].append(row)
    findings: list[dict[str, Any]] = []
    context_by_scenario = {str(item["scenario_id"]): item.get("context_id") for item in run["scenarios"]}
    for (key, evaluated, location, category), rows in sorted(grouped.items()):
        destination = str(rows[0]["data"].get("destination_url") or "")
        destination_domain = registrable_domain(urlsplit(destination).hostname or "")
        purpose = str(rows[0]["purpose_candidate"])
        technically_unintended = bool(destination_domain and destination_domain != site_domain and purpose in {"ADVERTISING", "PERSONALIZATION", "ANALYTICS"})
        applicability = rule_context["applicability"] if technically_unintended else "UNKNOWN"
        status = "UNEXPECTED_BEHAVIOUR_OBSERVED" if technically_unintended else "INCONCLUSIVE"
        contexts = {context_by_scenario.get(str(row["scenario_id"])) for row in rows}
        contexts.discard(None)
        reproduced = len(contexts) >= 2
        priority_inputs = default_priority_inputs()
        priority_inputs.update({
            "sensitive_category": category,
            "unintended_collection": technically_unintended,
            "reproduced": reproduced,
            "direct_identifier_canary": category == "DIRECT_IDENTIFIER",
            "scenario_class": evaluated,
            "purpose_candidate": purpose,
            "localized_defect": technically_unintended and not reproduced and category not in {"CREDENTIAL", "AUTH_TOKEN", "PAYMENT", "SPECIAL_CATEGORY"},
            "optional_inconclusive": not technically_unintended,
        })
        findings.append(
            make_finding(
                run=run,
                rows=rows,
                rule_id=rule_id,
                finding_kind="SENSITIVE_DATA_DISCLOSURE",
                title=f"Synthetic {category.lower().replace('_', ' ')} reached {rows[0]['vendor_product']['display_name']}",
                observed_fact=f"An exact in-memory synthetic canary match was observed at {rows[0]['data'].get('safe_parameter_path')} for the minimized destination; the value was not retained.",
                expected="Synthetic data reaches only a technically approved destination for the registered interaction.",
                rule_context={**rule_context, "applicability": applicability},
                evaluation_class=evaluated,
                location_pattern=location,
                priority_inputs=priority_inputs,
                technical_status=status,
                limitations=[] if technically_unintended else ["The destination's intended technical role is not established; no unintended-disclosure conclusion is made"],
                vendor_key_override=key,
            )
        )
    return findings


def declaration_findings(run: dict[str, Any], declaration_diff: dict[str, Any] | None, observations: list[dict[str, Any]], rules: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rule_id = "TECH.DECLARATION.CONSISTENCY"
    if not declaration_diff or rule_id not in rules:
        return []
    rule_context = rules[rule_id]
    observed_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in observations:
        if row["surface"] in {"NETWORK", "SCRIPT", "CANARY"}:
            observed_by_key[observed_key(row)].append(row)
    results: list[dict[str, Any]] = []
    context_by_scenario = {str(item["scenario_id"]): item.get("context_id") for item in run["scenarios"]}
    for item in declaration_diff["items"]:
        if item["direction"] != "OBSERVED_UNDECLARED":
            continue
        rows = observed_by_key.get(str(item["vendor_product_key"]), [])
        if not rows:
            continue
        contexts = {context_by_scenario.get(str(row["scenario_id"])) for row in rows}
        contexts.discard(None)
        reproduced = len(contexts) >= 2
        scenario_class = str(rows[0]["scenario_class"])
        location = normalized_location_pattern(str(rows[0]["page_url"]), "declaration-review")
        priority_inputs = default_priority_inputs()
        priority_inputs.update({
            "reproduced": reproduced,
            "scenario_class": scenario_class,
            "purpose_candidate": str(rows[0]["purpose_candidate"]),
            "observed_undeclared": True,
            "localized_defect": not reproduced,
        })
        results.append(
            make_finding(
                run=run,
                rows=rows,
                rule_id=rule_id,
                finding_kind="DECLARATION_MISMATCH",
                title=f"Observed product absent from sampled tracker declaration: {item['display_name']}",
                observed_fact="The product was browser-observed in the sampled run but was not mapped to any supplied public tracker declaration row.",
                expected="Every browser-observed tracker product appears in the sampled public tracker declaration with a reliable identity mapping.",
                rule_context=rule_context,
                evaluation_class=scenario_class,
                location_pattern=location,
                priority_inputs=priority_inputs,
                technical_status="UNEXPECTED_BEHAVIOUR_OBSERVED",
                limitations=["This is a narrow tracker-declaration comparison, not a whole privacy-notice review"],
                layer="POLICY_OR_ORGANIZATIONAL",
                vendor_key_override=str(item["vendor_product_key"]),
                declaration=True,
            )
        )
    return results


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    rank = {"URGENT": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    for finding in findings:
        fingerprint = finding["finding_fingerprint"]
        existing = result.get(fingerprint)
        if not existing:
            result[fingerprint] = finding
            continue
        existing["evidence_ids"] = sorted(set(existing["evidence_ids"] + finding["evidence_ids"]))
        existing["locations"] = sorted(set(existing["locations"] + finding["locations"]))
        existing["action_windows"] = sorted(set(existing["action_windows"] + finding["action_windows"]))
        existing["scenario_classes"] = sorted(set(existing["scenario_classes"] + finding["scenario_classes"]))
        existing["limitations"] = sorted(set(existing["limitations"] + finding["limitations"]))
        existing["first_seen"] = min(existing["first_seen"], finding["first_seen"])
        existing["last_seen"] = max(existing["last_seen"], finding["last_seen"])
        if rank[finding["technical_priority"]] < rank[existing["technical_priority"]]:
            existing["technical_priority"] = finding["technical_priority"]
            existing["technical_priority_inputs"] = finding["technical_priority_inputs"]
    return sorted(result.values(), key=lambda item: (rank[item["technical_priority"]], item["finding_fingerprint"]))


def analyze(run: dict[str, Any], observations: list[dict[str, Any]], declaration_diff: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    rules = profile_rule_index(run)
    findings = network_findings(run, observations, rules)
    findings.extend(state_findings(run, observations, rules))
    findings.extend(canary_findings(run, observations, rules))
    findings.extend(declaration_findings(run, declaration_diff, observations, rules))
    findings = deduplicate(findings)
    for item in findings:
        validate_schema(item, "finding.schema.json", label=item["finding_fingerprint"])
        if item["technical_priority"] != technical_priority(item["technical_priority_inputs"]):
            raise ContractError(f"Priority recomputation failed: {item['finding_fingerprint']}")
        if item["finding_fingerprint"] != finding_fingerprint(item["fingerprint_inputs"]):
            raise ContractError(f"Fingerprint recomputation failed: {item['finding_fingerprint']}")
    return findings


def main() -> int:
    args = parse_args()
    try:
        run = read_json(args.run)
        validate_schema(run, "audit-run.schema.json", label=str(args.run))
        observations = list(iter_jsonl(args.observations))
        for row in observations:
            validate_schema(row, "observation.schema.json", label=row.get("observation_id", "observation"))
            if row["run_id"] != run["run_id"]:
                raise ContractError("Observation run_id does not match manifest")
        declaration_diff = read_json(args.declaration_diff) if args.declaration_diff else None
        if declaration_diff:
            validate_schema(declaration_diff, "declaration-diff.schema.json", label=str(args.declaration_diff))
            if declaration_diff["run_id"] != run["run_id"]:
                raise ContractError("Declaration diff run_id does not match manifest")
        findings = analyze(run, observations, declaration_diff)
        write_json(args.output, findings)
        unexpected = any(item["technical_test_status"] == "UNEXPECTED_BEHAVIOUR_OBSERVED" for item in findings)
        material_gap = any(item["technical_test_status"] in {"INCONCLUSIVE", "NOT_TESTED"} and item["technical_priority"] in {"URGENT", "HIGH", "MEDIUM"} for item in findings)
        run["overall_technical_outcome"] = "CONTRADICTIONS_OBSERVED" if unexpected else "MATERIAL_TESTS_INCONCLUSIVE" if material_gap else "NO_SAMPLED_CONTRADICTION"
        run["outputs"]["findings"] = {"path": args.output.name, "sha256": sha256_file(args.output)}
        validate_schema(run, "audit-run.schema.json", label=str(args.run))
        write_json(args.run, run)
    except (ContractError, OSError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
