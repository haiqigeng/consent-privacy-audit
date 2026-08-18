from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT, clone, complete_run, observation, write_canonical

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from analyze_consent_findings import analyze, evaluation_scenario  # noqa: E402
from build_consent_delivery import build_handoffs, main as build_main  # noqa: E402
from build_declaration_diff import build as build_declaration  # noqa: E402
from validate_consent_delivery import validate_delivery, validate_package  # noqa: E402
from scan_consent_runtime import network_observations  # noqa: E402


def empty_declarations() -> dict:
    return {"schema_version": "1.0.0", "sources": [{"url": "https://example.test/cookies", "retrieved_at": "2026-08-18T12:00:00+00:00", "items": []}]}


class AnalyzerRoutingTests(unittest.TestCase):
    def test_later_withdrawal_window_is_classified_and_repeated_requests_keep_unique_evidence(self) -> None:
        run = complete_run()
        scenario = next(item for item in run["scenarios"] if item["scenario_class"] == "ACCEPTED_TO_WITHDRAWN")
        records = []
        for _ in range(3):
            records.append({
                "observed_at": "2026-08-18T12:00:00+00:00", "method": "GET",
                "safe_url": "https://example.test/collect", "raw_url_for_memory_only": "https://example.test/collect",
                "query_parameter_names": [], "resource_type": "fetch", "frame_url": "https://example.test/",
                "service_worker": False, "status": 204, "failure": None, "canary_hits": [],
            })
        rows = network_observations(run, scenario, records, "post_withdraw_later")
        self.assertEqual(3, len({row["observation_id"] for row in rows}))
        self.assertTrue(all(evaluation_scenario(row) == "ACCEPTED_TO_WITHDRAWN" for row in rows))

    def test_granular_denial_does_not_activate_advertising_silently(self) -> None:
        run = complete_run()
        template = clone(run["scenarios"][0])
        template.update({"scenario_id": "SCN-GRANULAR", "scenario_class": "GRANULAR_DENIED", "context_id": "CTX-GRANULAR"})
        run["scenarios"].append(template)
        row = observation(run, index=1, scenario_id="SCN-GRANULAR", scenario_class="GRANULAR_DENIED", action_window="choice_1_save", vendor_id="meta", product_id="meta-pixel", display_name="Meta Pixel", purpose="ADVERTISING")
        findings = analyze(run, [row])
        target = next(item for item in findings if item["fingerprint_inputs"]["scenario_class"] == "GRANULAR_DENIED")
        self.assertEqual("UNEXPECTED_BEHAVIOUR_OBSERVED", target["technical_test_status"])

    def test_hardcoded_meta_before_choice_routes_to_development(self) -> None:
        run = complete_run()
        rows = [
            observation(run, index=1, scenario_id="SCN-UNTOUCHED", scenario_class="UNTOUCHED", action_window="initial_load", vendor_id="meta", product_id="meta-pixel", display_name="Meta Pixel", purpose="ADVERTISING", layer="HARDCODED_OR_BUNDLED", url="https://www.facebook.com/tr?ev=PageView"),
            observation(run, index=2, scenario_id="SCN-ACCEPTED", scenario_class="ACCEPTED", action_window="initial_load", vendor_id="meta", product_id="meta-pixel", display_name="Meta Pixel", purpose="ADVERTISING", layer="HARDCODED_OR_BUNDLED", url="https://www.facebook.com/tr?ev=PageView"),
        ]
        findings = analyze(run, rows)
        target = next(item for item in findings if item["fingerprint_inputs"]["vendor_product_key"] == "meta:meta-pixel")
        self.assertEqual("DEVELOPER", target["primary_owner"])
        self.assertEqual("MEDIUM", target["technical_priority"])
        self.assertEqual("SUSPECTED", target["root_cause_status"])

    def test_gtm_association_creates_supporting_only_handoff(self) -> None:
        run = complete_run()
        rows = [observation(run, index=1, scenario_id="SCN-REJECTED", scenario_class="REJECTED", action_window="choice_1_reject", layer="GTM_CONTAINER")]
        findings = analyze(run, rows)
        with tempfile.TemporaryDirectory() as temp:
            _, recette, _ = build_handoffs(run, findings, Path(temp))
        self.assertEqual(1, len(recette["handoffs"]))
        self.assertEqual("SUPPORTING_ONLY", recette["handoffs"][0]["role"])
        self.assertFalse(recette["handoffs"][0]["verdict_authority"])
        self.assertEqual("SUSPECTED", findings[0]["root_cause_status"])

    def test_withdrawal_continuation_is_not_missed(self) -> None:
        run = complete_run()
        rows = [observation(run, index=1, scenario_id="SCN-WITHDRAWAL", scenario_class="ACCEPTED_TO_WITHDRAWN", action_window="choice_3_withdraw")]
        findings = analyze(run, rows)
        self.assertTrue(any(item["fingerprint_inputs"]["scenario_class"] == "ACCEPTED_TO_WITHDRAWN" for item in findings))

    def test_first_party_proxy_and_service_worker_are_not_harmless(self) -> None:
        run = complete_run()
        proxy = observation(run, index=1, scenario_id="SCN-REJECTED", scenario_class="REJECTED", action_window="choice_1_reject", vendor_id=None, product_id=None, display_name="example.test", confidence="UNKNOWN", purpose="UNKNOWN", layer="FIRST_PARTY_PROXY_OR_GATEWAY", url="https://example.test/collect")
        worker = observation(run, index=2, scenario_id="SCN-WITHDRAWAL", scenario_class="ACCEPTED_TO_WITHDRAWN", action_window="choice_3_withdraw", vendor_id=None, product_id=None, display_name="worker endpoint", confidence="UNKNOWN", purpose="UNKNOWN", layer="SERVICE_WORKER", url="https://example.test/track")
        findings = analyze(run, [proxy, worker])
        layers = {item["suspected_implementation_layer"] for item in findings}
        self.assertIn("FIRST_PARTY_PROXY_OR_GATEWAY", layers)
        self.assertIn("SERVICE_WORKER", layers)
        self.assertTrue(all(item["technical_priority_inputs"]["unresolved_proxy_worker"] for item in findings))

    def test_canary_is_detected_without_value_retention(self) -> None:
        run = complete_run()
        data = {"canary_id": "email-field", "safe_parameter_path": "query.em", "destination_url": "https://www.google-analytics.com/g/collect?em=%3Credacted%3E", "category": "DIRECT_IDENTIFIER", "detection_basis": "exact in-memory synthetic canary match", "redacted_marker": "<synthetic-canary-detected>", "value_fingerprint": "NOT_RETAINED"}
        rows = [
            observation(run, index=1, scenario_id="SCN-REJECTED", scenario_class="REJECTED", action_window="choice_1_reject", surface="CANARY", data=data),
            observation(run, index=2, scenario_id="SCN-PERSIST-REJECTED", scenario_class="PERSISTENCE_REJECTED", action_window="choice_1_reject", surface="CANARY", data=data),
        ]
        findings = analyze(run, rows)
        target = next(item for item in findings if item["finding_kind"] == "SENSITIVE_DATA_DISCLOSURE")
        serialized = json.dumps(target)
        self.assertNotIn("synthetic-test-value", serialized)
        self.assertIn("NOT_RETAINED", json.dumps(rows))
        self.assertEqual("HIGH", target["technical_priority"])

    def test_state_gap_is_material_and_source_failure_is_localized(self) -> None:
        run = complete_run()
        scenario = next(item for item in run["scenarios"] if item["scenario_class"] == "REJECTED")
        scenario["status"] = "INCONCLUSIVE"
        scenario["state_verified"] = False
        scenario["limitations"] = ["CMP state reader unavailable"]
        findings = analyze(run, [])
        target = next(item for item in findings if item["finding_kind"] == "STATE_VERIFICATION_GAP")
        self.assertEqual("MEDIUM", target["technical_priority"])
        cnil_source = next(item for item in run["source_checks"] if item["source_id"].startswith("CNIL-"))
        cnil_source.update({"status": "CHANGED", "task_required": True})
        rows = [observation(run, index=1, scenario_id="SCN-REJECTED", scenario_class="REJECTED", action_window="choice_1_reject")]
        affected = analyze(run, rows)
        browser_rule = next(item for item in affected if item["rule_id"] == "CNIL.FR.PRIOR.CHOICE")
        self.assertEqual("INCONCLUSIVE", browser_rule["technical_test_status"])
        self.assertEqual("BROWSER_OBSERVED", browser_rule["fact_class"])


class DeclarationTests(unittest.TestCase):
    def test_unknown_third_party_script_remains_an_investigation_item(self) -> None:
        run = complete_run()
        row = observation(
            run, index=1, scenario_id="SCN-UNTOUCHED", scenario_class="UNTOUCHED", action_window="initial_load",
            vendor_id=None, product_id=None, display_name="cdn.vendor.invalid", confidence="UNKNOWN", purpose="UNKNOWN",
            url="https://cdn.vendor.invalid/library.js",
        )
        row["data"]["resource_type"] = "script"
        diff = build_declaration(run, [row], empty_declarations())
        self.assertEqual(1, len(diff["items"]))
        self.assertEqual("AMBIGUOUS", diff["items"][0]["direction"])
        self.assertEqual("INCONCLUSIVE", diff["items"][0]["status"])

    def test_declared_unobserved_is_not_verified(self) -> None:
        run = complete_run()
        declarations = empty_declarations()
        declarations["sources"][0]["items"].append({"declaration_id": "D1", "display_name": "Hotjar", "vendor_id": "hotjar", "product_id": "hotjar", "aliases": [], "purpose_text": "Audience analysis", "purpose_category": "ANALYTICS", "category_text": "Analytics", "duration_text": "12 months"})
        result = build_declaration(run, [], declarations)
        self.assertEqual("DECLARED_UNOBSERVED", result["items"][0]["direction"])
        self.assertEqual("NOT_VERIFIED", result["items"][0]["status"])

    def test_observed_undeclared_appears_in_diff_and_findings(self) -> None:
        run = complete_run()
        rows = [
            observation(run, index=1, scenario_id="SCN-UNTOUCHED", scenario_class="UNTOUCHED", action_window="initial_load"),
            observation(run, index=2, scenario_id="SCN-ACCEPTED", scenario_class="ACCEPTED", action_window="initial_load"),
        ]
        diff = build_declaration(run, rows, empty_declarations())
        item = next(item for item in diff["items"] if item["direction"] == "OBSERVED_UNDECLARED")
        findings = analyze(run, rows, diff)
        declaration_finding = next(item for item in findings if item["finding_kind"] == "DECLARATION_MISMATCH")
        self.assertEqual(item["vendor_product_key"], declaration_finding["fingerprint_inputs"]["vendor_product_key"])
        self.assertEqual("DPO_LEGAL", declaration_finding["primary_owner"])


class DeliveryTests(unittest.TestCase):
    def test_full_canonical_delivery_builds_and_validates(self) -> None:
        run = complete_run()
        rows = [
            observation(run, index=1, scenario_id="SCN-UNTOUCHED", scenario_class="UNTOUCHED", action_window="initial_load", vendor_id="meta", product_id="meta-pixel", display_name="Meta Pixel", purpose="ADVERTISING", url="https://www.facebook.com/tr?ev=PageView"),
            observation(run, index=2, scenario_id="SCN-ACCEPTED", scenario_class="ACCEPTED", action_window="initial_load", vendor_id="meta", product_id="meta-pixel", display_name="Meta Pixel", purpose="ADVERTISING", url="https://www.facebook.com/tr?ev=PageView"),
        ]
        diff = build_declaration(run, rows, empty_declarations())
        findings = analyze(run, rows, diff)
        run["overall_technical_outcome"] = "CONTRADICTIONS_OBSERVED"
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            write_canonical(directory, run, rows, findings, diff)
            argv = sys.argv
            try:
                sys.argv = ["build_consent_delivery.py", str(directory)]
                self.assertEqual(0, build_main())
            finally:
                sys.argv = argv
            checks = validate_delivery(directory, [])
            self.assertIn("privacy", checks)
            self.assertTrue((directory / "consent-privacy-audit.xlsx").is_file())
            self.assertFalse((directory / "recette-handoff.json").exists())

    def test_package_profiles_adapters_and_schemas_validate(self) -> None:
        checks = validate_package()
        self.assertIn("profile:cnil-fr", checks)
        self.assertIn("adapter:axeptio-web", checks)


if __name__ == "__main__":
    unittest.main()
