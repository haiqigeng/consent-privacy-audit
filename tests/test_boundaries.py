from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT, complete_run, observation

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from analyze_consent_findings import analyze  # noqa: E402
from consent_runtime_core import PrivacyError, finding_fingerprint, load_adapters, load_profile, read_json, write_json  # noqa: E402
from scan_consent_runtime import abort_run  # noqa: E402
from validate_consent_delivery import scan_delivery_files  # noqa: E402


class BoundaryTests(unittest.TestCase):
    def test_cookie_wall_remains_contextual_legal_review(self) -> None:
        profile = load_profile("cnil-fr")
        rule = next(item for item in profile["rules"] if item["rule_id"] == "CNIL.FR.CHOICE.EASE")
        self.assertTrue(rule["legal_review_required"])
        self.assertTrue(any("cookie-wall" in item.casefold() for item in rule["exceptions"]))

    def test_exemption_keeps_organizational_evidence_unobservable(self) -> None:
        profile = load_profile("cnil-fr")
        rule = next(item for item in profile["rules"] if item["rule_id"] == "CNIL.FR.AUDIENCE.EXEMPTION")
        joined = " ".join(rule["unobservable_dependencies"]).casefold()
        self.assertIn("vendor reuse", joined)
        self.assertIn("contract", joined)
        self.assertTrue(rule["legal_review_required"])

    def test_api_fallback_cannot_certify_cmp_ux(self) -> None:
        didomi = next(item for item in load_adapters() if item["adapter_id"] == "didomi-web")
        self.assertTrue(didomi["api_fallback"]["allowed"])
        self.assertEqual("INCONCLUSIVE", didomi["api_fallback"]["ux_status_when_used"])

    def test_saved_undeployed_gtm_is_not_runtime_evidence(self) -> None:
        text = (ROOT / "SKILL.md").read_text(encoding="utf-8") + (ROOT / "references" / "product-and-boundaries.md").read_text(encoding="utf-8")
        self.assertIn("saved GTM", text)
        self.assertIn("not runtime", text.casefold())

    def test_market_claim_requires_verified_network_route(self) -> None:
        run = complete_run()
        run["scope"]["markets"] = ["FR"]
        run["network_route"]["browser_geolocation_emulated"] = True
        run["network_route"]["externally_verified_region"] = None
        rows = [observation(run, index=1, scenario_id="SCN-REJECTED", scenario_class="REJECTED", action_window="choice_1_reject")]
        finding = analyze(run, rows)[0]
        self.assertFalse(finding["test_context"]["market_claim_supported"])

    def test_ab_banner_variants_have_distinct_normative_location_identity(self) -> None:
        base = {"rule_id": "RULE", "finding_kind": "OTHER", "vendor_product_key": "v:p", "scenario_class": "UNTOUCHED", "location_pattern": "https://example.test/#banner-variant-a"}
        variant = dict(base, location_pattern="https://example.test/#banner-variant-b")
        self.assertNotEqual(finding_fingerprint(base), finding_fingerprint(variant))

    def test_browser_readiness_failure_writes_aborted_manifest(self) -> None:
        run = complete_run()
        run["status"] = "PLANNED"
        run["started_at"] = None
        run["completed_at"] = None
        run["overall_technical_outcome"] = None
        for scenario in run["scenarios"]:
            scenario["status"] = "REGISTERED"
            scenario["state_verified"] = None
            scenario["capture_status"] = {key: "REGISTERED" for key in scenario["capture_status"]}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit-run.json"
            write_json(path, run)
            abort_run(path, run, "Chromium readiness failed; route to web-analyst-mcp-setup")
            aborted = read_json(path)
        self.assertEqual("ABORTED", aborted["status"])
        self.assertIsNone(aborted["overall_technical_outcome"])
        self.assertTrue(all(item["status"] == "ABORTED" for item in aborted["scenarios"]))
        self.assertTrue(all(all(value == "ABORTED" for value in item["capture_status"].values()) for item in aborted["scenarios"]))

    def test_codex_metadata_is_minimal_and_functional_instructions_stay_in_skill(self) -> None:
        metadata = (ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn("allow_implicit_invocation: true", metadata)
        self.assertNotIn("CNIL.FR.PRIOR.CHOICE", metadata)
        self.assertIn("Non-negotiable boundaries", (ROOT / "SKILL.md").read_text(encoding="utf-8"))

    def test_authenticated_and_gpc_are_explicit_post_v1_boundaries(self) -> None:
        text = (ROOT / "SKILL.md").read_text(encoding="utf-8").casefold()
        self.assertIn("authenticated", text)
        self.assertIn("gpc", text)
        self.assertIn("do not test", text)

    def test_handoffs_have_no_mutation_or_verdict_authority(self) -> None:
        recette_schema = read_json(ROOT / "schemas" / "recette-handoff.schema.json")
        remediation_schema = read_json(ROOT / "schemas" / "remediation-handoff.schema.json")
        self.assertEqual(False, recette_schema["$defs"]["handoff"]["properties"]["verdict_authority"]["const"])
        self.assertEqual("SUPPORTING_ONLY", recette_schema["$defs"]["handoff"]["properties"]["role"]["const"])
        self.assertEqual("MANUAL_ONLY", remediation_schema["$defs"]["handoff"]["properties"]["role"]["const"])

    def test_raw_har_is_rejected_from_normal_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "capture.har").write_text("{}", encoding="utf-8")
            with self.assertRaises(PrivacyError):
                scan_delivery_files(directory, [], {"artifacts": []})

    def test_no_server_processing_or_receipt_claim_is_possible_from_schema(self) -> None:
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8").casefold()
        self.assertIn("unseen server", skill)
        self.assertIn("cmp back-office", (ROOT / "references" / "product-and-boundaries.md").read_text(encoding="utf-8").casefold())


if __name__ == "__main__":
    unittest.main()
