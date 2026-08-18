from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers import ROOT, complete_run

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from consent_runtime_core import (  # noqa: E402
    ContractError,
    PrivacyError,
    default_priority_inputs,
    detect_cmp,
    finding_fingerprint,
    normalized_location_pattern,
    normalize_path_template,
    privacy_findings,
    sanitize_url,
    technical_priority,
)
from consent_runtime_core import read_json, write_json  # noqa: E402
from review_screenshot_evidence import main as screenshot_main, review_text  # noqa: E402
from scan_consent_runtime import detect_canary_path, execute_interaction_plan, extract_cdp_initiator, find_control, state_matches_action, websocket_observations  # noqa: E402
from verify_rule_sources import verify  # noqa: E402


class FakeLocator:
    def __init__(self) -> None:
        self.clicks = 0
        self.filled: list[str] = []

    def count(self) -> int:
        return 1

    def is_visible(self) -> bool:
        return True

    def click(self) -> None:
        self.clicks += 1

    def fill(self, value: str) -> None:
        self.filled.append(value)

    def press(self, value: str) -> None:
        return


class FakePage:
    def __init__(self, url: str) -> None:
        self.url = url
        self.locator_value = FakeLocator()

    def get_by_role(self, role: str, name: str, exact: bool = True) -> FakeLocator:
        return self.locator_value

    def get_by_label(self, name: str, exact: bool = True) -> FakeLocator:
        return self.locator_value

    def locator(self, value: str) -> FakeLocator:
        return self.locator_value


class SemanticButton:
    def __init__(self, label: str) -> None:
        self.label = label

    def is_visible(self) -> bool:
        return True

    def get_attribute(self, name: str) -> None:
        return None

    def inner_text(self, timeout: int = 500) -> str:
        return self.label


class SemanticCollection:
    def __init__(self, labels: list[str]) -> None:
        self.buttons = [SemanticButton(label) for label in labels]

    def count(self) -> int:
        return len(self.buttons)

    def nth(self, index: int) -> SemanticButton:
        return self.buttons[index]


class SemanticPage:
    def __init__(self, labels: list[str]) -> None:
        self.labels = labels

    def get_by_role(self, role: str) -> SemanticCollection:
        return SemanticCollection(self.labels if role == "button" else [])

    def locator(self, selector: str) -> SemanticCollection:
        return SemanticCollection([])


class PriorityTests(unittest.TestCase):
    def inputs(self, **changes: object) -> dict:
        value = default_priority_inputs()
        value.update(changes)
        return value

    def test_all_five_priority_rows(self) -> None:
        self.assertEqual("URGENT", technical_priority(self.inputs(sensitive_category="CREDENTIAL", unintended_collection=True)))
        self.assertEqual("HIGH", technical_priority(self.inputs(reproduced=True, direct_identifier_canary=True, unintended_collection=True)))
        self.assertEqual("MEDIUM", technical_priority(self.inputs(required_state_inconclusive=True)))
        self.assertEqual("LOW", technical_priority(self.inputs(localized_defect=True)))
        self.assertEqual("INFORMATIONAL", technical_priority(self.inputs(expected=True)))

    def test_priority_is_ordered_first_match(self) -> None:
        value = self.inputs(sensitive_category="PAYMENT", unintended_collection=True, required_state_inconclusive=True, localized_defect=True, expected=True)
        self.assertEqual("URGENT", technical_priority(value))

    def test_missing_priority_input_rejected(self) -> None:
        value = self.inputs()
        value.pop("reproduced")
        with self.assertRaises(ContractError):
            technical_priority(value)

    def test_reproduced_denied_advertising_is_high(self) -> None:
        value = self.inputs(reproduced=True, unintended_collection=True, consent_state_contradiction=True, scenario_class="REJECTED", purpose_candidate="ADVERTISING")
        self.assertEqual("HIGH", technical_priority(value))

    def test_single_unrepeatable_contradiction_is_capped(self) -> None:
        value = self.inputs(unintended_collection=True, consent_state_contradiction=True, scenario_class="REJECTED", purpose_candidate="ADVERTISING", localized_defect=True)
        self.assertEqual("LOW", technical_priority(value))


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_determinism_and_normative_change(self) -> None:
        base = {"rule_id": "RULE.A", "finding_kind": "OTHER", "vendor_product_key": "v:p", "scenario_class": "REJECTED", "location_pattern": "https://example.test/{locale}/x#reject"}
        self.assertEqual(finding_fingerprint(base), finding_fingerprint(dict(reversed(list(base.items())))))
        changed = dict(base, scenario_class="ACCEPTED_TO_WITHDRAWN")
        self.assertNotEqual(finding_fingerprint(base), finding_fingerprint(changed))

    def test_fingerprint_rejects_extra_or_missing_inputs(self) -> None:
        with self.assertRaises(ContractError):
            finding_fingerprint({"rule_id": "x"})

    def test_location_and_path_normalization_remove_volatile_segments(self) -> None:
        self.assertEqual("/{locale}/orders/{id}/{uuid}", normalize_path_template("/fr-FR/orders/123456/123e4567-e89b-12d3-a456-426614174000"))
        self.assertEqual("https://example.test/{locale}/orders/{id}#submit", normalized_location_pattern("https://example.test/fr-FR/orders/123456?token=secret", "Submit"))


class CmpTests(unittest.TestCase):
    def test_customized_localized_control_is_found_semantically(self) -> None:
        adapter = next(item for item in __import__("consent_runtime_core").load_adapters() if item["adapter_id"] == "axeptio-web")
        control, method = find_control(SemanticPage(["Accepter tout"]), adapter, "accept")
        self.assertIsNotNone(control)
        self.assertTrue(method.startswith("semantic"))

    def test_known_cmp_requires_weighted_multisignal_evidence(self) -> None:
        snapshot = {"globals": ["Didomi"], "script_hosts": ["sdk.privacy-center.org"], "script_paths": [], "cookie_names": [], "storage_keys": [], "dom_markers": [], "events": []}
        result = detect_cmp(snapshot)
        self.assertEqual("didomi-web", result.adapter_id)
        self.assertEqual("CONFIRMED", result.confidence)

    def test_provider_identity_wins_over_generic_tcf_capability(self) -> None:
        snapshot = {"globals": ["Didomi", "__tcfapi"], "script_hosts": ["sdk.privacy-center.org"], "script_paths": [], "cookie_names": ["euconsent-v2"], "storage_keys": [], "dom_markers": ["iframe[name=__tcfapiLocator]"], "events": []}
        result = detect_cmp(snapshot)
        self.assertEqual("didomi-web", result.adapter_id)
        self.assertEqual("CONFIRMED", result.confidence)

    def test_unknown_custom_cmp_degrades_without_provider_claim(self) -> None:
        empty = {key: [] for key in ["globals", "script_hosts", "script_paths", "cookie_names", "storage_keys", "dom_markers", "events"]}
        result = detect_cmp(empty)
        self.assertEqual("generic-custom-banner", result.adapter_id)
        self.assertEqual("UNKNOWN", result.confidence)

    def test_generic_tcf_does_not_activate_without_tcf_signals(self) -> None:
        snapshot = {"globals": ["SomeCMP"], "script_hosts": ["cmp.example.test"], "script_paths": ["/cmp.js"], "cookie_names": ["consent"], "storage_keys": [], "dom_markers": ["[role=dialog]"], "events": []}
        self.assertNotEqual("generic-tcf-web", detect_cmp(snapshot).adapter_id)

    def test_state_semantics_cover_withdrawal_and_persistence(self) -> None:
        self.assertTrue(state_matches_action({"ready": True, "state": "WITHDRAWN"}, "withdraw"))
        self.assertTrue(state_matches_action({"ready": True, "state": "REJECTED"}, "reject"))
        self.assertFalse(state_matches_action({"ready": True, "state": "ACCEPTED"}, "reject"))

    def test_onetrust_differential_state_uses_baseline_and_banner_visibility(self) -> None:
        baseline = {"ready": True, "active_groups": ["1"], "banner_visible": True}
        rejected = {"ready": True, "active_groups": ["1"], "banner_visible": False}
        accepted = {"ready": True, "active_groups": ["1", "2", "3", "4"], "banner_visible": False}
        self.assertTrue(state_matches_action(rejected, "reject", baseline_state=baseline))
        self.assertTrue(state_matches_action(rejected, "withdraw", baseline_state=baseline))
        self.assertTrue(state_matches_action(accepted, "accept", baseline_state=baseline))
        self.assertFalse(state_matches_action(baseline, "reject", baseline_state=baseline))

    def test_numeric_asset_version_is_redacted_as_non_personal_query_value(self) -> None:
        safe, names = sanitize_url("https://example.test/app.js?v=20250430123045")
        self.assertEqual("https://example.test/app.js?v=%3Credacted%3E", safe)
        self.assertEqual(["v"], names)
        safe_path, _ = sanitize_url("https://example.test/getattachment/123e4567-e89b-12d3-a456-426614174000/istock-12345678901234.jpg")
        self.assertNotIn("12345678901234", safe_path)

    def test_cdp_initiator_prefers_gtm_in_the_actual_stack(self) -> None:
        value = extract_cdp_initiator(
            {"type": "script", "stack": {"callFrames": [{"url": "https://vendor.test/pixel.js"}, {"url": "https://www.googletagmanager.com/gtm.js?id=GTM-TEST"}]}},
            "https://example.test/",
        )
        self.assertEqual("script", value["type"])
        self.assertIn("googletagmanager.com/gtm.js", value["url"] or "")
        self.assertNotIn("GTM-TEST", value["url"] or "")


class SafetyTests(unittest.TestCase):
    def test_canary_detection_covers_query_path_header_and_body_without_returning_value(self) -> None:
        specs = {"C1": {"value": "synthetic-test-canary", "category": "AUTH_TOKEN"}}
        hits = detect_canary_path(
            "https://vendor.test/p/synthetic-test-canary?q=synthetic-test-canary",
            '{"nested":{"value":"synthetic-test-canary"}}',
            {"x-fixture": "synthetic-test-canary"},
            specs,
        )
        paths = {item["safe_parameter_path"] for item in hits}
        self.assertEqual({"path.<segment>", "query.q", "header.x-fixture", "body.nested.value"}, paths)
        self.assertNotIn("synthetic-test-canary", json.dumps(hits))

    def test_websocket_capture_emits_sanitized_request_and_nonretention_canary_marker(self) -> None:
        run = complete_run()
        scenario = run["scenarios"][0]
        rows = websocket_observations(
            run,
            scenario,
            {"wss://vendor.test/socket?identity=synthetic-test-canary"},
            "https://example.test/",
            {"C1": {"value": "synthetic-test-canary", "category": "DIRECT_IDENTIFIER"}},
        )
        self.assertEqual(["NETWORK", "CANARY"], [row["surface"] for row in rows])
        self.assertEqual("wss://vendor.test/socket?identity=%3Credacted%3E", rows[0]["data"]["url"])
        self.assertTrue(rows[0]["data"]["canary_detected"])
        self.assertEqual("NOT_RETAINED", rows[1]["data"]["value_fingerprint"])
        self.assertNotIn("synthetic-test-canary", json.dumps(rows))

    def submission_plan(self, environment: str, authorizations: list[dict] | None = None) -> dict:
        return {
            "schema_version": "1.0.0",
            "environment": environment,
            "actions": [{"action_id": "submit", "scenario_classes": ["REJECTED"], "url": "https://example.test/", "kind": "SUBMIT", "locator": {"by": "ROLE_NAME", "value": "Submit"}, "canary_id": None, "effect": "FORM_SUBMISSION", "authorization_id": "AUTH-1"}],
            "submission_authorizations": authorizations or [],
        }

    def test_production_submission_stops_without_exact_authorization(self) -> None:
        page = FakePage("https://example.test/")
        notes = execute_interaction_plan(page=page, scenario_class="REJECTED", plan=self.submission_plan("production"), canaries={}, run=complete_run())
        self.assertEqual(0, page.locator_value.clicks)
        self.assertIn("NOT_TESTED", notes[0])

    def test_test_environment_submission_is_allowed_without_retained_canary(self) -> None:
        page = FakePage("https://example.test/")
        notes = execute_interaction_plan(page=page, scenario_class="REJECTED", plan=self.submission_plan("test"), canaries={}, run=complete_run())
        self.assertEqual(1, page.locator_value.clicks)
        self.assertNotIn("example", json.dumps(notes).lower())

    def test_personal_data_and_canary_scans_fail_closed(self) -> None:
        self.assertIn("EMAIL", privacy_findings("contact jane@example.com"))
        self.assertIn("PHONE", privacy_findings("call 01 23 45 67 89"))
        self.assertNotIn("PHONE", privacy_findings("Chromium 151.0.7922.34"))
        self.assertNotIn("PHONE", privacy_findings('{"expires": 1767225600000}'))
        self.assertNotIn("PHONE", privacy_findings('{"expires": 1767225600}'))
        self.assertIn("PHONE", privacy_findings('{"phone": 1767225600}'))
        with self.assertRaises(PrivacyError):
            review_text("visible synthetic-test-canary", ["synthetic-test-canary"])
        review_text("Cookie settings", ["synthetic-test-canary"])

    def test_screenshot_gate_rejects_visible_canary_and_delivers_only_reviewed_safe_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "staged.png"
            image.write_bytes(b"controlled-fixture")
            canaries = root / "restricted.json"
            write_json(canaries, {"field": {"value": "synthetic-test-canary", "category": "DIRECT_IDENTIFIER"}})
            index_path = root / "evidence-index.json"
            write_json(index_path, {"schema_version": "1.0.0", "run_id": "RUN", "generated_at": "2026-08-18T12:00:00+00:00", "artifacts": []})
            output = root / "evidence"
            original = sys.argv
            try:
                sys.argv = ["review_screenshot_evidence.py", str(image), str(index_path), "--evidence-id", "EVD-safe-screen", "--output-dir", str(output), "--canary-file", str(canaries), "--cropped-or-masked", "--analyst-approved"]
                with patch("review_screenshot_evidence.extract_text", return_value="synthetic-test-canary"):
                    self.assertEqual(2, screenshot_main())
                self.assertFalse((output / "EVD-safe-screen.png").exists())
                with patch("review_screenshot_evidence.extract_text", return_value="Cookie settings"):
                    self.assertEqual(0, screenshot_main())
            finally:
                sys.argv = original
            index = read_json(index_path)
            self.assertEqual("PASSED", index["artifacts"][0]["screenshot_review"]["ocr_status"])
            self.assertEqual("PASSED", index["artifacts"][0]["screenshot_review"]["analyst_status"])


class SourceVerificationTests(unittest.TestCase):
    def profile(self, expected_hash: str, last_verified: str = "2026-08-18T00:00:00+00:00") -> dict:
        return {
            "schema_version": "1.0.0", "profile_id": "fixture", "profile_version": "1.0.0", "title": "fixture", "jurisdiction": None, "status": "ACTIVE",
            "sources": [{
                "source_id": "SRC", "source_type": "TECHNICAL_STANDARD", "authority": "Fixture", "title": "Fixture", "url": "https://example.test/rule",
                "section_locator": {"kind": "TEXT_BETWEEN", "start_marker": "START", "end_marker": "END"}, "verification_method": "CONTENT_FINGERPRINT",
                "content_fingerprint": expected_hash, "content_fingerprint_algo_version": "normalized-text-sha256-v1", "normalization_version": "visible-text-nfc-whitespace-v1",
                "volatile": True, "staleness_threshold_days": 90, "retrieved_at": "2026-08-18T00:00:00+00:00", "last_human_verified_at": last_verified,
                "effective_date": None, "transition_deadline": None,
            }],
            "rules": [{"rule_id": "FIXTURE.RULE", "source_ids": ["SRC"], "title": "Fixture", "applicability_facts": [], "observable_test": "Observe", "expected_by_scenario": {"UNTOUCHED": "Expected"}, "exceptions": [], "unobservable_dependencies": [], "legal_review_required": False, "superseded": False}],
        }

    def test_matching_changed_unreachable_and_stale_sources_are_localized(self) -> None:
        expected = hashlib.sha256("START stable".encode()).hexdigest()
        profile = self.profile(expected)
        with patch("verify_rule_sources.fetch_source", return_value=("https://example.test/rule", "<p>START stable END</p>")):
            matched = verify(profile)
        self.assertEqual("MATCHED", matched["checks"][0]["status"])
        with patch("verify_rule_sources.fetch_source", return_value=("https://example.test/rule", "<p>START changed END</p>")):
            changed = verify(profile)
        self.assertEqual("CHANGED", changed["checks"][0]["status"])
        with patch("verify_rule_sources.fetch_source", side_effect=OSError("offline")):
            unreachable = verify(profile)
        self.assertEqual("UNREACHABLE", unreachable["checks"][0]["status"])
        stale_profile = self.profile(expected, "2020-01-01T00:00:00+00:00")
        with patch("verify_rule_sources.fetch_source", return_value=("https://example.test/rule", "<p>START stable END</p>")):
            stale = verify(stale_profile)
        self.assertEqual("STALE", stale["checks"][0]["status"])
        for result in (changed, unreachable, stale):
            self.assertEqual(["FIXTURE.RULE"], result["checks"][0]["dependent_rule_ids"])
            self.assertTrue(result["checks"][0]["task_required"])


if __name__ == "__main__":
    unittest.main()
