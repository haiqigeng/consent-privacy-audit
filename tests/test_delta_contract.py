from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT, clone, complete_run, observation

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from analyze_consent_findings import analyze  # noqa: E402
from compare_consent_runs import compare  # noqa: E402
from consent_runtime_core import finding_fingerprint, validate_schema, write_json  # noqa: E402


def base_finding(run: dict) -> dict:
    rows = [
        observation(run, index=1, scenario_id="SCN-UNTOUCHED", scenario_class="UNTOUCHED", action_window="initial_load"),
        observation(run, index=2, scenario_id="SCN-ACCEPTED", scenario_class="ACCEPTED", action_window="initial_load"),
    ]
    return next(item for item in analyze(run, rows) if item["finding_kind"] == "CONSENT_STATE_CONTRADICTION")


def variant(base: dict, vendor_key: str, path: str = "/a") -> dict:
    item = clone(base)
    item["fingerprint_inputs"]["vendor_product_key"] = vendor_key
    item["fingerprint_inputs"]["location_pattern"] = f"https://example.test{path}#pre-choice"
    item["finding_fingerprint"] = finding_fingerprint(item["fingerprint_inputs"])
    item["title"] = f"Fixture {vendor_key}"
    item["locations"] = [f"https://example.test{path}"]
    validate_schema(item, "finding.schema.json", label=vendor_key)
    return item


class DeltaTests(unittest.TestCase):
    def write_run(self, directory: Path, run: dict, findings: list[dict]) -> None:
        directory.mkdir(parents=True)
        write_json(directory / "audit-run.json", run)
        write_json(directory / "findings.json", findings)

    def test_fixed_persistent_regressed_new_and_noncomparable(self) -> None:
        previous = complete_run(urls=["https://example.test/a", "https://example.test/b"])
        current = complete_run(urls=["https://example.test/a", "https://example.test/c"])
        previous["run_id"] = "PREVIOUS-RUN"
        current["run_id"] = "CURRENT-RUN"
        base = base_finding(previous)
        persistent = variant(base, "fixture:persistent", "/a")
        fixed = variant(base, "fixture:fixed", "/a")
        nonoverlap = variant(base, "fixture:nonoverlap", "/b")
        new = variant(base, "fixture:new", "/a")
        regressed = variant(base, "fixture:regressed", "/a")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prior_dir, current_dir = root / "previous", root / "current"
            self.write_run(prior_dir, previous, [persistent, fixed, nonoverlap])
            self.write_run(current_dir, current, [persistent, new, regressed])
            historical_delta = {
                "schema_version": "1.0.0", "previous_run_id": "OLDER", "current_run_id": previous["run_id"], "generated_at": "2026-08-18T12:00:00+00:00",
                "comparison_scope": "FULLY_COMPARABLE", "reason_codes": [], "versions": {}, "compared_slices": ["UNTOUCHED|https://example.test/a"],
                "items": [{"finding_fingerprint": regressed["finding_fingerprint"], "classification": "FIXED", "previous_present": True, "current_present": False, "slice_id": "UNTOUCHED|https://example.test/a", "reason_codes": []}],
                "priority_changes": [],
            }
            write_json(prior_dir / "delta.json", historical_delta)
            delta = compare(prior_dir, current_dir)
        classes = {item["finding_fingerprint"]: item["classification"] for item in delta["items"]}
        self.assertEqual("PARTIALLY_COMPARABLE", delta["comparison_scope"])
        self.assertEqual("PERSISTENT", classes[persistent["finding_fingerprint"]])
        self.assertEqual("FIXED", classes[fixed["finding_fingerprint"]])
        self.assertEqual("NEW", classes[new["finding_fingerprint"]])
        self.assertEqual("REGRESSED", classes[regressed["finding_fingerprint"]])
        self.assertEqual("NOT_COMPARABLE", classes[nonoverlap["finding_fingerprint"]])
        self.assertIn("LOCATION_NOT_SAMPLED_IN_BOTH_RUNS", delta["reason_codes"])

    def test_market_route_change_prevents_technical_delta_labels(self) -> None:
        previous = complete_run(urls=["https://example.test/a"])
        current = complete_run(urls=["https://example.test/a"])
        current["network_route"]["route_id"] = "FR-EXIT"
        current["network_route"]["externally_verified_region"] = "FR"
        finding = variant(base_finding(previous), "fixture:priority", "/a")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_run(root / "previous", previous, [finding])
            self.write_run(root / "current", current, [finding])
            delta = compare(root / "previous", root / "current")
        self.assertEqual("NOT_COMPARABLE", delta["comparison_scope"])
        self.assertIn("MARKET_OR_NETWORK_ROUTE_CHANGED", delta["reason_codes"])
        self.assertTrue(all(item["classification"] == "NOT_COMPARABLE" for item in delta["items"]))

    def test_priority_rubric_change_is_not_a_technical_regression_or_fix(self) -> None:
        previous = complete_run(urls=["https://example.test/a"])
        current = complete_run(urls=["https://example.test/a"])
        current["technical_priority_rubric_version"] = "technical-priority-v2"
        finding = variant(base_finding(previous), "fixture:priority", "/a")
        changed_priority = clone(finding)
        changed_priority["technical_priority"] = "LOW" if finding["technical_priority"] != "LOW" else "MEDIUM"
        changed_priority["technical_priority_rubric_version"] = "technical-priority-v2"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_run(root / "previous", previous, [finding])
            self.write_run(root / "current", current, [changed_priority])
            delta = compare(root / "previous", root / "current")
        self.assertEqual("PERSISTENT", delta["items"][0]["classification"])
        self.assertEqual(1, len(delta["priority_changes"]))
        self.assertFalse(delta["priority_changes"][0]["comparable"])


if __name__ == "__main__":
    unittest.main()
