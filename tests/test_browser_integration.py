from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from helpers import ROOT
from fixture_server import Handler

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from analyze_consent_findings import analyze  # noqa: E402
from consent_runtime_core import iter_jsonl, read_json, write_json  # noqa: E402
from init_audit_run import build  # noqa: E402
from scan_consent_runtime import main as scan_main  # noqa: E402


@unittest.skipUnless(os.environ.get("RUN_CONSENT_BROWSER_TESTS") == "1", "set RUN_CONSENT_BROWSER_TESTS=1 for the Playwright forward test")
class BrowserIntegrationTests(unittest.TestCase):
    def test_all_core_scenarios_and_later_withdrawal_capture(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            run = build(
                {
                    "run_id": "BROWSER-INTEGRATION",
                    "urls": [f"http://127.0.0.1:{port}/", f"http://127.0.0.1:{port}/second"],
                    "environment": "test", "deployment_verified": True, "deployment_evidence": ["controlled fixture server"],
                    "rule_profiles": [{"profile_id": "neutral-technical", "applicability": "CONFIRMED"}, {"profile_id": "cnil-fr", "applicability": "CONFIRMED"}],
                    "markets": [], "declaration_urls": [], "exclusions": [], "authenticated_boundaries": [],
                    "network_route_id": "LOCAL-FIXTURE", "headed": False, "locale": "en-US", "timezone": "Europe/Paris",
                }
            )
            for check in run["source_checks"]:
                check.update({"status": "MATCHED", "checked_at": "2026-08-18T12:00:00+00:00", "task_required": False, "note": "Controlled analyzer fixture; source verifier is tested separately"})
            with tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                run_path = directory / "audit-run.json"
                observations_path = directory / "observations.jsonl"
                write_json(run_path, run)
                original = sys.argv
                try:
                    sys.argv = [
                        "scan_consent_runtime.py", str(run_path), "--output", str(observations_path),
                        "--adapter", "generic-custom-banner", "--quiet-ms", "300", "--later-ms", "1000", "--timeout-ms", "4000",
                    ]
                    self.assertEqual(0, scan_main())
                finally:
                    sys.argv = original
                completed = read_json(run_path)
                observations = list(iter_jsonl(observations_path))
            self.assertTrue(all(item["status"] == "COMPLETE" and item["state_verified"] is True for item in completed["scenarios"]))
            later = [item for item in observations if item["scenario_class"] == "ACCEPTED_TO_WITHDRAWN" and item["action_window"] == "post_withdraw_later" and item["surface"] == "NETWORK"]
            self.assertGreaterEqual(len(later), 1)
            findings = analyze(completed, observations)
            self.assertTrue(any(item["fingerprint_inputs"]["scenario_class"] == "ACCEPTED_TO_WITHDRAWN" for item in findings))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
