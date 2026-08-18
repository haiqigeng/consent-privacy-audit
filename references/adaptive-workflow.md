# Adaptive Workflow

## Intake

Resolve once:

- in-scope origins, URLs/routes, templates, markets, locales, and exclusions;
- exact environment and deployment evidence;
- verified network/IP region separately from browser locale/geolocation;
- critical public journeys and safe interaction boundaries;
- known CMP, declaration URLs, and optional policy/profile facts;
- optional measurement, GTM audit/configuration, or client-policy evidence;
- rate limits, scan window, production constraints, and output language.

Credentials do not expand v1. Record authenticated surfaces as uncovered.

## Commands

Run commands from the skill directory.

First use requires the Python dependencies and a Playwright Chromium build:

```powershell
python -m pip install -r requirements.txt
python -m playwright install chromium
```

If installation, browser launch, or capture readiness fails, route setup to `web-analyst-mcp-setup` and preserve an `ABORTED` run rather than attempting a manual substitute.

Initialize:

```powershell
python -B scripts/init_audit_run.py intake.json -o delivery/audit-run.json
```

Verify selected profiles before scanning:

```powershell
python -B scripts/verify_rule_sources.py references/jurisdiction-profiles/cnil-fr.json -o delivery/source-checks.json
```

Run the controlled browser scan:

```powershell
python -B scripts/scan_consent_runtime.py delivery/audit-run.json --output delivery/observations.jsonl
```

The scanner uses an activity-aware immediate window plus a separate 2.5-second later horizon by default. Increase `--later-ms` for a known slower vendor timer; do not reduce it below 500 ms.

Add `--interaction-plan plan.json --canary-file restricted-canaries.json` only when synthetic form testing is actually in scope. The canary file is restricted input and is never copied to delivery.

Normalize, compare declarations, analyze, and build delivery:

```powershell
python -B scripts/normalize_observations.py delivery/observations.jsonl -o delivery/observations.jsonl --update-run delivery/audit-run.json
python -B scripts/build_declaration_diff.py delivery/audit-run.json delivery/observations.jsonl declarations.json -o delivery/declaration-diff.json
python -B scripts/analyze_consent_findings.py delivery/audit-run.json delivery/observations.jsonl --declaration-diff delivery/declaration-diff.json -o delivery/findings.json
python -B scripts/redact_and_index_evidence.py delivery/audit-run.json delivery/observations.jsonl delivery/findings.json -o delivery/evidence-index.json --evidence-dir delivery/evidence
python -B scripts/build_consent_delivery.py delivery
python -B scripts/validate_consent_delivery.py delivery
```

Screenshots remain in staging until `review_screenshot_evidence.py` confirms a safe crop/mask, OCR/text extraction, and an analyst visual pass. Run screenshot review after evidence indexing and before the report/workbook build. The delivery builder preserves a valid reviewed screenshot index; the delivery validator reruns OCR for every delivered screenshot and fails closed if the OCR dependency is unavailable.

```powershell
python -B scripts/review_screenshot_evidence.py staging/banner.png delivery/evidence-index.json --evidence-id EVD-banner --output-dir delivery/evidence --cropped-or-masked --analyst-approved --update-run delivery/audit-run.json
```

Compare validated runs:

```powershell
python -B scripts/compare_consent_runs.py previous current -o current/delta.json
```

## Readiness

Before scanning, prove:

1. the URL is public HTTP(S) and belongs to the approved origin;
2. deployment is marked verified;
3. Chromium launches and exact version is captured;
4. clean contexts, network events, cookies, storage, CMP state, scripts/frames, service workers, and initiator cues are capturable;
5. the verified route supports any market claim;
6. selected profile sources are current enough to apply.

If 1–5 fail, write an `ABORTED` manifest and stop. If a source check fails, continue neutral observation but make only dependent rules inconclusive.

## Coverage

Build the sample from supplied journeys plus rendered route templates, critical public paths, embeds, vendor-triggering interactions, CMP/locale variants, second-page or SPA transitions, and realistic activation opportunities for declared vendors. Comparable scenarios use the same normalized sample. Every candidate is tested, excluded, blocked, or unresolved.

## Delivery gate

Delivery is valid only when:

- schemas and cross-file identities validate;
- every scenario/capture surface has a status;
- source checks and applicability are visible;
- no raw HAR, body, cookie value, token, credential, canary, or real identifier leaked;
- screenshot evidence has crop/mask, OCR/text, and analyst approval;
- findings use the versioned priority and fingerprint contracts;
- handoffs retain supporting/manual-only roles;
- human outputs are derived from canonical JSON;
- no legal-compliance statement appears.
