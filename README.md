# Consent Privacy Audit

Audit the consent and tracker behaviour that a visitor can observe on a
deployed public website. The skill uses isolated desktop Chromium contexts,
the real consent UI where it is safe to do so, browser-level network and
storage capture, minimized evidence, and deterministic scenario comparisons.

It answers:

> What does this deployed site send, store, load, and signal before a choice,
> after rejection, after acceptance, after withdrawal, and on a later visit?

It does not answer whether a site is legally compliant. A browser audit cannot
prove lawful basis, controller relationships, contracts, transfers, CMP
back-office receipts, or unseen server-side processing.

## When to use it

Use this skill for a live cookie/CMP or tracker-runtime audit, a reported
consent leak, a pre-release consent acceptance check, a tracker-declaration
comparison, or a rescan after remediation.

Route these requests elsewhere:

- complete GTM export or workspace logic: `gtm-container-audit-cleanup`;
- planned event QA in GTM Preview: `gtm-client-recette`;
- approved GTM implementation changes: `configure-gtm`;
- GA4 property administration, server-side GTM, legal or contract decisions:
  their named owner or future skill.

## How consent is checked

The primary scan is independent of GTM Preview. Playwright Chromium records
requests, responses, redirects, scripts, frames, service workers, WebSockets
where supported, cookies and storage metadata, CMP state, consent commands,
and initiator cues. Each fresh scenario is compared with the same normalized
page and interaction sample.

The required core set is:

1. untouched/pre-choice;
2. reject;
3. accept;
4. accept then withdraw in the same context;
5. accepted choice persistence; and
6. rejected choice persistence.

The scan also keeps a separate later-observation horizon so a vendor that was
already loaded can still be observed sending after withdrawal or rejection.
Granular and reject-then-accept scenarios are conditional: they run only when
the real interface exposes an unambiguous applicable choice.

## CMP providers

One scan engine uses small versioned adapters. V1 includes Axeptio, Didomi,
OneTrust, a generic IAB TCF route, and a generic custom-banner fallback.
Detection combines several signals; one cookie or selector does not normally
confirm a provider. Controls are discovered in this order:

1. accessible role and visible localized label;
2. semantic structure and nearby consent text;
3. verified provider selectors; and
4. one analyst-assisted interaction when automation cannot safely disambiguate.

Documented API fallback may verify downstream technical behaviour, but it can
never certify banner UX. Unknown or custom CMPs remain testable with reduced
provider confidence; the scan never invents a provider, edits an undocumented
cookie, or fabricates a TCF string.

## Status model

`INCONCLUSIVE` is a valid status for an individual observation or an incomplete
diagnostic run. It is never a pass result. The delivery validator accepts only
a `COMPLETE` run, and a complete run must contain all six core scenarios with
verified state. A failed browser/capture readiness check is `ABORTED`, not a
degraded manual audit.

Technical status and rule applicability are separate. A request can be
conclusive browser evidence while the legal applicability of a CNIL rule is
still `UNKNOWN` or `REQUIRES_DPO_CONFIRMATION`.

## Inputs and outputs

Minimum intake is one deployed public URL. The run may also register markets,
regional network evidence, declaration URLs, page/interaction scope, safe
synthetic canaries, selected profiles, and explicit exclusions.

Canonical delivery is generated from validated JSON:

- `audit-run.json` — scope, browser, route, profiles, scenarios, and gates;
- `observations.jsonl` — minimized browser observations;
- `findings.json` — deterministic technical findings and owner routes;
- `declaration-diff.json` — the narrow observed-vendor/declaration comparison;
- `evidence-index.json` — sanitized, hashed evidence pointers;
- `consent-privacy-audit.md` and `consent-privacy-audit.xlsx` — human views;
- `remediation-handoff.json` and optional `recette-handoff.json`;
- `monitoring-baseline.json` for future integration; and
- `delta.json` for a comparable rescan.

Reports never contain raw HARs, request bodies, credentials, cookie values,
consent strings, real identifiers, or synthetic canary values.

## Install and run

The repository root is the skill directory. Install its runtime dependencies
and the controlled Chromium build:

```powershell
python -m pip install -r requirements.txt
python -m playwright install chromium
```

Prepare one consolidated intake and initialize a run:

```powershell
python -B scripts/init_audit_run.py intake.json -o delivery/audit-run.json
python -B scripts/verify_rule_sources.py references/jurisdiction-profiles/cnil-fr.json -o delivery/source-checks-cnil-fr.json --update-run delivery/audit-run.json
python -B scripts/scan_consent_runtime.py delivery/audit-run.json -o delivery/observations.jsonl
```

Run the source-verification command once for every selected profile. The
`--update-run` option is required; without it, the report remains
`NOT_CHECKED` and cannot support a completed delivery.

Then normalize, compare declarations, analyze, index evidence, build the
human outputs, and validate the delivery:

```powershell
python -B scripts/normalize_observations.py delivery/observations.jsonl -o delivery/observations.jsonl --update-run delivery/audit-run.json
python -B scripts/build_declaration_diff.py delivery/audit-run.json delivery/observations.jsonl declarations.json -o delivery/declaration-diff.json
python -B scripts/analyze_consent_findings.py delivery/audit-run.json delivery/observations.jsonl --declaration-diff delivery/declaration-diff.json -o delivery/findings.json
python -B scripts/redact_and_index_evidence.py delivery/audit-run.json delivery/observations.jsonl delivery/findings.json -o delivery/evidence-index.json --evidence-dir delivery/evidence
python -B scripts/build_consent_delivery.py delivery
python -B scripts/validate_consent_delivery.py delivery
```

Screenshots stay in staging until `review_screenshot_evidence.py` crops or
masks them, runs OCR/text extraction, and records an analyst visual approval.

## Profiles and boundaries

The package ships a neutral technical baseline and a dated CNIL/France profile.
Source checks are mechanical, but changed or stale sources only make their
dependent rule comparisons inconclusive; neutral browser observation continues.
The CNIL profile keeps six-month consent-choice guidance separate from the
13-month audience-measurement recommendation and does not turn either value
into a universal consent-validity rule.

V1 does not test authenticated pages, GPC, native mobile, CMP back-office
receipts, broad multi-jurisdiction law, unseen server processing, continuous
monitoring, or implementation mutation. Those boundaries are recorded and
routed to the named owner rather than silently treated as passes.

## Quality checks

Run the repository checks before a release:

```powershell
python -B scripts/validate_consent_delivery.py --package-only
python -B -m unittest discover -s tests -p "test_*.py" -v
ruff check scripts tests
```

When running in Codex, also run the installed `skill-creator` quick validator
against the repository root; it checks frontmatter and scaffold hygiene.

The controlled-browser forward test is opt-in:

```powershell
$env:RUN_CONSENT_BROWSER_TESTS = "1"
python -B -m unittest discover -s tests -p "test_browser_integration.py" -v
```

See [`SKILL.md`](SKILL.md) for routing rules, [`references/`](references/)
for the focused contracts, [`schemas/`](schemas/) for canonical JSON, and
[`references/maintenance-and-release.md`](references/maintenance-and-release.md)
for release discipline.
