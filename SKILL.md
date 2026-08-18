---
name: consent-privacy-audit
description: Audit deployed public websites for browser-observed consent and tracker behavior across untouched, reject, accept, withdrawal, persistence, and applicable granular scenarios. Use for live CMP/cookie behavior, trackers before choice or after rejection, Consent Mode runtime checks, declaration mismatches, and evidence-safe rescans. Do not use for legal compliance opinions, GTM/CMP/site mutation, ordinary tracking-plan-led Preview recette, authenticated or GPC scenarios in v1, or unseen server-side processing.
---

# Consent Privacy Audit

## North star

Observe what the deployed public site sends, stores, loads, and signals under each tested visitor choice. Compare only with a current, mechanically verified, applicable technical or jurisdiction/client rule profile. Produce sanitized technical findings and owner routes without claiming legal compliance or changing the implementation.

## Non-negotiable boundaries

- Audit deployed browser behavior. A saved GTM workspace, export, CMP configuration, or client statement is supporting context, not runtime proof.
- Use desktop Chromium v1. Record the exact browser, capture, network route, market evidence, sample, and limitations.
- Do not use GTM Preview in the primary scan. If browser evidence points to GTM, finish the finding first and create a `SUPPORTING_ONLY` recette handoff.
- Do not mutate GTM, CMP, website, GA4, vendor, or server settings; publish; deploy; bypass access controls; or infer unseen server forwarding.
- Do not test authenticated pages, signed-in consent sync, multi-device consent, or GPC in v1. Record them as uncovered boundaries.
- Never state that the site, CMP, or implementation is GDPR compliant. Keep technical status and rule applicability separate.
- Never retain request bodies, raw HARs, cookie values, credentials, tokens, real identifiers, or canary values in normal output.
- Fail closed when a controlled browser or required capture capability is unavailable. Produce an `ABORTED` manifest and route setup to `web-analyst-mcp-setup`; do not downgrade to an uncontrolled manual audit.

## Load references progressively

| Need | Read |
| --- | --- |
| Scope, suite boundaries, and owner routing | [product and boundaries](references/product-and-boundaries.md) |
| Intake, commands, execution, and delivery | [adaptive workflow](references/adaptive-workflow.md) |
| Required scenarios, capture, and CMP interaction | [scenario and capture contract](references/scenario-and-capture-contract.md) |
| Personal-data, canary, request, and screenshot safety | [evidence and redaction contract](references/evidence-and-redaction-contract.md) |
| Status, priority, fingerprints, and rescans | [findings, priority, and delta contract](references/findings-priority-delta-contract.md) |
| Public declarations and cross-skill artifacts | [declaration and handoff contract](references/declaration-and-handoff-contract.md) |
| Applying neutral/CNIL profiles or refreshing sources | [source verification and profiles](references/source-verification-and-profiles.md) |
| Provider detection, semantic controls, or fallback | [CMP adapter contract](references/cmp-adapter-contract.md) and only the detected adapter JSON |
| Maintaining or releasing this skill | [forward test matrix](tests/FORWARD-TEST-MATRIX.md) |

## One adaptive workflow

1. Resolve one consolidated intake: exact deployed URL(s), environment, markets, verified network route, public declaration URLs, safe interaction boundary, exclusions, and output language.
2. Initialize `audit-run.json`. Register all required scenarios before browser activity.
3. Verify every selected rule source. Only `MATCHED` and non-stale sources can support rule evaluation; otherwise make only dependent rules `INCONCLUSIVE`.
4. Establish the controlled browser and capture readiness. Abort rather than improvise when readiness fails.
5. Detect the CMP with weighted signatures. Prefer real UI, semantic roles, and visible localized labels; use provider selectors only as fallback. For a missing persistent control, exhaust the registered public declaration URLs before treating the scenario as incomplete.
6. Execute isolated untouched, rejected, accepted, accepted-to-withdrawn, accepted-persistence, and rejected-persistence scenarios. Add granular/reject-to-accept only when applicable. An `INCONCLUSIVE` required core scenario is an incomplete run, not an acceptable completed delivery; preserve the diagnostic evidence, but do not issue a `COMPLETE` report until the scenario is rerun successfully or explicitly marked `NOT_TESTED` with the required handoff.
7. Capture minimized network, cookie/storage metadata, scripts/embeds, service workers, consent state/timing, initiators, safe DOM, and approved screenshot evidence.
8. Normalize observations, compare scenarios, build technical findings, and run the narrow public declaration diff.
9. Build the Markdown, XLSX, evidence index, manual remediation handoff, optional supporting-only recette handoff, and future-only monitoring baseline from validated canonical artifacts.
10. Run the delivery validator. On rescans, determine compatibility before classifying `FIXED`, `PERSISTENT`, `REGRESSED`, `NEW`, or `NOT_COMPARABLE`.

Do not ask the user to know every intake fact. Continue public observation with explicit limits. Ask only for access/setup, a consequential-action authorization, a rule-applicability fact that changes a requested conclusion, or one genuinely ambiguous CMP interaction.

## Evidence and judgment model

Classify every material fact as exactly one of:

- `BROWSER_OBSERVED`
- `ADMIN_EVIDENCED`
- `CLIENT_ASSERTED`
- `UNOBSERVABLE`

Use one bounded technical status for individual observations and findings:

- `EXPECTED_BEHAVIOUR_OBSERVED`
- `UNEXPECTED_BEHAVIOUR_OBSERVED`
- `INCONCLUSIVE`
- `NOT_APPLICABLE`
- `NOT_TESTED`

Record rule applicability separately as `CONFIRMED`, `CLIENT_ASSERTED`, `REQUIRES_DPO_CONFIRMATION`, `NOT_APPLICABLE`, or `UNKNOWN`. `INCONCLUSIVE` is never a pass result and cannot coexist with a `COMPLETE` run for a required core scenario.

## Required scenarios

- `UNTOUCHED`: fresh context, no banner action, bounded quiet window, second page or route, and verification that no implicit choice appeared.
- `REJECTED`: fresh context, real reject UI, verified state, immediate and later browser behavior.
- `ACCEPTED`: fresh context, real accept UI, verified state, immediate and later browser behavior.
- `ACCEPTED_TO_WITHDRAWN`: same context, reopen preferences, withdraw, verify state, then capture continued immediate and later activity. If the persistent control is not visible on the landing page, navigate through each registered public declaration URL and retry the visible UI before recording an incomplete scenario.
- `PERSISTENCE_ACCEPTED` and `PERSISTENCE_REJECTED`: separate prepared contexts, reload/revisit, and compare retained state and behavior.

Never carry context across independent scenarios. API fallback cannot certify banner UX. Never fabricate TCF strings or edit undocumented consent cookies.

## Production interaction authority

Synthetic field entry, blur, validation, and non-submitting steps are permitted inside the registered safe boundary. A form submission requires a test environment or exact authorization naming the production form, allowed synthetic record, scan window, notification risk, cleanup owner, and cleanup method. Otherwise stop and mark submit-dependent leakage `NOT_TESTED`.

Never make a purchase, payment, booking, real-person lead, real message, subscription, consequential account, or irreversible action.

## Canonical delivery

Deliver only from validated artifacts:

- `audit-run.json`
- `observations.jsonl`
- `findings.json`
- `declaration-diff.json`
- `evidence-index.json`
- `consent-privacy-audit.md`
- `consent-privacy-audit.xlsx`
- `recette-handoff.json` when GTM follow-up is substantiated
- `remediation-handoff.json`
- `monitoring-baseline.json`
- `delta.json` on comparable rescans

The workbook is a view of canonical JSON and cannot introduce findings. Handoffs are never mutation or verdict authority.

## Closeout language

Use one of:

- No sampled technical contradiction was detected under the selected and applicable tests.
- One or more sampled technical contradictions were observed.
- Material tests remain inconclusive or untested.

Always disclose exact scope, markets, route evidence, sample, exclusions, unobserved surfaces, source freshness, and the no-legal-compliance boundary.
