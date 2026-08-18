# Declaration And Handoff Contract

## Narrow public declaration diff

Inspect only tracker-relevant public material: cookie/tracker policy, visitor-facing CMP vendor/purpose list, preference center, linked vendor list, and tracker table inside a privacy notice. Do not audit the whole notice.

Normalize declarations and observations to the same vendor/product key while preserving source wording, purpose/category, and duration for review.

- Observed but undeclared: `TECHNICAL_DECLARATION_MISMATCH`, DPO review.
- Declared but unobserved: `NOT_VERIFIED`, never automatic failure.
- Both: compare identity, purpose/category, and duration when reliable.
- Ambiguous: `INCONCLUSIVE`.
- Unknown observed endpoint: retain as an investigation item.

Every observed product appears in the diff.

## Recette handoff

Create only for a substantiated suspected GTM layer. Include exact reproduction, consent state/timing, safe request cues, expected and observed behavior, acceptance rule, evidence IDs, and limitations.

It must contain:

```json
{"role":"SUPPORTING_ONLY","verdict_authority":false}
```

The consumer must independently open Preview under its own readiness gate. This artifact cannot establish a Preview verdict.

## Remediation handoff

Every actionable finding may create one `MANUAL_ONLY` proposed outcome with primary/contributing owners, confirmed versus suspected cause, approvals, external decisions, prohibited reinterpretations, and exact retest rule. It is not mutation authority.

## Monitoring baseline

The baseline contains stable fingerprints, scenario identities, comparison fields, and freshness requirements only. It is `FUTURE_INTEGRATION_ONLY`; this skill does not schedule or run continuous monitoring.

## Contract adoption

Existing skills consume these artifacts manually until they add an explicit importer, schema version, source/hash verification, authority semantics, approval behavior, rejection of unknown contracts, and forward tests. Do not silently edit neighboring skills.
