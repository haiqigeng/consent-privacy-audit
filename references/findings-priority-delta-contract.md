# Findings, Priority, And Delta Contract

## Separate dimensions

`technical_test_status` reports one bounded browser test. `rule_applicability` reports whether the selected rule can be applied. A conclusive browser observation can coexist with unknown legal applicability.

Keep `observed_initiator`, `suspected_implementation_layer`, `attribution_confidence`, `root_cause_status`, and `confirmed_root_cause_evidence` separate. A `gtm.js` initiator supports suspected GTM attribution but does not prove a tag, trigger, exception, or container object.

## Technical priority v1

Evaluate ordered rows; first match wins. A cluster receives the highest constituent priority.

1. `URGENT`: credential, auth token, payment datum, or special-category canary reaches an unintended collection endpoint.
2. `HIGH`: reproduced contact/direct identifier canary reaches an unintended vendor; or a reproduced rejected/withdrawn/denied contradiction involves advertising/personalization, a stable identifier, or systemic breadth.
3. `MEDIUM`: reproduced analytics/unknown-purpose contradiction, choice/withdrawal/persistence failure, materially unresolved proxy/worker route, observed-undeclared product, or required state-verification gap.
4. `LOW`: reproduced localized technical, declaration-metadata, accessibility, or presentation defect without unintended identifier transmission; or non-material optional inconclusive test.
5. `INFORMATIONAL`: expected, not applicable, deliberately not tested without contradiction, or declared-but-unobserved `NOT_VERIFIED`.

`REPRODUCED` means two isolated equivalent observations or one controlled run plus independent equivalent evidence. `SYSTEMIC` means at least two material route/templates or a shared consent mechanism before route-specific code. Never use this ranking as legal severity.

## Stable fingerprint

Use `finding-fingerprint-jcs-sha256-v1`: SHA-256 over UTF-8 canonical JSON containing exactly stable `rule_id`, `finding_kind`, `vendor_product_key`, `scenario_class`, and normalized `location_pattern`.

Do not include timestamps, priority, evidence path, initiator, suspected layer, attribution, root cause, or volatile URL values. Store the normalized input object so the hash is independently reproducible.

Unknown products use normalized registrable domain plus endpoint path template. Locations use origin identity, route/template ID, and semantic interaction ID.

## Delta compatibility

Determine full, partial, or no comparability before finding labels. Reason codes are fixed in `delta.schema.json`. Changed origin/environment, fingerprint algorithm, rule meaning/applicability, profile/source readiness, scenario definition, market route, capture capability, required execution, sampled location, identity normalization, or adapter semantics can make a slice not comparable.

Compare only overlapping slices when scope expands or contracts. A missing finding is `FIXED` only when the exact comparable slice was retested and expected behavior observed. Non-overlap is never silently `NEW` or `FIXED`. Report priority-only changes separately.
