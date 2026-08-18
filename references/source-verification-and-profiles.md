# Source Verification And Profiles

## Included profiles

- `neutral-technical`: observation, comparison, state-verification, non-retention, and declaration consistency without legal classification.
- `cnil-fr`: bounded browser tests derived from current CNIL sources. Applicability facts and unobservable dependencies remain explicit; DPO/legal review is required where marked.

The six-month choice-retention guidance is distinct from the 13-month audience-measurement tracker recommendation. Neither is a universal consent-validity rule.

## Mechanical source check

For each profile source:

1. retrieve the authoritative URL with safe redirects;
2. extract the declared bounded visible-text section;
3. normalize HTML entities, Unicode NFC, non-breaking spaces, and whitespace under `visible-text-nfc-whitespace-v1`;
4. hash with SHA-256;
5. compare with the human-reviewed snapshot and staleness threshold.

Return exactly `MATCHED`, `CHANGED`, `UNREACHABLE`, `STALE`, or `NOT_CHECKED`.

Only current `MATCHED` sources enable dependent rule evaluation. Other results create a human re-verification task and make only dependent rules `INCONCLUSIVE`; neutral observation continues.

Do not update a fingerprint automatically after change. Human review must inspect the bounded content, dates, applicability, expectation, and exceptions. If meaning changed, create a new profile/rule version and preserve history.

## Volatile fields

Never freeze TCF, GVL, CMP, or Google request encodings as timeless. Keep raw safe parameter names/values, decoder/source version, and verification date. Unknown or changed encoding is inconclusive. Presence of one Google or TCF field cannot prove compliant behavior.

## Applying CNIL rules

The browser can show requests, storage, timing, visitor controls, expiry metadata, and differential behavior. It cannot establish controller purpose, lawful basis, strict necessity, exception eligibility, anonymization, no vendor reuse, contracts, transfers, or back-office consent receipts.

Use rule applicability facts to avoid overclaiming. Missing facts do not block scanning; they block only the affected rule conclusion.
