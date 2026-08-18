# Evidence And Redaction Contract

## Default evidence

Normal delivery may contain sanitized request metadata, parameter names and verified safe consent values, cookie/storage names and metadata, minimized CMP state/timing, source/initiator cues, approved screenshots, and non-retention markers.

It must not contain raw HARs, request/response bodies, authorization headers, Cookie/Set-Cookie values, credentials, tokens, form values, live identifiers, raw consent strings, or real personal data.

Hashing is pseudonymization, not anonymization. Do not hash and retain a sensitive value merely to make matching convenient.

## URL and request minimization

- Retain scheme, normalized host, path template, query parameter names, and only allowlisted consent/configuration values.
- Replace UUIDs, timestamps, long numeric identifiers, hashes, emails, phone-like strings, and unknown query values with redacted markers.
- Inspect request bodies only in memory for canary detection. Never write them.
- Preserve `gcs`, `gcd`, `dma`, and `dma_cps` only when current verified documentation supports the field and the value passes the safe-value policy. Unknown encoding is `INCONCLUSIVE`.

## Synthetic canaries

Use unique fake values and reserved domains. Keep values only in restricted input or process memory. Record canary ID, field/path, destination, safe parameter path, category, detection basis, technical status, redacted marker, and `value_fingerprint: NOT_RETAINED`.

Field entry, blur, validation, and non-submitting steps are allowed inside the registered safe boundary. Production submission needs exact authorization. Without it, submit-dependent leakage is `NOT_TESTED`.

If real personal data appears, stop propagating it, quarantine/discard unsafe capture, retain only category/location/redacted marker, and recreate proof with synthetic data when possible.

## Screenshots

Default to consent-UI, preference-center, or blocked-embed regions. Before delivery:

1. crop or mask fields, autofill, validation, account, or page areas that may show a canary or person;
2. run OCR/text extraction against in-memory canaries and sensitive patterns;
3. retain only pass/fail and redacted markers from that scan;
4. require an analyst visual pass;
5. omit the image if any step is unavailable or fails.

`evidence-index.json` permits screenshot evidence only when crop/mask, OCR, and analyst statuses are all `PASSED`.

## Restricted evidence

Raw evidence is exceptional and requires explicit authorization, a separate restricted location, named purpose/owner/access/retention/deletion responsibility, and sanitized derivatives. Never include restricted content in reports, workbooks, chat, or handoffs.
