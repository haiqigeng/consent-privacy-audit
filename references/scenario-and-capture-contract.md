# Scenario And Capture Contract

## Isolation

Create one new browser context per independent scenario. Keep one context inside an accept-to-withdraw or reject-to-accept transition. Use dedicated persistence contexts. Never carry authentication, cache, cookies, storage, or service workers unintentionally.

If isolation or resulting state cannot be proved, mark affected tests `INCONCLUSIVE`; do not infer state from a banner click alone.

## Required execution

### Untouched

Load fresh, do not touch the banner, wait for an activity-aware quiet window, perform a comparable second page/route, and verify no implicit choice. Record initial and later behavior separately.

### Reject

Use the real reject or continue-without-accepting control. Verify state from a documented surface plus browser differential. Capture immediate, second-view, and persistence behavior.

### Accept

Use the real accept-all control. Verify state and capture immediate plus later vendor activation.

### Accept then withdraw

Accept, verify, reopen through the persistent visitor control, withdraw, verify, and capture immediate continued requests, later automatic requests, new storage access, and next navigation. Already-loaded code is an observed fact, not assumed to stop.

### Persistence

Prepare accepted and rejected choices separately. Reload/revisit and verify the choice, banner state, storage expiry metadata, and browser behavior.

Run granular category and reject-to-accept scenarios only when the real interface exposes an unambiguous applicable choice.

## Activity-aware windows

Use a bounded timeout and quiet interval. Restart the quiet interval when relevant network or state activity occurs. Record timeout, quiet interval, start/end times, and whether the window settled. A fixed sleep alone is not readiness proof.

After the final visitor choice, also keep a separate fixed later-observation horizon. The default is 2.5 seconds and it may be increased for known slow vendor timers; shortening it below 500 ms is invalid. Preserve that traffic under `post_<choice>_later` so periodic activity after rejection or withdrawal cannot hide behind an earlier quiet interval.

## Network

Capture browser-context navigation, scripts, pixels/images, fetch/XHR, beacons, forms, redirects, frames/popups, workers, WebSockets/EventSource where supported, method, sanitized URL, timing, response status, frame/worker/source cues, and failed/cancelled status.

Do not treat first-party hosts as safe. Flag suspected CNAME, proxy, gateway, sGTM, or service-worker routes. Never infer downstream forwarding.

## Storage and state

Retain cookie names and metadata only: domain, path, expiry, host-only, HttpOnly, Secure, SameSite, and partitioning when available. Retain local/session storage and IndexedDB database/store names and safe structure, not values.

Capture documented CMP state summaries, consent lifecycle events, Google default/update timing, safe TCF fields, and state at each request/action. Never retain a TC string, CMP visitor token, consent receipt ID, or raw consent cookie.

## CMP interaction

1. Detect by multiple weighted signatures.
2. Prefer accessibility role and visible localized label.
3. Use version/provider selectors only when semantic discovery fails.
4. Verify the resulting state and browser differential.
5. Record UI, analyst-assisted, or API-fallback method.

Unknown provider identity does not stop untouched capture. Interact only when the intended choice is unambiguous; otherwise request one analyst-assisted click. API fallback leaves banner UX `INCONCLUSIVE` or `NOT_TESTED` and must use only a documented API.
