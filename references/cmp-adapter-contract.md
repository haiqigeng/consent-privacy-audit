# CMP Adapter Contract

## Architecture

One provider-independent engine loads small versioned adapter JSON files. An adapter contributes detection signatures, readiness/state surfaces, semantic control hints, sources, and limitations. It does not create a separate audit workflow.

Validate every adapter against `schemas/cmp-adapter.schema.json` before use.

## Detection confidence

Sum distinct matching signature weights, but require different signature kinds for confirmation:

- `CONFIRMED`: at least 70 points across at least two kinds.
- `PROBABLE`: at least 40 points or one highly specific signature.
- `UNKNOWN`: no provider reaches probable confidence.
- `CONFLICTING`: more than one provider reaches confirmed confidence or incompatible state surfaces coexist.

One cookie or DOM selector alone does not normally confirm a provider. Detection never proves correct configuration.

## Interaction order

1. Accessibility role plus visible label after Unicode/diacritic normalization.
2. Semantic structure and nearby consent-purpose text.
3. Provider selector for the verified adapter/version.
4. One analyst-assisted click when the control is unambiguous to a person but unsafe to automate.
5. Documented API fallback only when allowed by the adapter.

After interaction, verify documented state plus differential browser behavior. Record the method.

## Unknown/custom banner

Capture untouched behavior, discover rendered controls, interact only when unambiguous, verify state through changes, and retain provider confidence as unknown/probable. Never invent a provider, edit an undocumented cookie, or fabricate a consent string.

## API fallback

API fallback may test downstream behavior but cannot certify UI choice, banner accessibility, or end-to-end consent interaction. Mark those tests `INCONCLUSIVE` or `NOT_TESTED`, disclose method/values/timing, and independently verify resulting state. Before accepting an unavailable persistent UI control as incomplete, retry the visible control on every registered public declaration URL. A required core scenario that remains `INCONCLUSIVE` blocks a `COMPLETE` delivery.
