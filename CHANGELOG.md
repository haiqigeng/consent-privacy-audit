# Changelog

## [1.0.10] - 2026-08-19

### Added

- Complete repository documentation covering consent checks, CMP adapters,
  status semantics, inputs/outputs, installation, and release validation.
- Standard MIT license, Python project metadata, and continuous-integration
  checks consistent with the other analytics skill repositories.
- Maintenance and release contract for source verification, forward tests, and
  clean local installation.

### Fixed

- A delivery can no longer pass with a missing or duplicated required core
  scenario. The six-scenario requirement is now enforced by the schema and
  delivery validator, and missing scenario IDs block the scanner run.

## [1.0.9] - 2026-08-18

- Wait for slow CMP UI state transitions to settle before verifying a choice.

## [1.0.0] - 2026-08-18

- Initial consent runtime audit release with browser capture, versioned CMP
  adapters, neutral/CNIL profiles, privacy-safe evidence, deterministic
  findings, handoffs, and rescan deltas.

Patch releases between 1.0.0 and 1.0.9 tightened redaction, OneTrust control
discovery, declaration fallback, source handling, and incomplete-run gates.
