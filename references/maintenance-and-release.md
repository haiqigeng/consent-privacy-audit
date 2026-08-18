# Maintenance And Release

This package is a portable Codex skill repository. The functional contract is
in `SKILL.md`; schemas, adapters, profiles, and scripts are the executable
supporting contract. Do not put workflow rules only in `agents/openai.yaml` or
in a README.

## Change discipline

- Keep the six required core scenario IDs stable. A change to their meaning is
  a scenario-contract change and makes old deltas non-comparable.
- Version any changed schema, priority rubric, fingerprint algorithm,
  identity-normalization rule, adapter semantics, or rule profile.
- Re-verify changed CNIL, Google, TCF, or CMP source sections at build time;
  never silently refresh a fingerprint after source content changes.
- Keep browser observations, rule applicability, client assertions, and
  unobservable surfaces separate.
- Do not add a provider adapter merely because it is popular. Confirm the
  client portfolio, document the supported version range and limitations, and
  add a fixture/forward test before release.
- Do not edit neighboring analytics skills as part of this package. Consumer
  adoption of handoff schemas is a separate change with its own tests.

## Validation order

From the repository root, run:

```powershell
python -B scripts/validate_consent_delivery.py --package-only
python -B -m compileall -q scripts tests
ruff check scripts tests
python -B -m unittest discover -s tests -p "test_*.py" -v
```

For a Codex distribution, also run the installed `skill-creator` quick
validator against the repository root before packaging.

Run the Playwright forward test only when Chromium is installed and the
controlled fixture is explicitly enabled:

```powershell
$env:RUN_CONSENT_BROWSER_TESTS = "1"
python -B -m unittest discover -s tests -p "test_browser_integration.py" -v
```

The forward matrix maps all 37 v2.1 acceptance scenarios to unit, contract,
source-verification, safety, or controlled-browser evidence. A skipped browser
test is not a substitute for a production audit.

## Version and release

1. Update `VERSION`, `SKILL.md`, `pyproject.toml`, and `CHANGELOG.md` together.
2. Run every validation command above and inspect `git diff --check`.
3. Re-run the controlled pilot when scanner, adapter, capture, or scenario
   semantics change.
4. Commit the source tree and tag the same version as `v<major>.<minor>.<patch>`.
5. Install the tagged repository into a clean Codex skill location and run the
   package-only validator plus the unit suite from that installed copy.
6. Push the commit and tag only after the clean-install check passes.

Do not publish a `COMPLETE` audit from a run whose required scenario is
`INCONCLUSIVE`, `NOT_TESTED`, or missing. Preserve that run as diagnostic
evidence and route the smallest recovery action instead.

## Clean-install smoke test

The install target is the repository root, not a generated delivery directory.
After installation, verify that `SKILL.md`, `agents/openai.yaml`, every schema,
adapter, profile, script, and test fixture is present, then run:

```powershell
python -B scripts/validate_consent_delivery.py --package-only
python -B -m unittest discover -s tests -p "test_*.py"
```

The installed package must not contain `delivery/`, `staging/`, restricted
canary files, raw captures, or production audit outputs.
