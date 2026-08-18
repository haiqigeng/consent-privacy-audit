# Forward Test Matrix

This matrix maps the 37 release scenarios in the v2.1 requirements to automated or controlled-browser evidence. Run the unit/contract suite with:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

The controlled-browser pilot uses `tests/fixture_server.py`, initializes both profiles, mechanically verifies their sources, executes all six required scenarios through Playwright Chromium, then runs the full delivery validator. It deliberately leaves a 650 ms collection timer active after withdrawal; the expected result is a browser finding in `post_withdraw_later`.

| # | Required scenario | Test evidence |
| ---: | --- | --- |
| 1 | Hardcoded Meta before choice routes to development | `AnalyzerRoutingTests.test_hardcoded_meta_before_choice_routes_to_development` |
| 2 | GTM analytics after rejection creates only a supporting handoff | `AnalyzerRoutingTests.test_gtm_association_creates_supporting_only_handoff` |
| 3 | Loaded vendor continues after withdrawal | Controlled pilot plus `test_later_withdrawal_window_is_classified_and_repeated_requests_keep_unique_evidence` |
| 4 | Rejection persists across reload/second page | Controlled pilot plus `CmpTests.test_state_semantics_cover_withdrawal_and_persistence` |
| 5 | Granular denial does not activate advertising silently | `test_granular_denial_does_not_activate_advertising_silently` |
| 6 | First-party proxy is not harmless | `test_first_party_proxy_and_service_worker_are_not_harmless` |
| 7 | Service-worker route remains material | `test_first_party_proxy_and_service_worker_are_not_harmless` |
| 8 | Unknown/custom CMP degrades honestly | `CmpTests.test_unknown_custom_cmp_degrades_without_provider_claim` and controlled pilot |
| 9 | Localized custom controls use semantic discovery | `CmpTests.test_customized_localized_control_is_found_semantically` |
| 10 | API fallback leaves UX inconclusive | `BoundaryTests.test_api_fallback_cannot_certify_cmp_ux` |
| 11 | Canary reaches request without value retention | `AnalyzerRoutingTests.test_canary_is_detected_without_value_retention` |
| 12 | Real personal data stops export | `SafetyTests.test_personal_data_and_canary_scans_fail_closed` |
| 13 | Changed/unknown volatile decoding is inconclusive | `SourceVerificationTests.test_matching_changed_unreachable_and_stale_sources_are_localized` and source-dependent analyzer test |
| 14 | Cookie wall routes to contextual legal review | `BoundaryTests.test_cookie_wall_remains_contextual_legal_review` |
| 15 | Exemption lacks organizational proof | `BoundaryTests.test_exemption_keeps_organizational_evidence_unobservable` |
| 16 | Regional routes remain separate | `DeltaTests.test_market_route_change_prevents_technical_delta_labels` |
| 17 | Banner variants stay separately identifiable | `BoundaryTests.test_ab_banner_variants_have_distinct_normative_location_identity` |
| 18 | Declared/unobserved is NOT_VERIFIED | `DeclarationTests.test_declared_unobserved_is_not_verified` |
| 19 | Observed/undeclared appears in both outputs | `DeclarationTests.test_observed_undeclared_appears_in_diff_and_findings` |
| 20 | `gtm.js` association remains suspected | GTM handoff routing test |
| 21 | Saved undeployed GTM is not runtime evidence | `BoundaryTests.test_saved_undeployed_gtm_is_not_runtime_evidence` |
| 22 | All five delta labels are accurate | `DeltaTests.test_fixed_persistent_regressed_new_and_noncomparable` |
| 23 | Raw HAR/authorization data cannot enter delivery | `BoundaryTests.test_raw_har_is_rejected_from_normal_delivery` and delivery privacy validation |
| 24 | Generic TCF does not activate on non-TCF site | `CmpTests.test_generic_tcf_does_not_activate_without_tcf_signals` |
| 25 | Browser geolocation cannot prove market | `BoundaryTests.test_market_claim_requires_verified_network_route` |
| 26 | All priority rows/order/missing input/version are exercised | `PriorityTests` |
| 27 | Rubric change is not a technical regression/fix | `DeltaTests.test_priority_rubric_change_is_not_a_technical_regression_or_fix` |
| 28 | Fingerprint ignores volatile fields and changes on normative input | `FingerprintTests` |
| 29 | Expanded/reduced samples compare overlap only | Five-label delta test |
| 30 | Source MATCHED/CHANGED/UNREACHABLE/STALE affects dependent rules only | Source verification and analyzer source-localization tests |
| 31 | Unauthorized production submit is NOT_TESTED | `SafetyTests.test_production_submission_stops_without_exact_authorization` |
| 32 | Test/authorized submission records no canary value | `SafetyTests.test_test_environment_submission_is_allowed_without_retained_canary` |
| 33 | Screenshot canary is rejected; safe reviewed copy passes | `SafetyTests.test_screenshot_gate_rejects_visible_canary_and_delivers_only_reviewed_safe_copy` |
| 34 | Missing browser readiness creates ABORTED manifest | `BoundaryTests.test_browser_readiness_failure_writes_aborted_manifest` |
| 35 | Codex metadata is minimal and runtime-appropriate | `BoundaryTests.test_codex_metadata_is_minimal_and_functional_instructions_stay_in_skill` |
| 36 | Authenticated routes remain post-v1 | `BoundaryTests.test_authenticated_and_gpc_are_explicit_post_v1_boundaries` |
| 37 | GPC does not route to v1 | Same explicit-boundary test and frontmatter routing validation |

The controlled fixture never submits a real lead, creates an account, purchases, books, subscribes, or handles real personal data.
