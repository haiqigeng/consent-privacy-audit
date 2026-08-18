# Product And Boundaries

## Purpose

This skill owns deployed browser consent and tracker runtime evidence. It answers what the sampled site does under tested visitor choices and who should investigate a contradiction. It does not certify lawfulness or whole-site compliance.

## V1 surface

- Public deployed pages and safe public interactions.
- Neutral technical and CNIL/France profiles.
- Desktop Chromium.
- Axeptio, Didomi, OneTrust, generic TCF, and generic custom-banner adapters.
- Network, storage metadata, CMP state/timing, scripts/embeds, service workers, initiators, screenshots that pass the privacy gate, canary markers, declarations, reports, handoffs, and rescans.

Authenticated journeys, GPC, native mobile, CMP back-office receipts, GA4 property privacy settings, server-side GTM behavior, continuous monitoring, transfer analysis, contracts, DPIAs, and full privacy-notice review are outside v1.

## Suite interaction

| Neighbor | This skill may exchange | Boundary |
| --- | --- | --- |
| design-measurement-framework | Consume journeys and variants as coverage hints. | Journey evidence does not prove complete runtime scope; do not design KPIs. |
| ga4-tracking-plan | Produce confirmed sensitive-field observations or approved privacy constraints for later review. | Do not choose GA4 semantics or edit a plan. |
| gtm-container-audit-cleanup | Consume complete static configuration as supporting evidence. | Static configuration is not deployed runtime proof. |
| gtm-preview-recette | Produce a specific `SUPPORTING_ONLY` acceptance-rule handoff. | Do not open Preview automatically or absorb tracking-plan-led recette. |
| configure-gtm | Produce a proposed manual remediation outcome. | A finding is not configuration authority and never authorizes mutation. |
| governed-analytics-workflow | Expose instrumentation-reliability limits. | Do not estimate commercial or causal impact. |
| web-analyst-mcp-setup | Route missing browser, regional route, or account setup. | Do not install or reconfigure integrations inside this audit. |

## Owner routing

- Suspected GTM: GTM owner, optional separate Preview recette, then approved configuration, deployment, and independent browser rescan.
- Hardcoded/bundled or CMS/plugin: developer or CMS owner.
- Embed/iframe: component or vendor owner.
- CMP category/state/UX: CMP administrator.
- Declaration, exception, or applicability: DPO/legal owner.
- First-party proxy or suspected sGTM: future server-side audit owner.
- Unknown: analyst investigation naming the smallest missing evidence.

One primary owner does not erase contributing owners or dependencies.

## Deployment boundary

The relevant implementation must be deployed to the exact tested environment. A workspace save, preview-only change, screenshot, or client assertion is not deployment evidence. After remediation, the final confirmation is a clean browser rescan without Preview.
