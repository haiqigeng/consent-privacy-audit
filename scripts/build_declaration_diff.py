from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from consent_runtime_core import (
    ContractError,
    assert_privacy_safe,
    iter_jsonl,
    normalize_label,
    read_json,
    registrable_domain,
    sha256_file,
    stable_id,
    utc_now,
    validate_schema,
    vendor_product_key,
    write_json,
)


TRACKING_PATH_RE = re.compile(r"/(?:collect|track|tracking|event|events|beacon|pixel|analytics)(?:/|$)", re.I)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare browser-observed products with supplied public tracker declarations.")
    parser.add_argument("run", type=Path)
    parser.add_argument("observations", type=Path)
    parser.add_argument("declarations", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    return parser.parse_args()


def observed_products(observations: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    products: dict[str, dict[str, Any]] = {}
    for row in observations:
        if row["surface"] not in {"NETWORK", "CANARY"}:
            continue
        purpose = str(row["purpose_candidate"])
        data = row.get("data", {})
        url = str(data.get("url") or data.get("destination_url") or "")
        request_domain = registrable_domain(urlsplit(url).hostname or "")
        page_domain = registrable_domain(urlsplit(str(row["page_url"])).hostname or "")
        external_unknown = bool(request_domain and page_domain and request_domain != page_domain) and str(data.get("resource_type")) in {"fetch", "xhr", "beacon", "ping", "image", "script"}
        known_tracker = purpose in {"ADVERTISING", "PERSONALIZATION", "ANALYTICS"}
        unknown_candidate = purpose == "UNKNOWN" and (
            row["suspected_implementation_layer"] in {"FIRST_PARTY_PROXY_OR_GATEWAY", "SERVICE_WORKER"}
            or bool(TRACKING_PATH_RE.search(url))
            or row["surface"] == "CANARY"
            or external_unknown
        )
        if not (known_tracker or unknown_candidate):
            continue
        key = vendor_product_key(row["vendor_product"], fallback_url=url)
        current = products.setdefault(
            key,
            {
                "vendor_product_key": key,
                "display_name": str(row["vendor_product"]["display_name"]),
                "confidence": str(row["vendor_product"]["confidence"]),
                "purposes": set(),
                "evidence_ids": set(),
            },
        )
        current["purposes"].add(purpose)
        current["evidence_ids"].add(str(row["evidence_id"]))
        if current["confidence"] == "UNKNOWN" and row["vendor_product"]["confidence"] != "UNKNOWN":
            current["confidence"] = row["vendor_product"]["confidence"]
    return products


def declaration_rows(value: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in value["sources"]:
        for item in source["items"]:
            key = None
            if item.get("vendor_id") and item.get("product_id"):
                key = f"{normalize_label(item['vendor_id']).replace(' ', '-')}:{normalize_label(item['product_id']).replace(' ', '-')}"
            names = {normalize_label(str(item["display_name"]))}
            names.update(normalize_label(str(alias)) for alias in item.get("aliases", []))
            rows.append({**item, "source_url": source["url"], "row_identity": f"{source['url']}#{item['declaration_id']}", "canonical_key": key, "normalized_names": {name for name in names if name}})
    return rows


def compare_purpose(observed: set[str], declared: list[dict[str, Any]]) -> tuple[str, bool]:
    declared_categories = {str(row["purpose_category"]) for row in declared if row.get("purpose_category") not in {None, "UNKNOWN"}}
    observed_categories = {item for item in observed if item != "UNKNOWN"}
    if not declared_categories or not observed_categories:
        return "Purpose not mechanically comparable from the supplied declaration wording and sampled requests.", False
    if observed_categories <= declared_categories:
        return f"Observed candidate category {', '.join(sorted(observed_categories))} is represented by the supplied declaration category.", False
    return f"Observed candidate category {', '.join(sorted(observed_categories))} is not fully represented by declared category {', '.join(sorted(declared_categories))}.", True


def render_wording(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "display_name": str(row["display_name"]),
            "purpose_text": row.get("purpose_text"),
            "category_text": row.get("category_text"),
            "duration_text": row.get("duration_text"),
        }
        for row in rows
    ]


def build(run: dict[str, Any], observations: list[dict[str, Any]], declarations: dict[str, Any]) -> dict[str, Any]:
    observed = observed_products(observations)
    declared = declaration_rows(declarations)
    used_declarations: set[str] = set()
    items: list[dict[str, Any]] = []
    for key, product in sorted(observed.items()):
        exact = [row for row in declared if row["canonical_key"] == key]
        if not exact:
            display_key = normalize_label(product["display_name"])
            exact = [row for row in declared if display_key and display_key in row["normalized_names"]]
        exact_keys = {row["canonical_key"] for row in exact}
        ambiguous = len(exact) > 1 and (None in exact_keys or len(exact_keys) > 1)
        for row in exact:
            used_declarations.add(str(row["row_identity"]))
        purpose_text, purpose_mismatch = compare_purpose(product["purposes"], exact) if exact else ("No supplied declaration row matched this observed product.", False)
        if ambiguous or product["confidence"] in {"UNKNOWN", "CONFLICTING"}:
            direction, status = "AMBIGUOUS", "INCONCLUSIVE"
        elif not exact:
            direction, status = "OBSERVED_UNDECLARED", "TECHNICAL_DECLARATION_MISMATCH"
        elif purpose_mismatch:
            direction, status = "BOTH", "TECHNICAL_DECLARATION_MISMATCH"
        else:
            direction, status = "BOTH", "MATCHED"
        source_urls = sorted({str(row["source_url"]) for row in exact})
        items.append(
            {
                "item_id": stable_id("DECL", run["run_id"], key),
                "vendor_product_key": key,
                "display_name": product["display_name"],
                "observed": True,
                "declared": bool(exact),
                "direction": direction,
                "status": status,
                "confidence": product["confidence"],
                "observed_evidence_ids": sorted(product["evidence_ids"]),
                "declaration_source": source_urls[0] if source_urls else None,
                "declaration_ids": sorted({str(row["declaration_id"]) for row in exact}),
                "declaration_wording": render_wording(exact),
                "purpose_comparison": purpose_text,
                "duration_comparison": "Runtime cookie lifetime metadata is not sufficient to verify the supplied declaration duration; no automatic duration conclusion is made." if exact else None,
                "legal_review_required": status in {"TECHNICAL_DECLARATION_MISMATCH", "INCONCLUSIVE"},
            }
        )
    for row in sorted(declared, key=lambda item: (str(item["declaration_id"]), str(item["source_url"]))):
        if str(row["row_identity"]) in used_declarations:
            continue
        key = row["canonical_key"] or f"declared:{normalize_label(str(row['display_name'])).replace(' ', '-')}"
        items.append(
            {
                "item_id": stable_id("DECL", run["run_id"], str(row["declaration_id"]), str(row["source_url"])),
                "vendor_product_key": key,
                "display_name": str(row["display_name"]),
                "observed": False,
                "declared": True,
                "direction": "DECLARED_UNOBSERVED",
                "status": "NOT_VERIFIED",
                "confidence": "CONFIRMED" if row["canonical_key"] else "PROBABLE",
                "observed_evidence_ids": [],
                "declaration_source": str(row["source_url"]),
                "declaration_ids": [str(row["declaration_id"])],
                "declaration_wording": render_wording([row]),
                "purpose_comparison": "Declared item was not activated in the bounded browser sample; absence is not a failure.",
                "duration_comparison": "Not verified because the product was not observed in the bounded sample.",
                "legal_review_required": False,
            }
        )
    result = {"schema_version": "1.0.0", "run_id": run["run_id"], "generated_at": utc_now(), "items": items}
    validate_schema(result, "declaration-diff.schema.json", label="declaration diff")
    assert_privacy_safe(result, label="declaration diff")
    return result


def main() -> int:
    args = parse_args()
    try:
        run = read_json(args.run)
        validate_schema(run, "audit-run.schema.json", label=str(args.run))
        observations = list(iter_jsonl(args.observations))
        for row in observations:
            validate_schema(row, "observation.schema.json", label=row["observation_id"])
        declarations = read_json(args.declarations)
        validate_schema(declarations, "declarations-input.schema.json", label=str(args.declarations))
        result = build(run, observations, declarations)
        write_json(args.output, result)
        run["outputs"]["declaration_diff"] = {"path": args.output.name, "sha256": sha256_file(args.output)}
        validate_schema(run, "audit-run.schema.json", label=str(args.run))
        write_json(args.run, run)
    except (ContractError, OSError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
