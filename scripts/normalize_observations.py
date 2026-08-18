from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from consent_runtime_core import ContractError, assert_privacy_safe, iter_jsonl, read_json, sanitize_url, sha256_file, validate_schema, write_json, write_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate, minimize, de-duplicate, and deterministically order consent observations.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--update-run", type=Path)
    return parser.parse_args()


def normalize(row: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(row, ensure_ascii=False))
    value["page_url"] = sanitize_url(str(value["page_url"]))[0]
    initiator = value.get("observed_initiator")
    if isinstance(initiator, str) and initiator.startswith(("http://", "https://")):
        value["observed_initiator"] = sanitize_url(initiator)[0]
    data = value.get("data", {})
    for key in ("url", "destination_url"):
        if isinstance(data.get(key), str):
            data[key] = sanitize_url(data[key])[0]
    forbidden = {"headers", "request_headers", "response_headers", "body", "request_body", "response_body", "post_data", "raw_url", "raw_url_for_memory_only", "cookie_value", "storage_value"}
    present = sorted(forbidden & set(data))
    if present:
        raise ContractError(f"Observation {value.get('observation_id')} contains prohibited raw fields: {present}")
    validate_schema(value, "observation.schema.json", label=str(value.get("observation_id", "observation")))
    assert_privacy_safe(value, label=str(value.get("observation_id", "observation")))
    return value


def main() -> int:
    args = parse_args()
    try:
        by_id: dict[str, dict[str, Any]] = {}
        for row in iter_jsonl(args.input):
            item = normalize(row)
            observation_id = str(item["observation_id"])
            if observation_id in by_id and by_id[observation_id] != item:
                raise ContractError(f"Conflicting duplicate observation_id: {observation_id}")
            by_id[observation_id] = item
        rows = sorted(by_id.values(), key=lambda item: (item["scenario_id"], item["action_window"], item["surface"], item["page_url"], item["observation_id"]))
        write_jsonl(args.output, rows)
        if args.update_run:
            run = read_json(args.update_run)
            validate_schema(run, "audit-run.schema.json", label=str(args.update_run))
            if any(item["run_id"] != run["run_id"] for item in rows):
                raise ContractError("Normalized observation run identity does not match manifest")
            run["outputs"]["observations"] = {"path": args.output.name, "sha256": sha256_file(args.output)}
            write_json(args.update_run, run)
    except (ContractError, OSError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
