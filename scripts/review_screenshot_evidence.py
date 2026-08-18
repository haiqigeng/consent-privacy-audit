from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from consent_runtime_core import (
    ContractError,
    PrivacyError,
    assert_privacy_safe,
    privacy_findings,
    read_json,
    sha256_file,
    utc_now,
    validate_schema,
    write_json,
)
from scan_consent_runtime import load_restricted_canaries


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail-closed OCR and analyst gate for a cropped or masked screenshot.")
    parser.add_argument("image", type=Path)
    parser.add_argument("evidence_index", type=Path)
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--canary-file", type=Path)
    parser.add_argument("--update-run", type=Path)
    parser.add_argument("--cropped-or-masked", action="store_true")
    parser.add_argument("--analyst-approved", action="store_true")
    return parser.parse_args()


def extract_text(image: Path) -> str:
    try:
        import pytesseract
        from PIL import Image
    except ImportError as exc:
        raise ContractError("Screenshot review requires Pillow and pytesseract; no screenshot may be delivered without OCR") from exc
    try:
        with Image.open(image) as opened:
            return str(pytesseract.image_to_string(opened))
    except Exception as exc:
        raise ContractError(f"Screenshot OCR failed closed: {type(exc).__name__}: {exc}") from exc


def review_text(text: str, canary_values: list[str]) -> None:
    issues = privacy_findings(text, canaries=canary_values)
    if issues:
        raise PrivacyError(f"Screenshot OCR contains prohibited category marker(s): {', '.join(issues)}")


def main() -> int:
    args = parse_args()
    try:
        if not args.image.is_file():
            raise ContractError(f"Screenshot does not exist: {args.image}")
        if args.image.suffix.casefold() not in {".png", ".jpg", ".jpeg", ".webp"}:
            raise ContractError("Screenshot must be PNG, JPEG, or WebP")
        if not args.cropped_or_masked:
            raise ContractError("Screenshot must be cropped to a safe region or masked before review")
        if not args.analyst_approved:
            raise ContractError("An analyst visual pass is required after OCR")
        canaries = load_restricted_canaries(args.canary_file)
        extracted = extract_text(args.image)
        review_text(extracted, [item["value"] for item in canaries.values()])
        index = read_json(args.evidence_index)
        validate_schema(index, "evidence-index.schema.json", label=str(args.evidence_index))
        if any(item["evidence_id"] == args.evidence_id for item in index["artifacts"]):
            raise ContractError(f"Duplicate screenshot evidence ID: {args.evidence_id}")
        args.output_dir.mkdir(parents=True, exist_ok=True)
        destination = args.output_dir / f"{args.evidence_id}{args.image.suffix.casefold()}"
        if destination.exists():
            raise ContractError(f"Refusing to overwrite existing screenshot evidence: {destination}")
        shutil.copy2(args.image, destination)
        relative = destination.resolve().relative_to(args.evidence_index.parent.resolve()).as_posix()
        artifact = {
            "evidence_id": args.evidence_id,
            "kind": "SCREENSHOT",
            "path": relative,
            "sha256": sha256_file(destination),
            "restricted": False,
            "sanitization_status": "PASSED",
            "contains_canary_value": False,
            "contains_personal_data": False,
            "screenshot_review": {"cropped_or_masked": True, "ocr_status": "PASSED", "analyst_status": "PASSED"},
        }
        assert_privacy_safe(artifact, label=args.evidence_id)
        index["artifacts"].append(artifact)
        index["artifacts"] = sorted(index["artifacts"], key=lambda item: item["evidence_id"])
        index["generated_at"] = utc_now()
        validate_schema(index, "evidence-index.schema.json", label=str(args.evidence_index))
        write_json(args.evidence_index, index)
        if args.update_run:
            run = read_json(args.update_run)
            validate_schema(run, "audit-run.schema.json", label=str(args.update_run))
            if run["run_id"] != index["run_id"]:
                raise ContractError("Screenshot index and run identity mismatch")
            run["outputs"]["evidence_index"] = {"path": args.evidence_index.name, "sha256": sha256_file(args.evidence_index)}
            write_json(args.update_run, run)
    except (ContractError, PrivacyError, OSError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
