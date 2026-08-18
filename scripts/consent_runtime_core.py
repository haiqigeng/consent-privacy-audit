from __future__ import annotations

import hashlib
import html
import json
import os
import re
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
ADAPTER_DIR = ROOT / "references" / "cmp-adapters"
PROFILE_DIR = ROOT / "references" / "jurisdiction-profiles"
VENDOR_REGISTRY = ROOT / "references" / "vendor-signatures.json"

SCHEMA_VERSION = "1.0.0"
PRIORITY_RUBRIC_VERSION = "technical-priority-v1"
FINGERPRINT_ALGO_VERSION = "finding-fingerprint-jcs-sha256-v1"
SOURCE_FINGERPRINT_VERSION = "normalized-text-sha256-v1"
TEXT_NORMALIZATION_VERSION = "visible-text-nfc-whitespace-v1"
IDENTITY_NORMALIZATION_VERSION = "vendor-path-normalization-v1"
SCENARIO_CONTRACT_VERSION = "consent-scenarios-v1"

TECHNICAL_STATUSES = {
    "EXPECTED_BEHAVIOUR_OBSERVED",
    "UNEXPECTED_BEHAVIOUR_OBSERVED",
    "INCONCLUSIVE",
    "NOT_APPLICABLE",
    "NOT_TESTED",
}

SCENARIO_CLASSES = {
    "UNTOUCHED",
    "REJECTED",
    "ACCEPTED",
    "ACCEPTED_TO_WITHDRAWN",
    "PERSISTENCE_ACCEPTED",
    "PERSISTENCE_REJECTED",
    "GRANULAR_DENIED",
    "REJECTED_TO_ACCEPTED",
}

SAFE_QUERY_VALUE_FIELDS = {
    "dma",
    "dma_cps",
    "gcd",
    "gcs",
    "gdpr",
    "npa",
    "v",
    "en",
    "tid",
}

SENSITIVE_KEY_RE = re.compile(
    r"(^|[-_])(authorization|cookie|set[-_]?cookie|password|passwd|secret|token|"
    r"access[-_]?token|refresh[-_]?token|email|phone|mobile|first[-_]?name|"
    r"last[-_]?name|address|card|pan|cvv|session[-_]?id|client[-_]?id)($|[-_])",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])")
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
LONG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{24,}(?![A-Za-z0-9])")
PHONE_RE = re.compile(r"(?<![A-Za-z0-9])\+?(?:\d[ .()/-]*){10,15}(?![A-Za-z0-9])")


class ContractError(ValueError):
    pass


class PrivacyError(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"Could not read JSON {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=False)
            handle.write("\n")
        Path(name).replace(path)
    except Exception:
        try:
            Path(name).unlink(missing_ok=True)
        finally:
            raise


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, raw in enumerate(handle, start=1):
                if not raw.strip():
                    continue
                try:
                    value = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ContractError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
                if not isinstance(value, dict):
                    raise ContractError(f"Expected object at {path}:{line_number}")
                yield value
    except OSError as exc:
        raise ContractError(f"Could not read JSONL {path}: {exc}") from exc


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
                handle.write("\n")
        Path(name).replace(path)
    except Exception:
        try:
            Path(name).unlink(missing_ok=True)
        finally:
            raise


def validate_schema(value: Any, schema_name: str, *, label: str | None = None) -> None:
    schema_path = SCHEMA_DIR / schema_name
    schema = read_json(schema_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path))
    if not errors:
        return
    rendered: list[str] = []
    for error in errors[:50]:
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        rendered.append(f"{location}: {error.message}")
    prefix = label or schema_name
    if len(errors) > 50:
        rendered.append(f"... {len(errors) - 50} additional schema error(s)")
    raise ContractError(f"{prefix} failed schema validation:\n" + "\n".join(rendered))


def normalize_visible_text(value: str) -> str:
    normalized = unicodedata.normalize("NFC", html.unescape(value)).replace("\u00a0", " ")
    return re.sub(r"\s+", " ", normalized).strip()


def normalize_label(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value)
    asciiish = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    asciiish = asciiish.casefold().replace("’", "'")
    return re.sub(r"[^a-z0-9]+", " ", asciiish).strip()


def canonical_json_bytes(value: Any) -> bytes:
    # Fingerprint inputs are schema-constrained strings. For this domain that makes
    # sorted, compact UTF-8 JSON equivalent to the required JCS representation.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def finding_fingerprint(inputs: dict[str, str]) -> str:
    expected = {"rule_id", "finding_kind", "vendor_product_key", "scenario_class", "location_pattern"}
    if set(inputs) != expected or not all(isinstance(inputs[key], str) and inputs[key] for key in expected):
        raise ContractError(f"Fingerprint inputs must contain exactly non-empty {sorted(expected)}")
    return sha256_bytes(canonical_json_bytes(inputs))


def registrable_domain(host: str) -> str:
    host = host.lower().strip(".")
    if not host or host.replace(".", "").isdigit() or ":" in host:
        return host
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return host
    common_second_level = {"co", "com", "net", "org", "gov", "ac", "edu"}
    if len(labels[-1]) == 2 and labels[-2] in common_second_level and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def normalize_path_template(path: str) -> str:
    path = PHONE_RE.sub("{redacted}", UUID_RE.sub("{uuid}", path or "/"))
    segments: list[str] = []
    for segment in path.split("/"):
        if not segment:
            segments.append("")
            continue
        decoded = segment
        if re.fullmatch(r"(?:19|20)\d{2}[-_.]?\d{2}[-_.]?\d{2}(?:[T_.-]\d{2}[-_.:]?\d{2}(?:[-_.:]?\d{2})?)?", decoded):
            decoded = "{timestamp}"
        elif re.fullmatch(r"[a-zA-Z]{2}(?:[-_][a-zA-Z]{2,4})?", decoded) and decoded.casefold() in {
            "ar", "de", "en", "en-gb", "en-us", "es", "fr", "fr-fr", "it", "ja", "nl", "pl", "pt", "pt-br", "zh", "zh-cn"
        }:
            decoded = "{locale}"
        elif re.fullmatch(r"\d{4,}", decoded):
            decoded = "{id}"
        elif re.fullmatch(r"[0-9a-fA-F]{16,}", decoded):
            decoded = "{hash}"
        elif re.fullmatch(r"[A-Za-z0-9_-]{24,}", decoded):
            decoded = "{token}"
        segments.append(decoded)
    result = "/".join(segments)
    return result if result.startswith("/") else "/" + result


def _safe_query_value(name: str, value: str) -> str:
    if name.lower() not in SAFE_QUERY_VALUE_FIELDS:
        return "<redacted>"
    if EMAIL_RE.search(value) or BEARER_RE.search(value) or JWT_RE.search(value) or UUID_RE.search(value) or PHONE_RE.search(value):
        return "<redacted>"
    if len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9._,:+/-]*", value):
        return "<redacted>"
    return value


def sanitize_url(raw_url: str) -> tuple[str, list[str]]:
    parts = urlsplit(raw_url)
    host = (parts.hostname or "").lower()
    port = parts.port
    if port and not ((parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80)):
        host = f"{host}:{port}"
    query_items: list[tuple[str, str]] = []
    names: list[str] = []
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:128]
        names.append(safe_name)
        query_items.append((safe_name, _safe_query_value(safe_name, value)))
    path = normalize_path_template(parts.path or "/")
    safe_url = urlunsplit((parts.scheme.lower(), host, path, urlencode(query_items), ""))
    return safe_url, sorted(set(names))


def unknown_vendor_product_key(raw_url: str) -> str:
    parts = urlsplit(raw_url)
    return f"unknown:{registrable_domain(parts.hostname or '')}:{normalize_path_template(parts.path or '/')}"


def load_vendor_registry(path: Path = VENDOR_REGISTRY) -> dict[str, Any]:
    value = read_json(path)
    if not isinstance(value, dict) or not isinstance(value.get("products"), list):
        raise ContractError(f"Invalid vendor registry: {path}")
    return value


def classify_url(raw_url: str, registry: dict[str, Any] | None = None) -> dict[str, Any]:
    registry = registry or load_vendor_registry()
    parts = urlsplit(raw_url)
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    matches: list[dict[str, Any]] = []
    for product in registry.get("products", []):
        host_ok = any(re.search(pattern, host, flags=re.IGNORECASE) for pattern in product.get("host_patterns", []))
        path_ok = any(re.search(pattern, path, flags=re.IGNORECASE) for pattern in product.get("path_patterns", []))
        if host_ok and path_ok:
            matches.append(product)
    if len(matches) == 1:
        item = matches[0]
        return {
            "vendor_id": item["vendor_id"],
            "product_id": item["product_id"],
            "display_name": item["display_name"],
            "confidence": "CONFIRMED",
            "purpose_candidate": item["purpose_candidate"],
            "vendor_product_key": f"{item['vendor_id']}:{item['product_id']}",
        }
    if len(matches) > 1:
        names = " / ".join(sorted({str(item["display_name"]) for item in matches}))
        return {
            "vendor_id": None,
            "product_id": None,
            "display_name": names,
            "confidence": "CONFLICTING",
            "purpose_candidate": "UNKNOWN",
            "vendor_product_key": unknown_vendor_product_key(raw_url),
        }
    return {
        "vendor_id": None,
        "product_id": None,
        "display_name": host or "Unknown endpoint",
        "confidence": "UNKNOWN",
        "purpose_candidate": "UNKNOWN",
        "vendor_product_key": unknown_vendor_product_key(raw_url),
    }


def infer_implementation_layer(initiator: str | None, *, service_worker: bool = False, frame_url: str | None = None) -> str:
    text = " ".join(value for value in [initiator, frame_url] if value).lower()
    if service_worker:
        return "SERVICE_WORKER"
    if "googletagmanager.com/gtm.js" in text or "gtm-" in text:
        return "GTM_CONTAINER"
    if frame_url and initiator and urlsplit(frame_url).hostname and urlsplit(frame_url).hostname != urlsplit(initiator).hostname:
        return "EMBED_OR_IFRAME"
    if text:
        return "HARDCODED_OR_BUNDLED"
    return "UNKNOWN"


PRIORITY_INPUT_KEYS = {
    "sensitive_category",
    "unintended_collection",
    "reproduced",
    "direct_identifier_canary",
    "consent_state_contradiction",
    "scenario_class",
    "purpose_candidate",
    "stable_identifier",
    "systemic",
    "choice_withdrawal_persistence_failure",
    "unresolved_proxy_worker",
    "observed_undeclared",
    "required_state_inconclusive",
    "localized_defect",
    "optional_inconclusive",
    "expected",
    "not_applicable",
    "deliberately_not_tested",
    "declared_unobserved",
}


def technical_priority(inputs: dict[str, Any]) -> str:
    missing = sorted(PRIORITY_INPUT_KEYS - set(inputs))
    extra = sorted(set(inputs) - PRIORITY_INPUT_KEYS)
    if missing or extra:
        raise ContractError(f"Priority inputs invalid; missing={missing}, extra={extra}")
    sensitive = str(inputs["sensitive_category"])
    if inputs["unintended_collection"] and sensitive in {"CREDENTIAL", "AUTH_TOKEN", "PAYMENT", "SPECIAL_CATEGORY"}:
        return "URGENT"
    denied_state = inputs["scenario_class"] in {"REJECTED", "ACCEPTED_TO_WITHDRAWN", "GRANULAR_DENIED"}
    if inputs["reproduced"] and (
        (inputs["direct_identifier_canary"] and inputs["unintended_collection"])
        or (
            inputs["consent_state_contradiction"]
            and denied_state
            and (
                inputs["purpose_candidate"] in {"ADVERTISING", "PERSONALIZATION"}
                or inputs["stable_identifier"]
                or inputs["systemic"]
            )
        )
    ):
        return "HIGH"
    if (
        inputs["required_state_inconclusive"]
        or (
            inputs["reproduced"]
            and (
                (inputs["consent_state_contradiction"] and inputs["purpose_candidate"] in {"ANALYTICS", "UNKNOWN"})
                or inputs["choice_withdrawal_persistence_failure"]
                or inputs["unresolved_proxy_worker"]
                or inputs["observed_undeclared"]
            )
        )
    ):
        return "MEDIUM"
    if inputs["localized_defect"] or inputs["optional_inconclusive"]:
        return "LOW"
    if inputs["expected"] or inputs["not_applicable"] or inputs["deliberately_not_tested"] or inputs["declared_unobserved"]:
        return "INFORMATIONAL"
    raise ContractError("Priority inputs match no technical-priority-v1 row")


def default_priority_inputs() -> dict[str, Any]:
    return {
        "sensitive_category": "NONE",
        "unintended_collection": False,
        "reproduced": False,
        "direct_identifier_canary": False,
        "consent_state_contradiction": False,
        "scenario_class": "UNTOUCHED",
        "purpose_candidate": "UNKNOWN",
        "stable_identifier": False,
        "systemic": False,
        "choice_withdrawal_persistence_failure": False,
        "unresolved_proxy_worker": False,
        "observed_undeclared": False,
        "required_state_inconclusive": False,
        "localized_defect": False,
        "optional_inconclusive": False,
        "expected": False,
        "not_applicable": False,
        "deliberately_not_tested": False,
        "declared_unobserved": False,
    }


class VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript", "svg"}:
            self._skip_depth += 1
        elif not self._skip_depth:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript", "svg"} and self._skip_depth:
            self._skip_depth -= 1
        elif not self._skip_depth:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)

    def text(self) -> str:
        return normalize_visible_text(" ".join(self.parts))


def visible_text_from_html(raw_html: str) -> str:
    parser = VisibleTextParser()
    parser.feed(raw_html)
    return parser.text()


def extract_source_section(text: str, locator: dict[str, Any]) -> str:
    kind = locator.get("kind")
    text = normalize_visible_text(text)
    if kind == "FULL_DOCUMENT":
        return text
    if kind in {"LOCAL_BASELINE", "EXACT_TEXT_FRAGMENT", "VERSIONED_RESOURCE"}:
        marker = normalize_visible_text(str(locator.get("start_marker") or ""))
        if not marker:
            raise ContractError(f"{kind} requires start_marker")
        if kind == "LOCAL_BASELINE":
            return marker
        if marker not in text:
            raise ContractError("Source start marker not found")
        return marker
    if kind == "TEXT_BETWEEN":
        start_marker = normalize_visible_text(str(locator.get("start_marker") or ""))
        end_marker = normalize_visible_text(str(locator.get("end_marker") or ""))
        start = text.find(start_marker)
        end = text.find(end_marker, start + len(start_marker)) if start >= 0 else -1
        if start < 0 or end < 0 or end <= start:
            raise ContractError("Source section markers not found in order")
        return text[start:end].strip()
    raise ContractError(f"Unsupported source locator kind: {kind}")


@dataclass(frozen=True)
class CmpDetection:
    adapter_id: str | None
    provider: str | None
    confidence: str
    scores: dict[str, int]
    matched_kinds: dict[str, list[str]]


def load_adapters() -> list[dict[str, Any]]:
    adapters: list[dict[str, Any]] = []
    for path in sorted(ADAPTER_DIR.glob("*.json")):
        value = read_json(path)
        validate_schema(value, "cmp-adapter.schema.json", label=str(path))
        adapters.append(value)
    return adapters


def detect_cmp(snapshot: dict[str, list[str]], adapters: list[dict[str, Any]] | None = None) -> CmpDetection:
    adapters = adapters or load_adapters()
    kind_map = {
        "GLOBAL": "globals",
        "SCRIPT_HOST": "script_hosts",
        "SCRIPT_PATH": "script_paths",
        "COOKIE_NAME": "cookie_names",
        "STORAGE_KEY": "storage_keys",
        "DOM": "dom_markers",
        "EVENT": "events",
        "TCF_API": "globals",
    }
    scores: dict[str, int] = {}
    matched: dict[str, list[str]] = {}
    for adapter in adapters:
        adapter_id = str(adapter["adapter_id"])
        score = 0
        kinds: set[str] = set()
        signatures: list[str] = []
        if adapter_id == "generic-custom-banner":
            # This is a fallback, not a provider candidate.
            scores[adapter_id] = 0
            matched[adapter_id] = []
            continue
        for signature in adapter.get("detection_signatures", []):
            kind = str(signature["kind"])
            values = snapshot.get(kind_map[kind], [])
            if any(re.search(str(signature["pattern"]), str(value), flags=re.IGNORECASE) for value in values):
                score += int(signature["weight"])
                kinds.add(kind)
                signatures.append(f"{kind}:{signature['pattern']}")
        scores[adapter_id] = score
        matched[adapter_id] = sorted(signatures)
        adapter["_matched_kind_count"] = len(kinds)
    confirmed = [adapter for adapter in adapters if scores.get(adapter["adapter_id"], 0) >= 70 and adapter.get("_matched_kind_count", 0) >= 2]
    provider_confirmed = [adapter for adapter in confirmed if adapter["adapter_id"] != "generic-tcf-web"]
    if len(provider_confirmed) > 1:
        return CmpDetection(None, None, "CONFLICTING", scores, matched)
    if len(provider_confirmed) == 1:
        adapter = provider_confirmed[0]
        return CmpDetection(str(adapter["adapter_id"]), str(adapter["provider"]), "CONFIRMED", scores, matched)
    if len(confirmed) == 1:
        adapter = confirmed[0]
        return CmpDetection(str(adapter["adapter_id"]), str(adapter["provider"]), "CONFIRMED", scores, matched)
    candidates = [adapter for adapter in adapters if scores.get(adapter["adapter_id"], 0) >= 40]
    if candidates:
        provider_candidates = [adapter for adapter in candidates if adapter["adapter_id"] != "generic-tcf-web"]
        adapter = max(provider_candidates or candidates, key=lambda item: scores[str(item["adapter_id"])])
        return CmpDetection(str(adapter["adapter_id"]), str(adapter["provider"]), "PROBABLE", scores, matched)
    return CmpDetection("generic-custom-banner", "Unknown or custom consent interface", "UNKNOWN", scores, matched)


def deep_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from deep_strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from deep_strings(item)


def privacy_findings(text: str, *, canaries: Iterable[str] = ()) -> list[str]:
    issues: list[str] = []
    for value in canaries:
        if value and value in text:
            issues.append("CANARY_VALUE")
            break
    if BEARER_RE.search(text):
        issues.append("BEARER_TOKEN")
    if JWT_RE.search(text):
        issues.append("JWT")
    if EMAIL_RE.search(text):
        issues.append("EMAIL")
    phone_found = False
    for match in PHONE_RE.finditer(text):
        candidate = match.group(0).strip()
        digits_only = candidate.isdigit()
        expiry_prefix = text[max(0, match.start() - 80):match.start()].replace('\\"', '"').replace("\\'", "'")
        is_expiry_metadata = bool(
            re.search(
                r'"(?:expires|expiry|expiration|expires_at|expiresAt)"\s*:\s*["\']?$',
                expiry_prefix,
                re.IGNORECASE,
            )
        )
        if digits_only and is_expiry_metadata:
            continue
        if "." in candidate and not re.search(r"[ +()/-]", candidate):
            parts = candidate.split(".")
            if not (len(parts) == 5 and all(len(part) == 2 for part in parts)):
                continue
        phone_found = True
        break
    if phone_found:
        issues.append("PHONE")
    return sorted(set(issues))


def assert_privacy_safe(value: Any, *, canaries: Iterable[str] = (), label: str = "artifact") -> None:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
    issues = privacy_findings(serialized, canaries=canaries)
    if issues:
        raise PrivacyError(f"{label} contains prohibited pattern(s): {', '.join(issues)}")
    prohibited_payload_keys = {
        "authorization", "cookie_header", "set_cookie", "request_body", "response_body",
        "post_data", "raw_url", "raw_url_for_memory_only", "cookie_value", "storage_value",
        "canary_value", "password_value", "token_value", "restricted_authorization",
    }
    def walk_keys(item: Any, path: str = "$") -> None:
        if isinstance(item, dict):
            for raw_key, nested in item.items():
                key = normalize_label(str(raw_key)).replace(" ", "_")
                if key in prohibited_payload_keys:
                    raise PrivacyError(f"{label} contains prohibited payload field at {path}.{raw_key}")
                walk_keys(nested, f"{path}.{raw_key}")
        elif isinstance(item, list):
            for index, nested in enumerate(item):
                walk_keys(nested, f"{path}[{index}]")
    walk_keys(value)


def vendor_product_key(vendor: dict[str, Any], *, fallback_url: str | None = None) -> str:
    vendor_id = vendor.get("vendor_id")
    product_id = vendor.get("product_id")
    if vendor_id and product_id:
        return f"{normalize_label(str(vendor_id)).replace(' ', '-')}:{normalize_label(str(product_id)).replace(' ', '-')}"
    if fallback_url:
        return unknown_vendor_product_key(fallback_url)
    display = normalize_label(str(vendor.get("display_name") or "unknown")).replace(" ", "-")
    return f"unknown:{display or 'unknown'}:/"


def stable_id(prefix: str, *parts: str, length: int = 16) -> str:
    payload = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}-{sha256_bytes(payload)[:length]}"


def normalized_location_pattern(page_url: str, interaction_id: str = "page") -> str:
    parts = urlsplit(page_url)
    origin = f"{parts.scheme.lower()}://{(parts.hostname or '').lower()}"
    if parts.port and not ((parts.scheme == "https" and parts.port == 443) or (parts.scheme == "http" and parts.port == 80)):
        origin += f":{parts.port}"
    return f"{origin}{normalize_path_template(parts.path or '/')}#{normalize_label(interaction_id) or 'page'}"


def load_profile(path_or_id: str | Path) -> dict[str, Any]:
    candidate = Path(path_or_id)
    if not candidate.exists():
        candidate = PROFILE_DIR / f"{path_or_id}.json"
    value = read_json(candidate)
    validate_schema(value, "rule-profile.schema.json", label=str(candidate))
    return value


def source_rule_index(profile: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {str(source["source_id"]): [] for source in profile.get("sources", [])}
    for rule in profile.get("rules", []):
        for source_id in rule.get("source_ids", []):
            result.setdefault(str(source_id), []).append(str(rule["rule_id"]))
    return {key: sorted(set(value)) for key, value in result.items()}


def path_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
