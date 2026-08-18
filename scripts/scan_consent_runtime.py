from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from consent_runtime_core import (
    ContractError,
    classify_url,
    detect_cmp,
    infer_implementation_layer,
    load_adapters,
    normalize_label,
    read_json,
    sanitize_url,
    stable_id,
    utc_now,
    validate_schema,
    write_json,
    write_jsonl,
)

REQUIRED_CORE_SCENARIO_IDS = frozenset(
    {"SCN-UNTOUCHED", "SCN-REJECTED", "SCN-ACCEPTED", "SCN-WITHDRAWAL", "SCN-PERSIST-ACCEPTED", "SCN-PERSIST-REJECTED"}
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture minimized consent runtime observations with Playwright Chromium.")
    parser.add_argument("run", type=Path, help="Initialized audit-run.json")
    parser.add_argument("--output", "-o", type=Path, required=True, help="observations.jsonl")
    parser.add_argument("--interaction-plan", type=Path)
    parser.add_argument("--canary-file", type=Path, help="Restricted JSON object mapping canary IDs to values")
    parser.add_argument("--adapter", help="Force a validated adapter ID after detection evidence is recorded")
    parser.add_argument("--quiet-ms", type=int, default=1800)
    parser.add_argument("--timeout-ms", type=int, default=12000)
    parser.add_argument("--later-ms", type=int, default=2500, help="Fixed post-choice horizon kept separate from the immediate quiet window")
    parser.add_argument("--screenshot-staging", type=Path)
    return parser.parse_args()


def incomplete_required_scenarios(scenarios: list[dict[str, Any]]) -> list[str]:
    return sorted(
        str(item["scenario_id"])
        for item in scenarios
        if item.get("scenario_id") in REQUIRED_CORE_SCENARIO_IDS and item.get("status") != "COMPLETE"
    )


def safe_get(obj: Any, name: str, default: Any = None) -> Any:
    try:
        value = getattr(obj, name)
        return value() if callable(value) and name in {"all_headers"} else value
    except Exception:
        return default


def detect_canary_path(raw_url: str, post_data: str | None, headers: dict[str, str], canaries: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    query = parse_qsl(urlsplit(raw_url).query, keep_blank_values=True)
    for canary_id, spec in canaries.items():
        canary = spec["value"]
        if not canary:
            continue
        for name, value in query:
            if canary in value:
                hits.append({"canary_id": canary_id, "safe_parameter_path": f"query.{name}", "category": spec["category"]})
        decoded_path = unquote(urlsplit(raw_url).path)
        if canary in decoded_path:
            hits.append({"canary_id": canary_id, "safe_parameter_path": "path.<segment>", "category": spec["category"]})
        for name, value in headers.items():
            if canary in str(value):
                safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", str(name))[:128]
                hits.append({"canary_id": canary_id, "safe_parameter_path": f"header.{safe_name}", "category": spec["category"]})
        if post_data and canary in post_data:
            path = "body.<unknown>"
            try:
                parsed = json.loads(post_data)

                def walk(value: Any, prefix: str) -> str | None:
                    if isinstance(value, dict):
                        for key, item in value.items():
                            found = walk(item, f"{prefix}.{key}" if prefix else str(key))
                            if found:
                                return found
                    elif isinstance(value, list):
                        for index, item in enumerate(value):
                            found = walk(item, f"{prefix}[{index}]")
                            if found:
                                return found
                    elif canary in str(value):
                        return prefix
                    return None

                path = f"body.{walk(parsed, '') or '<unknown>'}"
            except (json.JSONDecodeError, TypeError):
                for name, value in parse_qsl(post_data, keep_blank_values=True):
                    if canary in value:
                        path = f"body.{name}"
                        break
            hits.append({"canary_id": canary_id, "safe_parameter_path": path, "category": spec["category"]})
    unique = {(item["canary_id"], item["safe_parameter_path"], item["category"]): item for item in hits}
    return list(unique.values())


class NetworkRecorder:
    def __init__(self, *, canaries: dict[str, dict[str, str]]) -> None:
        self.canaries = canaries
        self.records: list[dict[str, Any]] = []
        self.by_request: dict[int, dict[str, Any]] = {}
        self.last_activity = time.monotonic()
        self.worker_urls: set[str] = set()
        self.websocket_urls: set[str] = set()
        self.cdp_events: dict[tuple[str, str], list[dict[str, str | None]]] = defaultdict(list)
        self.request_occurrences: dict[tuple[str, str], int] = defaultdict(int)

    def attach(self, context: Any, cdp_session: Any) -> None:
        context.on("request", self.on_request)
        context.on("response", self.on_response)
        context.on("requestfailed", self.on_failed)
        context.on("serviceworker", self.on_service_worker)
        context.on("websocket", self.on_websocket)
        cdp_session.on("Network.requestWillBeSent", self.on_cdp_request)
        cdp_session.send("Network.enable")

    def on_cdp_request(self, event: dict[str, Any]) -> None:
        request = event.get("request") or {}
        raw_url = str(request.get("url") or "")
        method = str(request.get("method") or "GET")
        if not raw_url:
            return
        self.cdp_events[(method, raw_url)].append(extract_cdp_initiator(event.get("initiator") or {}, str(event.get("documentURL") or "")))

    def on_request(self, request: Any) -> None:
        self.last_activity = time.monotonic()
        raw_url = str(request.url)
        request_key = (str(request.method), raw_url)
        cdp_match_index = self.request_occurrences[request_key]
        self.request_occurrences[request_key] += 1
        safe_url, query_names = sanitize_url(raw_url)
        frame_url: str | None = None
        try:
            frame_url = request.frame.url
        except Exception:
            frame_url = None
        post_data: str | None = None
        try:
            post_data = request.post_data
        except Exception:
            post_data = None
        try:
            headers = {str(name): str(value) for name, value in request.headers.items()}
        except Exception:
            headers = {}
        service_worker = False
        try:
            service_worker = bool(getattr(request, "service_worker", None))
        except Exception:
            pass
        record = {
            "request_key": id(request),
            "cdp_match_key": request_key,
            "cdp_match_index": cdp_match_index,
            "observed_at": utc_now(),
            "method": str(request.method),
            "safe_url": safe_url,
            "raw_url_for_memory_only": raw_url,
            "query_parameter_names": query_names,
            "resource_type": str(request.resource_type),
            "frame_url": frame_url,
            "service_worker": service_worker,
            "status": None,
            "failure": None,
            "canary_hits": detect_canary_path(raw_url, post_data, headers, self.canaries),
        }
        self.records.append(record)
        self.by_request[id(request)] = record

    def on_response(self, response: Any) -> None:
        self.last_activity = time.monotonic()
        record = self.by_request.get(id(response.request))
        if record is not None:
            record["status"] = int(response.status)

    def on_failed(self, request: Any) -> None:
        self.last_activity = time.monotonic()
        record = self.by_request.get(id(request))
        if record is not None:
            failure = safe_get(request, "failure", None)
            record["failure"] = str(failure)[:500] if failure else "request_failed"

    def on_service_worker(self, worker: Any) -> None:
        self.last_activity = time.monotonic()
        self.worker_urls.add(str(worker.url))

    def on_websocket(self, websocket: Any) -> None:
        self.last_activity = time.monotonic()
        self.websocket_urls.add(str(websocket.url))

    def cursor(self) -> int:
        return len(self.records)

    def wait_quiet(self, page: Any, *, quiet_ms: int, timeout_ms: int) -> tuple[bool, int]:
        started = time.monotonic()
        while (time.monotonic() - started) * 1000 < timeout_ms:
            quiet_for = (time.monotonic() - self.last_activity) * 1000
            if quiet_for >= quiet_ms:
                return True, int((time.monotonic() - started) * 1000)
            page.wait_for_timeout(min(150, max(50, quiet_ms // 8)))
        return False, int((time.monotonic() - started) * 1000)

    def slice(self, start: int) -> list[dict[str, Any]]:
        rows = self.records[start:]
        for record in rows:
            events = self.cdp_events.get(record["cdp_match_key"], [])
            index = int(record["cdp_match_index"])
            record["initiator"] = events[index] if index < len(events) else {"type": None, "url": None}
        return rows


def extract_cdp_initiator(initiator: dict[str, Any], document_url: str) -> dict[str, str | None]:
    initiator_type = str(initiator.get("type") or "unknown")
    urls: list[str] = []
    stack = initiator.get("stack")
    while isinstance(stack, dict):
        for frame in stack.get("callFrames") or []:
            if isinstance(frame, dict) and frame.get("url"):
                urls.append(str(frame["url"]))
        stack = stack.get("parent")
    if initiator.get("url"):
        urls.append(str(initiator["url"]))
    if document_url:
        urls.append(document_url)
    selected = next((url for url in urls if "googletagmanager.com/gtm.js" in url.lower()), urls[0] if urls else None)
    safe_url = sanitize_url(selected)[0] if selected and selected.startswith(("http://", "https://")) else None
    return {"type": initiator_type[:100], "url": safe_url}


def load_restricted_canaries(path: Path | None) -> dict[str, dict[str, str]]:
    if not path:
        return {}
    value = read_json(path)
    if not isinstance(value, dict) or not value:
        raise ContractError("Canary file must be a non-empty JSON object")
    result: dict[str, dict[str, str]] = {}
    for key, item in value.items():
        if isinstance(item, str):
            text = item
            category = "DIRECT_IDENTIFIER"
        elif isinstance(item, dict):
            text = item.get("value")
            category = str(item.get("category", "DIRECT_IDENTIFIER"))
        else:
            text = None
            category = "DIRECT_IDENTIFIER"
        if not isinstance(text, str) or len(text) < 6:
            raise ContractError(f"Canary {key} must be a distinctive string of at least six characters")
        if category not in {"DIRECT_IDENTIFIER", "CREDENTIAL", "AUTH_TOKEN", "PAYMENT", "SPECIAL_CATEGORY", "OTHER"}:
            raise ContractError(f"Canary {key} has unsupported category {category}")
        if not ("example" in text.lower() or "test" in text.lower() or "synthetic" in text.lower()):
            raise ContractError(f"Canary {key} must be obviously synthetic (include example, test, or synthetic)")
        result[str(key)] = {"value": text, "category": category}
    return result


def load_interaction_plan(path: Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    value = read_json(path)
    validate_schema(value, "interaction-plan.schema.json", label=str(path))
    return value


def browser_snapshot(page: Any, context: Any) -> dict[str, list[str]]:
    globals_found = page.evaluate(
        """() => ['axeptioSDK','_axcb','Didomi','didomiOnReady','OneTrust','OnetrustActiveGroups','__tcfapi']
          .filter(name => typeof window[name] !== 'undefined')"""
    )
    script_urls = page.locator("script[src]").evaluate_all("els => els.map(el => el.src).filter(Boolean)")
    cookies = context.cookies()
    storage = page.evaluate("() => ({local:Object.keys(localStorage), session:Object.keys(sessionStorage)})")
    dom_markers = page.evaluate(
        """() => {
          const out=[];
          if (document.querySelector('iframe[name="__tcfapiLocator"]')) out.push('iframe[name=__tcfapiLocator]');
          if (document.querySelector('[role="dialog"]')) out.push('[role=dialog]');
          if (document.querySelector('dialog')) out.push('dialog');
          if (document.querySelector('[aria-modal="true"]')) out.push('[aria-modal=true]');
          return out;
        }"""
    )
    hosts = sorted({(urlsplit(str(url)).hostname or "").lower() for url in script_urls if url})
    paths = sorted({urlsplit(str(url)).path for url in script_urls if url})
    return {
        "globals": [str(item) for item in globals_found],
        "script_hosts": hosts,
        "script_paths": paths,
        "cookie_names": sorted({str(item.get("name")) for item in cookies}),
        "storage_keys": sorted(set(storage.get("local", []) + storage.get("session", []))),
        "dom_markers": [str(item) for item in dom_markers],
        "events": [],
    }


def read_tcf_state(page: Any) -> dict[str, Any]:
    return page.evaluate(
        """() => new Promise(resolve => {
          if (typeof window.__tcfapi !== 'function') return resolve({ready:false});
          let done=false;
          const finish=value => { if (!done) { done=true; resolve(value); } };
          const timer=setTimeout(() => finish({ready:false, timeout:true}), 2500);
          try {
            window.__tcfapi('addEventListener', 2, (data, success) => {
              if (!success || !data) return;
              const enabled = obj => Object.keys(obj || {}).filter(k => obj[k] === true).sort();
              const result={
                ready:data.cmpStatus === 'loaded',
                cmpStatus:data.cmpStatus || null,
                eventStatus:data.eventStatus || null,
                gdprApplies:typeof data.gdprApplies === 'boolean' ? data.gdprApplies : null,
                tcfPolicyVersion:Number.isInteger(data.tcfPolicyVersion) ? data.tcfPolicyVersion : null,
                cmpId:Number.isInteger(data.cmpId) ? data.cmpId : null,
                purpose_consents:enabled(data.purpose && data.purpose.consents),
                vendor_consents:enabled(data.vendor && data.vendor.consents),
                tc_string_present:typeof data.tcString === 'string' && data.tcString.length > 0
              };
              clearTimeout(timer); finish(result);
            });
          } catch (e) { clearTimeout(timer); finish({ready:false, error_type:e && e.name || 'Error'}); }
        })"""
    )


def read_cmp_state(page: Any, adapter: dict[str, Any]) -> dict[str, Any]:
    reader = adapter["state_reader"]
    if reader["kind"] == "TCF_API":
        return read_tcf_state(page)
    if reader["kind"] == "JAVASCRIPT_EXPRESSION" and reader.get("expression"):
        try:
            result = page.evaluate(reader["expression"])
            return result if isinstance(result, dict) else {"ready": False}
        except Exception as exc:
            return {"ready": False, "error_type": type(exc).__name__}
    return page.evaluate(
        """() => {
          const dialog = Array.from(document.querySelectorAll('[role=dialog],dialog,[aria-modal=true]'))
            .find(el => /cookie|consent|privacy|traceur/i.test(el.innerText || ''));
          const marker = document.documentElement.getAttribute('data-consent-state')
            || document.body && document.body.getAttribute('data-consent-state')
            || document.querySelector('[data-consent-state]') && document.querySelector('[data-consent-state]').getAttribute('data-consent-state');
          const normalized = String(marker || '').trim().toUpperCase();
          const known = ['UNTOUCHED','ACCEPTED','REJECTED','WITHDRAWN'].includes(normalized);
          return {ready: !!dialog || known, state: known ? normalized : (dialog ? 'UNTOUCHED' : null), banner_visible: !!dialog, verification:'browser_differential_required'};
        }"""
    )


def state_matches_action(state: dict[str, Any], action: str, *, baseline_state: dict[str, Any] | None = None) -> bool:
    if not state.get("ready"):
        return False
    marker = str(state.get("state") or "").upper()
    if marker:
        expected = {
            "accept": {"ACCEPTED"},
            "reject": {"REJECTED"},
            "withdraw": {"REJECTED", "WITHDRAWN"},
            "reopen": {"ACCEPTED", "REJECTED", "WITHDRAWN"},
            "untouched": {"UNTOUCHED"},
        }
        return marker in expected.get(action, {marker})
    current_groups = {str(value) for value in state.get("active_groups", [])} if isinstance(state.get("active_groups"), list) else None
    baseline_groups = {str(value) for value in (baseline_state or {}).get("active_groups", [])} if isinstance((baseline_state or {}).get("active_groups"), list) else None
    if current_groups is not None and baseline_groups is not None:
        banner_closed = state.get("banner_visible") is False
        if action in {"reject", "withdraw"}:
            return current_groups == baseline_groups and banner_closed
        if action == "accept":
            return banner_closed or current_groups != baseline_groups
    boolean_sets: list[list[bool]] = []
    choices = state.get("choices")
    if isinstance(choices, dict):
        boolean_sets.append([bool(value) for value in choices.values() if isinstance(value, bool)])
    for key in ("purposes", "vendors", "active_groups", "purpose_consents", "vendor_consents"):
        value = state.get(key)
        if isinstance(value, list):
            boolean_sets.append([True] * len(value))
    flattened = [value for group in boolean_sets for value in group]
    if action == "accept":
        return bool(flattened) and any(flattened)
    if action in {"reject", "withdraw"}:
        return bool(boolean_sets) and not any(flattened)
    return True


def capture_consent_signals(page: Any) -> list[dict[str, Any]]:
    return page.evaluate(
        """() => {
          const safe=[];
          for (const item of (window.dataLayer || [])) {
            let a=[];
            try { a=Array.from(item); } catch (_) {}
            if (a[0] === 'consent' && (a[1] === 'default' || a[1] === 'update') && a[2] && typeof a[2] === 'object') {
              const values={};
              for (const key of ['ad_storage','analytics_storage','ad_user_data','ad_personalization','functionality_storage','personalization_storage','security_storage']) {
                if (a[2][key] === 'granted' || a[2][key] === 'denied') values[key]=a[2][key];
              }
              safe.push({command:'consent', phase:a[1], values});
            }
          }
          return safe;
        }"""
    )


def adapter_by_id(adapters: list[dict[str, Any]], adapter_id: str) -> dict[str, Any]:
    for adapter in adapters:
        if adapter["adapter_id"] == adapter_id:
            return adapter
    raise ContractError(f"Unknown adapter ID: {adapter_id}")


def matching_controls(page: Any, control: dict[str, Any]) -> list[tuple[Any, str]]:
    patterns = [re.compile(pattern, re.IGNORECASE) for pattern in control.get("label_patterns", [])]
    matches: list[tuple[Any, str]] = []
    for role in control.get("roles", []):
        locator = page.get_by_role(role)
        count = min(locator.count(), 100)
        for index in range(count):
            item = locator.nth(index)
            try:
                if not item.is_visible():
                    continue
                label = item.get_attribute("aria-label") or item.inner_text(timeout=500)
                normalized = normalize_label(label)
                if any(pattern.search(normalized) for pattern in patterns):
                    matches.append((item, label))
            except Exception:
                continue
    return matches


def find_control(page: Any, adapter: dict[str, Any], action: str) -> tuple[Any | None, str]:
    control = adapter["semantic_controls"][action]
    semantic = matching_controls(page, control)
    if len(semantic) == 1:
        return semantic[0][0], f"semantic:{semantic[0][1]}"
    if len(semantic) > 1:
        exact = [item for item in semantic if normalize_label(item[1]) in {"accept all", "reject all", "tout accepter", "tout refuser", "save choices", "confirmer mes choix"}]
        if len(exact) == 1:
            return exact[0][0], f"semantic-exact:{exact[0][1]}"
        # A provider selector can be more specific than duplicated semantic
        # labels (for example OneTrust's preference-center reject button).
        # Continue to selector fallback before declaring the control ambiguous.
    for selector in control.get("provider_selectors", []):
        selector_matches: list[Any] = []
        try:
            locator = page.locator(selector)
            for index in range(min(locator.count(), 20)):
                item = locator.nth(index)
                if item.is_visible():
                    selector_matches.append(item)
        except Exception:
            continue
        if len(selector_matches) == 1:
            return selector_matches[0], "provider-selector"
        if len(selector_matches) > 1:
            return None, "ambiguous provider selectors"
    return None, "control not found"


def stage_cmp_screenshot(page: Any, adapter: dict[str, Any], action: str, staging: Path | None, scenario_id: str) -> str | None:
    if not staging:
        return None
    locator, _ = find_control(page, adapter, action)
    if locator is None:
        return None
    try:
        container = locator.locator("xpath=ancestor-or-self::*[@role='dialog' or self::dialog or @aria-modal='true'][1]")
        target = container if container.count() == 1 else locator
        path = staging / f"{scenario_id}-{action}.png"
        path.parent.mkdir(parents=True, exist_ok=True)
        target.screenshot(path=str(path))
        return str(path)
    except Exception:
        return None


def click_control(page: Any, adapter: dict[str, Any], action: str) -> tuple[bool, str]:
    locator, method = find_control(page, adapter, action)
    if locator is None:
        return False, method
    try:
        locator.click(timeout=5000)
        return True, method
    except Exception as exc:
        return False, f"{method} click failed: {type(exc).__name__}"


def click_reopen_with_public_fallback(
    *, page: Any, run: dict[str, Any], adapter: dict[str, Any], recorder: NetworkRecorder,
    quiet_ms: int, timeout_ms: int,
) -> tuple[bool, str]:
    """Retry a missing persistent control on declared public privacy surfaces.

    A CMP preference control may be intentionally absent from the landing page but
    available on the linked cookie policy. This remains a browser/UI interaction:
    no provider API or undocumented storage mutation is used.
    """
    ok, method = click_control(page, adapter, "reopen")
    if ok:
        return True, method
    attempted: list[str] = []
    for raw_url in run.get("scope", {}).get("declaration_urls", []):
        safe_url, _ = sanitize_url(str(raw_url))
        if not safe_url or safe_url in attempted:
            continue
        attempted.append(safe_url)
        try:
            page.goto(str(raw_url), wait_until="domcontentloaded", timeout=timeout_ms)
            recorder.wait_quiet(page, quiet_ms=quiet_ms, timeout_ms=timeout_ms)
            reopened, reopen_method = click_control(page, adapter, "reopen")
            if reopened:
                return True, f"public-declaration:{safe_url}:{reopen_method}"
        except Exception:
            continue
    suffix = ",".join(attempted) if attempted else "none"
    return False, f"{method}; public-declaration-fallback-exhausted:{suffix}"


def wait_for_cmp_ui_settle(page: Any, action: str, timeout_ms: int) -> None:
    if action not in {"accept", "reject", "withdraw"}:
        return
    try:
        page.wait_for_function(
            """action => {
              const visible = selector => Array.from(document.querySelectorAll(selector)).some(el => {
                const style = window.getComputedStyle(el);
                return style.display !== 'none' && style.visibility !== 'hidden' && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
              });
              if (action === 'withdraw') return !visible('#onetrust-banner-sdk,#onetrust-pc-sdk');
              return !visible('#onetrust-banner-sdk');
            }""",
            arg=action,
            timeout=min(timeout_ms, 5000),
        )
    except Exception:
        # The state reader remains authoritative; this bounded wait only gives
        # slow CMP templates a chance to settle before the state is evaluated.
        return


def storage_metadata(page: Any, context: Any) -> dict[str, Any]:
    cookies = []
    for item in context.cookies():
        cookies.append(
            {
                "name": item.get("name"),
                "domain": item.get("domain"),
                "path": item.get("path"),
                "expires": item.get("expires"),
                "http_only": item.get("httpOnly"),
                "secure": item.get("secure"),
                "same_site": item.get("sameSite"),
                "partition_key_present": bool(item.get("partitionKey")),
            }
        )
    web_storage = page.evaluate("() => ({local_storage_keys:Object.keys(localStorage).sort(), session_storage_keys:Object.keys(sessionStorage).sort()})")
    try:
        indexed = page.evaluate(
            """() => indexedDB.databases ? indexedDB.databases().then(rows => rows.map(row => ({name:row.name || null, version:row.version || null}))) : []"""
        )
    except Exception:
        indexed = []
    return {"cookies": cookies, **web_storage, "indexed_db": indexed}


def script_embed_metadata(page: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    script_urls = page.locator("script[src]").evaluate_all("els => els.map(el => el.src).filter(Boolean)")
    frame_urls = page.frames
    scripts: list[dict[str, Any]] = []
    for raw_url in script_urls:
        safe_url, _ = sanitize_url(str(raw_url))
        vendor = classify_url(str(raw_url))
        scripts.append({"url": safe_url, "vendor_product_key": vendor["vendor_product_key"], "purpose_candidate": vendor["purpose_candidate"]})
    embeds: list[dict[str, Any]] = []
    for frame in frame_urls:
        raw_url = str(frame.url or "")
        if not raw_url or raw_url == page.url or raw_url == "about:blank":
            continue
        safe_url, _ = sanitize_url(raw_url)
        embeds.append({"url": safe_url})
    unique_scripts = {json.dumps(item, sort_keys=True): item for item in scripts}
    unique_embeds = {json.dumps(item, sort_keys=True): item for item in embeds}
    return list(unique_scripts.values()), list(unique_embeds.values())


def make_observation(
    *, run: dict[str, Any], scenario: dict[str, Any], action_window: str, page_url: str,
    surface: str, data: dict[str, Any], vendor: dict[str, Any] | None = None,
    initiator: str | None = None, layer: str = "UNKNOWN", status: str = "INCONCLUSIVE",
) -> dict[str, Any]:
    safe_page_url, _ = sanitize_url(page_url)
    safe_initiator = sanitize_url(initiator)[0] if initiator and initiator.startswith(("http://", "https://")) else initiator
    seed = json.dumps([scenario["scenario_id"], action_window, surface, safe_page_url, data], ensure_ascii=False, sort_keys=True)
    observation_id = stable_id("OBS", run["run_id"], seed)
    evidence_id = stable_id("EVD", run["run_id"], observation_id)
    applicability = run["rule_profiles"][0]["applicability"] if run["rule_profiles"] else "UNKNOWN"
    vendor = vendor or {"vendor_id": None, "product_id": None, "display_name": run["cmp"].get("provider") or "Unknown", "confidence": run["cmp"].get("detection_confidence", "UNKNOWN")}
    return {
        "schema_version": "1.0.0",
        "observation_id": observation_id,
        "run_id": run["run_id"],
        "scenario_id": scenario["scenario_id"],
        "scenario_class": scenario["scenario_class"],
        "action_window": action_window,
        "observed_at": utc_now(),
        "page_url": safe_page_url,
        "surface": surface,
        "fact_class": "BROWSER_OBSERVED",
        "technical_test_status": status,
        "rule_applicability": applicability,
        "vendor_product": {key: vendor[key] for key in ["vendor_id", "product_id", "display_name", "confidence"]},
        "purpose_candidate": vendor.get("purpose_candidate", "UNKNOWN"),
        "observed_initiator": safe_initiator,
        "suspected_implementation_layer": layer,
        "data": data,
        "evidence_id": evidence_id,
    }


def network_observations(run: dict[str, Any], scenario: dict[str, Any], records: list[dict[str, Any]], action_window: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for occurrence_index, record in enumerate(records, start=1):
        vendor = classify_url(record["raw_url_for_memory_only"])
        initiator = record.get("initiator") or {}
        initiator_url = initiator.get("url")
        layer = infer_implementation_layer(initiator_url, service_worker=bool(record.get("service_worker")), frame_url=record.get("frame_url"))
        request_host = urlsplit(record["raw_url_for_memory_only"]).hostname or ""
        site_host = urlsplit(run["site"]["origin"]).hostname or ""
        frame_host = urlsplit(record.get("frame_url") or "").hostname or ""
        if frame_host and frame_host.lower() != site_host.lower() and layer not in {"GTM_CONTAINER", "SERVICE_WORKER"}:
            layer = "EMBED_OR_IFRAME"
        if vendor["confidence"] == "UNKNOWN" and request_host.lower() == site_host.lower() and re.search(r"/(collect|track|event|beacon|pixel)(/|$)", urlsplit(record["raw_url_for_memory_only"]).path, re.I):
            layer = "FIRST_PARTY_PROXY_OR_GATEWAY"
        data = {
            "method": record["method"],
            "url": record["safe_url"],
            "query_parameter_names": record["query_parameter_names"],
            "resource_type": record["resource_type"],
            "response_status": record["status"],
            "failure": record["failure"],
            "service_worker": record["service_worker"],
            "canary_detected": bool(record["canary_hits"]),
            "occurrence_index": occurrence_index,
            "initiator_type": initiator.get("type"),
        }
        row = make_observation(
            run=run,
            scenario=scenario,
            action_window=action_window,
            page_url=record.get("frame_url") or scenario["pages"][0],
            surface="NETWORK",
            data=data,
            vendor=vendor,
            initiator=initiator_url,
            layer=layer,
        )
        rows.append(row)
        for canary_hit_index, hit in enumerate(record["canary_hits"], start=1):
            rows.append(
                make_observation(
                    run=run,
                    scenario=scenario,
                    action_window=action_window,
                    page_url=record.get("frame_url") or scenario["pages"][0],
                    surface="CANARY",
                    data={
                        "canary_id": hit["canary_id"],
                        "safe_parameter_path": hit["safe_parameter_path"],
                        "destination_url": record["safe_url"],
                        "category": hit["category"],
                        "detection_basis": "exact in-memory synthetic canary match",
                        "redacted_marker": "<synthetic-canary-detected>",
                        "value_fingerprint": "NOT_RETAINED",
                        "request_occurrence_index": occurrence_index,
                        "canary_hit_index": canary_hit_index,
                    },
                    vendor=vendor,
                    initiator=initiator_url,
                    layer=layer,
                    status="UNEXPECTED_BEHAVIOUR_OBSERVED",
                )
            )
    return rows


def websocket_observations(
    run: dict[str, Any],
    scenario: dict[str, Any],
    websocket_urls: set[str],
    page_url: str,
    canaries: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for websocket_index, websocket_url in enumerate(sorted(websocket_urls), start=1):
        safe_url, query_names = sanitize_url(websocket_url)
        vendor = classify_url(websocket_url)
        rows.append(
            make_observation(
                run=run,
                scenario=scenario,
                action_window="whole_scenario",
                page_url=page_url,
                surface="NETWORK",
                data={
                    "method": "GET",
                    "url": safe_url,
                    "query_parameter_names": query_names,
                    "resource_type": "websocket",
                    "response_status": None,
                    "failure": None,
                    "service_worker": False,
                    "canary_detected": bool(detect_canary_path(websocket_url, None, {}, canaries)),
                    "occurrence_index": websocket_index,
                    "initiator_type": None,
                },
                vendor=vendor,
                layer="UNKNOWN",
            )
        )
        for hit_index, hit in enumerate(detect_canary_path(websocket_url, None, {}, canaries), start=1):
            rows.append(
                make_observation(
                    run=run,
                    scenario=scenario,
                    action_window="whole_scenario",
                    page_url=page_url,
                    surface="CANARY",
                    data={
                        "canary_id": hit["canary_id"],
                        "safe_parameter_path": hit["safe_parameter_path"],
                        "destination_url": safe_url,
                        "category": hit["category"],
                        "detection_basis": "exact in-memory synthetic canary match in WebSocket URL",
                        "redacted_marker": "<synthetic-canary-detected>",
                        "value_fingerprint": "NOT_RETAINED",
                        "request_occurrence_index": websocket_index,
                        "canary_hit_index": hit_index,
                    },
                    vendor=vendor,
                    layer="UNKNOWN",
                    status="UNEXPECTED_BEHAVIOUR_OBSERVED",
                )
            )
    return rows


def locator_for_plan(page: Any, locator: dict[str, str]) -> Any:
    if locator["by"] == "LABEL":
        return page.get_by_label(locator["value"], exact=True)
    if locator["by"] == "ROLE_NAME":
        return page.get_by_role("button", name=locator["value"], exact=True)
    return page.locator(locator["value"])


def execute_interaction_plan(
    *, page: Any, scenario_class: str, plan: dict[str, Any] | None, canaries: dict[str, dict[str, str]], run: dict[str, Any]
) -> list[str]:
    if not plan:
        return []
    notes: list[str] = []
    authorizations = {item["authorization_id"]: item for item in plan["submission_authorizations"]}
    for action in plan["actions"]:
        if scenario_class not in action["scenario_classes"]:
            continue
        if action["url"] != page.url:
            continue
        locator = locator_for_plan(page, action["locator"])
        if locator.count() != 1 or not locator.is_visible():
            notes.append(f"{action['action_id']}: target unavailable")
            continue
        canary_spec = canaries.get(str(action.get("canary_id"))) if action.get("canary_id") else None
        canary = canary_spec["value"] if canary_spec else None
        if action["kind"] == "FILL":
            if not canary:
                raise ContractError(f"{action['action_id']} requires a canary value")
            locator.fill(canary)
        elif action["kind"] == "BLUR":
            locator.press("Tab")
        elif action["kind"] in {"VALIDATE", "STEP_ADVANCE"}:
            locator.click()
        elif action["kind"] == "SUBMIT":
            authorization = authorizations.get(str(action.get("authorization_id")))
            if plan["environment"] == "production":
                if not authorization:
                    notes.append(f"{action['action_id']}: NOT_TESTED missing exact production submission authorization")
                    continue
                if authorization["exact_origin"].rstrip("/") != run["site"]["origin"].rstrip("/"):
                    raise ContractError(f"{action['action_id']} authorization origin mismatch")
            if re.search(r"payment|purchase|booking|subscription|account|message", authorization.get("allowed_synthetic_record", "") if authorization else "", re.I):
                raise ContractError(f"{action['action_id']} requests a prohibited consequential action")
            locator.click()
            notes.append(f"{action['action_id']}: authorized synthetic record; cleanup owner recorded in restricted intake")
    return notes


def execute_scenario(
    *, browser: Any, run: dict[str, Any], scenario: dict[str, Any], adapters: list[dict[str, Any]],
    forced_adapter: str | None, plan: dict[str, Any] | None, canaries: dict[str, dict[str, str]], quiet_ms: int,
    timeout_ms: int, later_ms: int, screenshot_staging: Path | None,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    context = browser.new_context(
        viewport={"width": run["browser"]["viewport"]["width"], "height": run["browser"]["viewport"]["height"]},
        locale=run["browser"]["locale"],
        timezone_id=run["browser"]["timezone"],
        service_workers="allow",
    )
    context_id = stable_id("CTX", run["run_id"], scenario["scenario_id"])
    recorder = NetworkRecorder(canaries=canaries)
    page = context.new_page()
    try:
        cdp_session = context.new_cdp_session(page)
        recorder.attach(context, cdp_session)
    except Exception as exc:
        raise ContractError(f"Chromium initiator capture readiness failed: {type(exc).__name__}: {exc}") from exc
    observations: list[dict[str, Any]] = []
    limitations: list[str] = []
    state_verified = False
    screenshot_captured = False
    adapter: dict[str, Any] | None = None
    detection_summary: dict[str, Any] = {}
    try:
        first_url = scenario["pages"][0]
        cursor = recorder.cursor()
        page.goto(first_url, wait_until="domcontentloaded", timeout=timeout_ms)
        settled, elapsed = recorder.wait_quiet(page, quiet_ms=quiet_ms, timeout_ms=timeout_ms)
        snapshot = browser_snapshot(page, context)
        detection = detect_cmp(snapshot, adapters)
        selected_id = forced_adapter or detection.adapter_id or "generic-custom-banner"
        adapter = adapter_by_id(adapters, selected_id)
        detection_summary = {
            "adapter_id": selected_id,
            "adapter_version": adapter["adapter_version"],
            "provider": adapter["provider"],
            "confidence": detection.confidence if not forced_adapter else "CONFIRMED",
            "scores": detection.scores,
            "matched_kinds": detection.matched_kinds,
        }
        observations.extend(network_observations(run, scenario, recorder.slice(cursor), "initial_load"))
        initial_state = read_cmp_state(page, adapter)
        observations.append(
            make_observation(
                run=run,
                scenario=scenario,
                action_window="initial_load",
                page_url=page.url,
                surface="CMP_STATE",
                data={"phase": "initial", "state": initial_state, "settled": settled, "settle_elapsed_ms": elapsed, "detection": detection_summary},
                layer="CMP",
            )
        )
        observations.append(
            make_observation(
                run=run,
                scenario=scenario,
                action_window="initial_load",
                page_url=page.url,
                surface="CONSENT_SIGNAL",
                data={"google_consent_commands": capture_consent_signals(page), "capture_phase": "initial"},
                layer="UNKNOWN",
            )
        )
        screenshot = stage_cmp_screenshot(page, adapter, "accept", screenshot_staging, scenario["scenario_id"])
        if screenshot:
            screenshot_captured = True
            limitations.append("Screenshot captured to staging only; OCR and analyst approval required before delivery")

        scenario_class = scenario["scenario_class"]
        transition_actions: list[str] = []
        if scenario_class == "REJECTED":
            transition_actions = ["reject"]
        elif scenario_class == "ACCEPTED":
            transition_actions = ["accept"]
        elif scenario_class == "ACCEPTED_TO_WITHDRAWN":
            transition_actions = ["accept", "reopen", "withdraw"]
        elif scenario_class == "PERSISTENCE_ACCEPTED":
            transition_actions = ["accept"]
        elif scenario_class == "PERSISTENCE_REJECTED":
            transition_actions = ["reject"]
        elif scenario_class == "REJECTED_TO_ACCEPTED":
            transition_actions = ["reject", "reopen", "accept"]
        elif scenario_class == "GRANULAR_DENIED":
            limitations.append("Granular category selection requires an explicit unambiguous analyst interaction in v1")
            scenario["status"] = "NOT_TESTED"
        transition_states_verified = True
        for index, action in enumerate(transition_actions):
            cursor = recorder.cursor()
            if action == "reopen":
                ok, method = click_reopen_with_public_fallback(
                    page=page,
                    run=run,
                    adapter=adapter,
                    recorder=recorder,
                    quiet_ms=quiet_ms,
                    timeout_ms=timeout_ms,
                )
            else:
                ok, method = click_control(page, adapter, action)
            if not ok:
                limitations.append(f"{action}: {method}")
                scenario["status"] = "INCONCLUSIVE"
                transition_states_verified = False
                break
            settled, elapsed = recorder.wait_quiet(page, quiet_ms=quiet_ms, timeout_ms=timeout_ms)
            wait_for_cmp_ui_settle(page, action, timeout_ms)
            state = read_cmp_state(page, adapter)
            action_state_verified = state_matches_action(state, action, baseline_state=initial_state)
            transition_states_verified = transition_states_verified and action_state_verified
            state_verified = transition_states_verified
            window = f"choice_{index + 1}_{action}"
            observations.extend(network_observations(run, scenario, recorder.slice(cursor), window))
            observations.append(
                make_observation(
                    run=run,
                    scenario=scenario,
                    action_window=window,
                    page_url=page.url,
                    surface="CMP_STATE",
                    data={"phase": action, "state": state, "state_matches_action": action_state_verified, "all_transition_states_verified": transition_states_verified, "interaction_method": method, "settled": settled, "settle_elapsed_ms": elapsed},
                    layer="CMP",
                    status="EXPECTED_BEHAVIOUR_OBSERVED" if action_state_verified else "INCONCLUSIVE",
                )
            )
            observations.append(
                make_observation(
                    run=run,
                    scenario=scenario,
                    action_window=window,
                    page_url=page.url,
                    surface="CONSENT_SIGNAL",
                    data={"google_consent_commands": capture_consent_signals(page), "capture_phase": action},
                    layer="UNKNOWN",
                )
            )
        if scenario_class == "UNTOUCHED":
            state_verified = state_matches_action(initial_state, "untouched")
        if transition_actions and scenario["status"] != "INCONCLUSIVE":
            final_action = transition_actions[-1]
            later_cursor = recorder.cursor()
            page.wait_for_timeout(later_ms)
            later_window = f"post_{final_action}_later"
            observations.extend(network_observations(run, scenario, recorder.slice(later_cursor), later_window))
            later_state = read_cmp_state(page, adapter)
            later_verified = state_matches_action(later_state, final_action, baseline_state=initial_state)
            state_verified = state_verified and later_verified
            observations.append(
                make_observation(
                    run=run,
                    scenario=scenario,
                    action_window=later_window,
                    page_url=page.url,
                    surface="CMP_STATE",
                    data={"phase": "later_after_choice", "last_action": final_action, "state": later_state, "state_matches_action": later_verified, "fixed_horizon_ms": later_ms},
                    layer="CMP",
                    status="EXPECTED_BEHAVIOUR_OBSERVED" if later_verified else "INCONCLUSIVE",
                )
            )
            observations.append(
                make_observation(
                    run=run,
                    scenario=scenario,
                    action_window=later_window,
                    page_url=page.url,
                    surface="CONSENT_SIGNAL",
                    data={"google_consent_commands": capture_consent_signals(page), "capture_phase": "later_after_choice"},
                    layer="UNKNOWN",
                )
            )
        if scenario["status"] != "NOT_TESTED":
            for page_index, target_url in enumerate(scenario["pages"]):
                if page_index == 0:
                    continue
                cursor = recorder.cursor()
                page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
                settled, elapsed = recorder.wait_quiet(page, quiet_ms=quiet_ms, timeout_ms=timeout_ms)
                observations.extend(network_observations(run, scenario, recorder.slice(cursor), f"page_{page_index + 1}"))
                observations.append(
                    make_observation(
                        run=run,
                        scenario=scenario,
                        action_window=f"page_{page_index + 1}",
                        page_url=page.url,
                        surface="CMP_STATE",
                        data={"phase": "later_page", "state": read_cmp_state(page, adapter), "settled": settled, "settle_elapsed_ms": elapsed},
                        layer="CMP",
                    )
                )
                observations.append(
                    make_observation(
                        run=run,
                        scenario=scenario,
                        action_window=f"page_{page_index + 1}",
                        page_url=page.url,
                        surface="CONSENT_SIGNAL",
                        data={"google_consent_commands": capture_consent_signals(page), "capture_phase": "later_page"},
                        layer="UNKNOWN",
                    )
                )
            plan_cursor = recorder.cursor()
            plan_notes = execute_interaction_plan(page=page, scenario_class=scenario_class, plan=plan, canaries=canaries, run=run)
            if plan_notes or (plan and any(scenario_class in action["scenario_classes"] for action in plan["actions"])):
                recorder.wait_quiet(page, quiet_ms=quiet_ms, timeout_ms=timeout_ms)
                observations.extend(network_observations(run, scenario, recorder.slice(plan_cursor), "synthetic_interactions"))
            limitations.extend(plan_notes)
            if scenario_class.startswith("PERSISTENCE_"):
                cursor = recorder.cursor()
                page.reload(wait_until="domcontentloaded", timeout=timeout_ms)
                settled, elapsed = recorder.wait_quiet(page, quiet_ms=quiet_ms, timeout_ms=timeout_ms)
                persisted_state = read_cmp_state(page, adapter)
                persisted_action = "accept" if scenario_class == "PERSISTENCE_ACCEPTED" else "reject"
                state_verified = state_matches_action(persisted_state, persisted_action, baseline_state=initial_state)
                observations.extend(network_observations(run, scenario, recorder.slice(cursor), "persistence_revisit"))
                observations.append(
                    make_observation(
                        run=run,
                        scenario=scenario,
                        action_window="persistence_revisit",
                        page_url=page.url,
                        surface="CMP_STATE",
                        data={"phase": "persistence_revisit", "state": persisted_state, "state_matches_expected_choice": state_verified, "settled": settled, "settle_elapsed_ms": elapsed},
                        layer="CMP",
                        status="EXPECTED_BEHAVIOUR_OBSERVED" if state_verified else "INCONCLUSIVE",
                    )
                )
                observations.append(
                    make_observation(
                        run=run,
                        scenario=scenario,
                        action_window="persistence_revisit",
                        page_url=page.url,
                        surface="CONSENT_SIGNAL",
                        data={"google_consent_commands": capture_consent_signals(page), "capture_phase": "persistence_revisit"},
                        layer="UNKNOWN",
                    )
                )
            observations.append(
                make_observation(
                    run=run,
                    scenario=scenario,
                    action_window="final_state",
                    page_url=page.url,
                    surface="STORAGE",
                    data=storage_metadata(page, context),
                    layer="CMP",
                )
            )
            signals = capture_consent_signals(page)
            observations.append(
                make_observation(
                    run=run,
                    scenario=scenario,
                    action_window="final_state",
                    page_url=page.url,
                    surface="CONSENT_SIGNAL",
                    data={"google_consent_commands": signals},
                    layer="UNKNOWN",
                )
            )
            scripts, embeds = script_embed_metadata(page)
            observations.append(
                make_observation(
                    run=run,
                    scenario=scenario,
                    action_window="final_state",
                    page_url=page.url,
                    surface="SCRIPT",
                    data={"scripts": scripts},
                    layer="UNKNOWN",
                )
            )
            observations.append(
                make_observation(
                    run=run,
                    scenario=scenario,
                    action_window="final_state",
                    page_url=page.url,
                    surface="EMBED",
                    data={"frames": embeds},
                    layer="EMBED_OR_IFRAME" if embeds else "UNKNOWN",
                )
            )
        for worker_url in sorted(recorder.worker_urls):
            safe_url, _ = sanitize_url(worker_url)
            observations.append(make_observation(run=run, scenario=scenario, action_window="whole_scenario", page_url=page.url, surface="SERVICE_WORKER", data={"url": safe_url}, layer="SERVICE_WORKER"))
        if not recorder.worker_urls:
            limitations.append("No service worker observed; absence is sample-bound")
        observations.extend(websocket_observations(run, scenario, recorder.websocket_urls, page.url, canaries))
        if scenario["status"] == "RUNNING":
            scenario["status"] = "COMPLETE" if state_verified else "INCONCLUSIVE"
        scenario["context_id"] = context_id
        scenario["state_verified"] = state_verified
        scenario["capture_status"] = {
            "network": "COMPLETE",
            "cookies": "COMPLETE" if scenario["status"] != "NOT_TESTED" else "NOT_TESTED",
            "storage": "COMPLETE" if scenario["status"] != "NOT_TESTED" else "NOT_TESTED",
            "cmp_state": "COMPLETE" if state_verified else "INCONCLUSIVE",
            "scripts_embeds": "COMPLETE" if scenario["status"] != "NOT_TESTED" else "NOT_TESTED",
            "screenshot": "COMPLETE" if screenshot_captured else "NOT_TESTED",
            "attribution": "COMPLETE",
            "service_workers": "COMPLETE",
        }
        scenario["limitations"] = sorted(set(limitations))
        return observations, scenario, detection_summary
    finally:
        context.close()


def abort_run(run_path: Path, run: dict[str, Any], reason: str) -> None:
    run["status"] = "ABORTED"
    run["abort_reason"] = reason[:2000]
    run["completed_at"] = utc_now()
    run["overall_technical_outcome"] = None
    for scenario in run["scenarios"]:
        if scenario["status"] in {"REGISTERED", "RUNNING"}:
            scenario["status"] = "ABORTED"
            scenario["capture_status"] = {key: "ABORTED" for key in scenario["capture_status"]}
            scenario["limitations"] = sorted(set(scenario["limitations"] + [reason[:500]]))
    validate_schema(run, "audit-run.schema.json", label=str(run_path))
    write_json(run_path, run)


def main() -> int:
    args = parse_args()
    run = read_json(args.run)
    try:
        validate_schema(run, "audit-run.schema.json", label=str(args.run))
        if run["status"] not in {"PLANNED", "ABORTED"}:
            raise ContractError(f"Run status must be PLANNED or explicitly resumed ABORTED, got {run['status']}")
        if not run["site"]["deployment_verified"]:
            raise ContractError("Deployment is not verified")
        if args.quiet_ms < 250 or args.timeout_ms <= args.quiet_ms or args.later_ms < 500:
            raise ContractError("Require timeout-ms > quiet-ms >= 250 and later-ms >= 500")
        canaries = load_restricted_canaries(args.canary_file)
        plan = load_interaction_plan(args.interaction_plan)
        if bool(plan) != bool(args.canary_file) and plan and any(item.get("canary_id") for item in plan["actions"]):
            raise ContractError("Interaction plan references canaries but no canary file was supplied")
        adapters = load_adapters()
        if args.adapter:
            adapter_by_id(adapters, args.adapter)
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise ContractError("Playwright is unavailable; route browser setup and abort") from exc
        launch_options: dict[str, Any] = {"headless": not run["browser"]["headed"]}
        if run["network_route"].get("proxy"):
            launch_options["proxy"] = {"server": run["network_route"]["proxy"]}
        run["status"] = "RUNNING"
        run["started_at"] = utc_now()
        run["abort_reason"] = None
        write_json(args.run, run)
        all_observations: list[dict[str, Any]] = []
        detections: list[dict[str, Any]] = []
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(**launch_options)
            except Exception as exc:
                raise ContractError(f"Chromium readiness failed: {type(exc).__name__}: {exc}") from exc
            try:
                run["browser"]["version"] = str(browser.version)
                probe = browser.new_page()
                run["browser"]["user_agent"] = probe.evaluate("() => navigator.userAgent")
                probe.close()
                run["capture_capabilities"] = {"network": True, "cookies": True, "storage": True, "cmp_state": True, "scripts_embeds": True, "service_workers": True, "screenshots": bool(args.screenshot_staging), "initiators": True}
                for index, scenario in enumerate(run["scenarios"]):
                    scenario["status"] = "RUNNING"
                    rows, updated, detection = execute_scenario(
                        browser=browser,
                        run=run,
                        scenario=scenario,
                        adapters=adapters,
                        forced_adapter=args.adapter,
                        plan=plan,
                        canaries=canaries,
                        quiet_ms=args.quiet_ms,
                        timeout_ms=args.timeout_ms,
                        later_ms=args.later_ms,
                        screenshot_staging=args.screenshot_staging,
                    )
                    run["scenarios"][index] = updated
                    all_observations.extend(rows)
                    detections.append(detection)
                    write_json(args.run, run)
            finally:
                browser.close()
        for row in all_observations:
            validate_schema(row, "observation.schema.json", label=row["observation_id"])
        write_jsonl(args.output, all_observations)
        nonempty_detections = [item for item in detections if item]
        if nonempty_detections:
            ids = {item["adapter_id"] for item in nonempty_detections}
            selected = nonempty_detections[0]
            run["cmp"] = {
                "adapter_id": selected["adapter_id"] if len(ids) == 1 else None,
                "adapter_version": selected["adapter_version"] if len(ids) == 1 else None,
                "provider": selected["provider"] if len(ids) == 1 else None,
                "detection_confidence": selected["confidence"] if len(ids) == 1 else "CONFLICTING",
                "interaction_method": "UI",
                "limitations": [] if len(ids) == 1 else ["CMP detection changed across scenario contexts"],
            }
        incomplete_required = incomplete_required_scenarios(run["scenarios"])
        if incomplete_required:
            run["status"] = "INCONCLUSIVE"
            run["abort_reason"] = "Required core scenario(s) did not complete: " + ", ".join(sorted(incomplete_required))
            run["overall_technical_outcome"] = "MATERIAL_TESTS_INCONCLUSIVE"
        else:
            run["status"] = "COMPLETE"
        run["completed_at"] = utc_now()
        run["outputs"]["observations"] = {"path": str(args.output.name), "sha256": None}
        from consent_runtime_core import sha256_file

        run["outputs"]["observations"]["sha256"] = sha256_file(args.output)
        validate_schema(run, "audit-run.schema.json", label=str(args.run))
        write_json(args.run, run)
        if incomplete_required:
            print(f"ERROR {run['abort_reason']}", file=sys.stderr)
            return 2
    except Exception as exc:
        try:
            abort_run(args.run, run, f"{type(exc).__name__}: {exc}")
        except Exception as abort_exc:
            print(f"ERROR failed to record aborted run: {abort_exc}", file=sys.stderr)
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
