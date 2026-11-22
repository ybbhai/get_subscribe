"""Inspect the actual selected proxy exit using bounded HTTPS JSON requests."""

import asyncio
import copy
from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import threading
import time

import aiohttp
import yaml

from utils.node_policy import NodePolicy


IPQUERY_URL = "https://api.ipquery.io/"
IPAPI_URL = "https://api.ipapi.is/"
MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_EXIT_QUALITY_CONFIG = Path(__file__).resolve().parents[1] / "config" / "exit_quality.yaml"


def _load_ipapi_key():
    """Resolve an optional local credential without exposing its contents in errors."""
    key = os.environ.get("IPAPI_IS_KEY", "").strip()
    if key:
        return key
    configured_path = os.environ.get("EXIT_QUALITY_CONFIG", "").strip()
    try:
        path = Path(configured_path).expanduser() if configured_path else DEFAULT_EXIT_QUALITY_CONFIG
        if not path.is_file():
            if configured_path:
                raise ValueError("指定的出口质量检测配置文件不存在")
            return ""
        with path.open("r", encoding="utf-8") as stream:
            contents = stream.read(MAX_RESPONSE_BYTES + 1)
        if len(contents) > MAX_RESPONSE_BYTES:
            raise ValueError("出口质量检测配置文件过大")
        data = yaml.safe_load(contents)
    except (OSError, UnicodeError, yaml.YAMLError, RuntimeError):
        # YAML and OS errors can contain credentials or private file contents.
        raise ValueError("出口质量检测配置文件无法读取") from None
    if data is None:
        return ""
    if not isinstance(data, dict) or not isinstance(data.get("ipapi_is_key", ""), str):
        raise ValueError("出口质量检测配置的 ipapi_is_key 必须是字符串")
    return data.get("ipapi_is_key", "").strip()


def _reputation_failure_reason(error):
    if isinstance(error, LookupError):
        if error.status in (403, 429) or error.args == ("reputation_rate_limited",):
            return "reputation_rate_limited"
        if error.args == ("lookup_timeout",):
            return "reputation_timeout"
    return "reputation_unavailable"


def public_ip(value):
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return None
    return str(address) if address.is_global else None


def unknown(reason, ip=None):
    return {"status": "unknown", "residential": None, "ip": ip, "reason": reason}


def _number(value, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if math.isfinite(value) and 0 <= value <= maximum else None


def _abuse_score(value):
    if isinstance(value, str):
        match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(?:\s+\([^\r\n]*\))?", value.strip())
        return _number(float(match.group(1)), 1) if match else None
    return _number(value, 1)


def parse_ipquery(data, policy):
    if not isinstance(data, dict) or not public_ip(data.get("ip")):
        return unknown("invalid_exit_ip")
    result = unknown("missing_risk_fields", public_ip(data["ip"]))
    result["sources"] = ["ipquery"]
    risk = data.get("risk")
    if not isinstance(risk, dict):
        return result
    fields = ("is_vpn", "is_proxy", "is_tor", "is_datacenter", "is_mobile")
    result["flags"] = {key: risk.get(key) for key in fields if type(risk.get(key)) is bool}
    score = _number(risk.get("risk_score"), 100)
    result["risk_score"] = score
    if any(risk.get(key) is True for key in ("is_vpn", "is_proxy", "is_tor")) or (
            score is not None and score > policy.max_risk_score):
        result.update(status="risk", reason="risk_signal")
    elif all(type(risk.get(key)) is bool for key in fields) and score is not None:
        result.update(status="clean", reason="low_risk_signals")
    # Neither an ISP name nor is_datacenter=false proves residential access.
    return result


def apply_ipapi(evidence, data, policy):
    result = copy.deepcopy(evidence)
    if not isinstance(data, dict) or public_ip(data.get("ip")) != evidence.get("ip"):
        result.update(status="unknown", residential=None, reason="reputation_ip_mismatch")
        return result
    result["sources"] = list(dict.fromkeys(result.get("sources", []) + ["ipapi.is"]))
    flags = ("is_bogon", "is_abuser", "is_proxy", "is_vpn", "is_tor", "is_crawler")
    company = data.get("company") if isinstance(data.get("company"), dict) else {}
    asn = data.get("asn") if isinstance(data.get("asn"), dict) else {}
    scores = [_abuse_score(company.get("abuser_score")), _abuse_score(asn.get("abuser_score"))]
    result["company_type"] = company.get("type")
    result["asn_type"] = asn.get("type")
    result["abuse_scores"] = scores
    # A recognized positive flag overrides a clean result from another provider.
    if (evidence.get("status") == "risk" or any(data.get(key) for key in flags)
            or any(score is not None and score > policy.max_abuse_score for score in scores)):
        result.update(status="risk", residential=False, reason="risk_signal")
        return result
    if not all(data.get(key) is False for key in flags) or any(score is None for score in scores):
        result.update(status="unknown", residential=None, reason="missing_reputation_fields")
        return result
    if evidence.get("status") != "clean":
        result.update(status="unknown", residential=None, reason="incomplete_risk_evidence")
        return result
    result["residential"] = (
        company.get("type") == "isp" and asn.get("type") == "isp"
        and all(data.get(key) is False for key in ("is_datacenter", "is_mobile", "is_satellite", "is_anycast"))
        and evidence.get("flags", {}).get("is_datacenter") is False
        and evidence.get("flags", {}).get("is_mobile") is False
        and not data.get("egress_service")
    )
    result["reason"] = "low_risk_isp_candidate" if result["residential"] else "low_risk_signals"
    return result


class LookupError(ValueError):
    def __init__(self, reason, status=None):
        super().__init__(reason)
        self.status = status


async def _request_json_async(proxy_url, method, url, timeout, **kwargs):
    # The total deadline includes connect, headers and the entire body, even when
    # the peer keeps trickling bytes. Do not round longer deadlines up to seconds.
    deadline = aiohttp.ClientTimeout(total=timeout, connect=min(5, timeout),
                                     sock_read=timeout, ceil_threshold=math.inf)
    async with aiohttp.ClientSession(trust_env=False, timeout=deadline) as session:
        async with session.request(method, url, proxy=proxy_url,
                                   allow_redirects=False, **kwargs) as response:
            if response.status != 200:
                raise LookupError("lookup_http_error", response.status)
            body = bytearray()
            async for chunk in response.content.iter_chunked(8192):
                if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise LookupError("lookup_response_limit")
                body.extend(chunk)
            try:
                data = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                raise LookupError("lookup_invalid_json") from None
            if not isinstance(data, dict) or data.get("error"):
                raise LookupError("lookup_invalid_record")
            return data


def _request_json(proxy_url, method, url, timeout, **kwargs):
    # Called from synchronous node-test workers. Cancellation closes the actual
    # connection before returning; no abandoned background request can keep a lock.
    try:
        return asyncio.run(_request_json_async(proxy_url, method, url, timeout, **kwargs))
    except asyncio.TimeoutError:
        raise LookupError("lookup_timeout") from None
    except aiohttp.ClientError:
        raise LookupError("lookup_transport_error") from None


class ExitInspector:
    """Shared per round; quotas and keyed reputation cache are bounded and thread safe."""

    def __init__(self, policy=None, profile=None):
        self.policy = policy or NodePolicy()
        self._key = _load_ipapi_key()
        self._residential_enabled = profile == "prod" or bool(self._key)
        self._lock = threading.Lock()
        self._lookup_count = 0
        self._ipapi_blocked = False
        self._cache = {}

    def capabilities(self):
        """Nonsecret mode and credential availability for logs and selection reports."""
        with self._lock:
            if not self._residential_enabled:
                reason = "disabled"
            elif not self._key:
                reason = "missing_api_key"
            elif self._ipapi_blocked:
                reason = "reputation_rate_limited"
            else:
                reason = "ready"
            return {"enabled": self._residential_enabled,
                    "available": bool(self._key) and not self._ipapi_blocked,
                    "reason": reason}

    def inspect(self, http_port):
        with self._lock:
            if self._lookup_count >= self.policy.max_lookups_per_round:
                return unknown("round_lookup_budget")
            self._lookup_count += 1
        proxy_url = f"http://127.0.0.1:{http_port}"
        # Always use the selected node; never fall back to direct or environment proxies.
        try:
            data = _request_json(proxy_url, "GET", IPQUERY_URL, self.policy.lookup_timeout_seconds,
                                 params={"format": "json"})
            evidence = parse_ipquery(data, self.policy)
        except (LookupError, OSError) as error:
            if isinstance(error, LookupError) and error.status in (403, 429):
                # IPQuery has no shared account: a rejection can be specific
                # to this exit, so other nodes must still get their own lookup.
                return unknown("provider_rate_limited")
            # Do not print exception text: it can contain a token or remote response.
            return unknown(type(error).__name__)
        if self._residential_enabled and self._key and evidence.get("ip") and evidence.get("status") != "risk":
            try:
                record = self._lookup_ipapi(proxy_url, evidence["ip"])
                evidence = apply_ipapi(evidence, record, self.policy)
            except (LookupError, OSError) as error:
                # Optional enrichment being unavailable does not invalidate the
                # independently observed IPQuery risk evidence. It only leaves
                # residential access unverified for this exit.
                evidence.update(residential=None, reputation_reason=_reputation_failure_reason(error))
        elif not self._key:
            evidence["residential_reason"] = self.capabilities()["reason"]
        evidence["checked_at"] = datetime.now(timezone.utc).isoformat()
        return evidence

    def _lookup_ipapi(self, proxy_url, ip):
        # Serialize keyed requests so identical exits consume one lookup per round.
        with self._lock:
            cached = self._cache.get(ip)
            if cached and time.monotonic() - cached[0] < 600:
                return copy.deepcopy(cached[1])
            if self._ipapi_blocked:
                raise LookupError("reputation_rate_limited")
            try:
                record = _request_json(proxy_url, "POST", IPAPI_URL, self.policy.lookup_timeout_seconds,
                                       json={"q": ip, "key": self._key})
            except LookupError as error:
                if error.status in (403, 429):
                    self._ipapi_blocked = True
                raise
            self._cache[ip] = (time.monotonic(), record)
            return copy.deepcopy(record)
