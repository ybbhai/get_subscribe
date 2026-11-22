"""EdgeTunnel and CFnew subscription adapters for the shared proxy pipeline."""

import asyncio
import copy
import csv
import ipaddress
import io
import json
import math
import os
import re
import ssl
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
from requests.utils import select_proxy
import yaml

from utils.utils import v2ray_2_clash, b64_decode_text, _is_dialable_host
from utils.proxy_chain import bind_dialer
from utils.source_tracking import tag_source


MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ADDRESSES = 500
DEFAULT_MAX_CANDIDATES = 100
DEFAULT_AUTOMATIC_MAX_CANDIDATES = 40
MAX_AUTOMATIC_TEMPLATES = 3
MAX_AUTOMATIC_SOURCE_TEMPLATES = 10
TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
ADDRESS_HEADERS = {"ip", "ipaddress", "ip地址"}


def validate_candidate_limit(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_ADDRESSES:
        raise CloudflareSourceError(f"Cloudflare 候选数量必须为 1–{MAX_ADDRESSES} 的整数")


def _normalize_worker_proxy(proxy):
    """Normalize a standalone Worker route, preserving all transport options."""
    if not isinstance(proxy, dict):
        return None
    kind = str(proxy.get("type", "")).lower()
    if (kind not in ("vless", "trojan")
            or str(proxy.get("network", "")).lower() != "ws"
            or (kind == "vless" and proxy.get("tls") is not True)
            or (kind == "trojan" and proxy.get("tls") is False)
            or proxy.get("reality-opts") or proxy.get("flow")
            or proxy.get("dialer-proxy")):
        return None
    if kind == "vless" and not _is_valid_uuid(proxy.get("uuid")):
        return None
    if kind == "trojan" and not isinstance(proxy.get("password"), str):
        return None
    if kind == "trojan" and not proxy["password"]:
        return None
    if not _is_dialable_host(proxy.get("server")):
        return None
    port = proxy.get("port")
    if isinstance(port, bool) or not str(port).isdigit() or int(port) not in TLS_PORTS:
        return None
    options = proxy.get("ws-opts", {})
    if not isinstance(options, dict) or not isinstance(options.get("headers", {}), dict):
        return None
    headers = options.get("headers", {})
    host = next((v for k, v in headers.items() if str(k).lower() == "host"), None)
    sni = proxy.get("servername") or proxy.get("sni") or host or proxy["server"]
    host = host or sni
    if not all(isinstance(v, str) and _is_dialable_host(v) for v in (sni, host)):
        return None
    path = options.get("path", "/")
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    alpn = proxy.get("alpn")
    if alpn and (not isinstance(alpn, (list, tuple)) or "http/1.1" not in alpn):
        return None
    result = {k: copy.deepcopy(v) for k, v in proxy.items() if not k.startswith("_")}
    result.update(type=kind, network="ws", port=int(port))
    result["sni" if kind == "trojan" else "servername"] = sni
    result["ws-opts"] = copy.deepcopy(options)
    result["ws-opts"]["path"] = path
    result["ws-opts"]["headers"] = {
        k: v for k, v in headers.items() if str(k).lower() != "host"}
    result["ws-opts"]["headers"]["Host"] = host
    result.setdefault("name", "CF-Worker")
    return result


def _parse_worker_subscription(raw, max_candidates):
    # Detect YAML before attempting Base64, including CFnew's leading comments.
    text = raw.lstrip("\ufeff").strip()
    if not re.search(r"(?m)^\s*proxies\s*:", text) and not text.startswith("{"):
        decoded = b64_decode_text(text)
        if decoded:
            text = decoded
    try:
        document = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError):
        document = None
    if not isinstance(document, dict):
        return [node for proxy in v2ray_2_clash(content=raw)
                if (node := _normalize_worker_proxy(proxy)) is not None]
    proxies = document.get("proxies")
    if not isinstance(proxies, list):
        raise CloudflareSourceError("Cloudflare Clash 订阅缺少 proxies 列表")
    groups = document.get("proxy-groups", [])
    if not isinstance(groups, list):
        raise CloudflareSourceError("Cloudflare Clash 订阅 proxy-groups 格式无效")
    by_name = {}
    for item in proxies + groups:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        if item["name"] in by_name:
            raise CloudflareSourceError("Cloudflare Clash 订阅节点或分组重名")
        by_name[item["name"]] = item

    def resolve(name, visiting=(), budget=None):
        if budget is None:
            budget = [256]
        budget[0] -= 1
        if budget[0] < 0 or not isinstance(name, str) or name in visiting or len(visiting) >= 16:
            return []
        item = by_name.get(name)
        if not item:
            return []
        node = _normalize_worker_proxy(item)
        if node:
            return [node]
        if item.get("type") not in ("select", "url-test", "fallback"):
            return []
        # Dynamic providers/filters cannot be faithfully flattened here.
        if any(item.get(k) for k in ("use", "include-all", "include-all-proxies", "filter", "exclude-filter")):
            return []
        members = item.get("proxies", [])
        if not isinstance(members, list):
            return []
        routes = []
        for member in members:
            routes.extend(resolve(member, visiting + (name,), budget))
            if len(routes) >= MAX_AUTOMATIC_TEMPLATES:
                break
        return routes[:MAX_AUTOMATIC_TEMPLATES]

    exits = [p for p in proxies if isinstance(p, dict) and p.get("type") == "openvpn"]
    if not exits:
        return [node for proxy in proxies if (node := _normalize_worker_proxy(proxy)) is not None]
    routes_by_exit = []
    for proxy in exits:
        if (proxy.get("proto", "tcp") != "tcp" or not _is_dialable_host(proxy.get("server"))
                or isinstance(proxy.get("port"), bool)
                or not str(proxy.get("port", "")).isdigit()
                or not 1 <= int(proxy["port"]) <= 65535
                or not all(isinstance(proxy.get(k), str) and proxy[k].strip()
                           for k in ("ca", "cert", "key"))):
            continue
        routes = resolve(proxy.get("dialer-proxy"))
        if routes:
            routes_by_exit.append((proxy, routes))
    if not routes_by_exit:
        raise CloudflareSourceError("CFnew 家宽订阅没有可解析的 OpenVPN → Worker 链路（缺少前置、内联证书或引用无效）")
    result = []
    # Cover different exits before spending the budget on alternate ingress nodes.
    for route_index in range(MAX_AUTOMATIC_TEMPLATES):
        for proxy, routes in routes_by_exit:
            if route_index >= len(routes):
                continue
            clean = {k: v for k, v in proxy.items() if not k.startswith("_")}
            node = bind_dialer(clean, routes[route_index])
            node["name"] = f"CF-Chain-{proxy['name']}-{route_index + 1}"
            result.append(node)
            if len(result) >= max_candidates:
                return result
    return result


class CloudflareSourceError(ValueError):
    """An invalid or unreadable Cloudflare source with a safe message."""


def _decode_source(raw):
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise CloudflareSourceError("Cloudflare 来源不是 UTF-8 文本") from None


async def _fetch_subscription(session, url, timeout):
    """Keep the collection route and TLS settings, with a cancellable total deadline."""
    settings = session.merge_environment_settings(url, {}, None, None, None)
    proxy = select_proxy(url, settings["proxies"])
    if proxy and urlsplit(proxy).scheme.lower() not in ("http", "https"):
        raise CloudflareSourceError("Cloudflare 采集代理必须使用 HTTP 或 HTTPS")
    verify = settings["verify"]
    context = False if verify is False else ssl.create_default_context(
        cafile=verify if isinstance(verify, str) and not os.path.isdir(verify) else None,
        capath=verify if isinstance(verify, str) and os.path.isdir(verify) else None)
    if settings.get("cert") and context is not False:
        cert = settings["cert"]
        context.load_cert_chain(*(cert if isinstance(cert, (tuple, list)) else (cert,)))
    headers = dict(session.headers)
    headers.update({"User-Agent": "get-subscribe/1.0", "Accept": "text/plain,*/*"})
    connect, read, total = timeout
    deadline = aiohttp.ClientTimeout(total=total, connect=connect, sock_read=read,
                                     ceil_threshold=math.inf)
    async with aiohttp.ClientSession(headers=headers, trust_env=False, timeout=deadline) as client:
        async with client.get(url, proxy=proxy, ssl=context) as response:
            response.raise_for_status()
            if response.content_length is not None and response.content_length > MAX_SOURCE_BYTES:
                raise CloudflareSourceError("Cloudflare 订阅响应超过 4 MiB")
            body = bytearray()
            async for chunk in response.content.iter_chunked(8192):
                if len(body) + len(chunk) > MAX_SOURCE_BYTES:
                    raise CloudflareSourceError("Cloudflare 订阅响应超过 4 MiB")
                body.extend(chunk)
            return bytes(body)


def _read_subscription(session, subscription_url, subscription_file, timeout):
    if bool(subscription_url) == bool(subscription_file):
        raise CloudflareSourceError(
            "Cloudflare 订阅地址和文件必须且只能指定一个"
        )

    if subscription_file:
        path = Path(subscription_file)
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                raise CloudflareSourceError("Cloudflare 订阅文件超过 4 MiB")
            raw = path.read_bytes()
        except OSError as error:
            raise CloudflareSourceError(
                f"Cloudflare 订阅文件无法读取: {path}"
            ) from error
        if len(raw) > MAX_SOURCE_BYTES:
            raise CloudflareSourceError("Cloudflare 订阅文件超过 4 MiB")
        return _decode_source(raw)

    try:
        parsed = urlsplit(subscription_url)
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
        parsed.port
    except (TypeError, ValueError):
        raise CloudflareSourceError("Cloudflare 订阅 URL 格式无效") from None
    if parsed.scheme.lower() != "https":
        raise CloudflareSourceError("Cloudflare 订阅 URL 必须使用 HTTPS")

    limits = timeout if isinstance(timeout, (tuple, list)) else (timeout, timeout)
    if (len(limits) != 2 or any(isinstance(value, bool) or not isinstance(value, (int, float))
                              or not math.isfinite(value) or value <= 0 for value in limits)):
        raise CloudflareSourceError("Cloudflare 订阅超时必须是有限正数或两个有限正数")
    total_timeout = sum(limits) if isinstance(timeout, (tuple, list)) else timeout
    if not math.isfinite(total_timeout):
        raise CloudflareSourceError("Cloudflare 订阅总超时必须是有限正数")
    try:
        raw = asyncio.run(_fetch_subscription(session, subscription_url, (*limits, total_timeout)))
        return _decode_source(raw)
    except CloudflareSourceError:
        raise
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as error:
        raise CloudflareSourceError(
            f"Cloudflare 订阅请求失败（{type(error).__name__}）"
        ) from None


def _parse_address(line):
    endpoint, _, label = line.partition("#")
    endpoint = endpoint.strip()
    if not endpoint or any(char.isspace() for char in endpoint):
        return None
    if any(char in endpoint for char in "/@?\\"):
        return None

    try:
        if endpoint.count(":") > 1 and not endpoint.startswith("["):
            host = str(ipaddress.IPv6Address(endpoint))
            port = 443
        else:
            parsed = urlsplit("//" + endpoint)
            host = parsed.hostname or ""
            port = parsed.port if parsed.port is not None else 443
            if parsed.path or parsed.query or parsed.fragment:
                return None
    except ValueError:
        return None

    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError:
            return None
        labels = host.split(".")
        if (len(host) > 253 or len(labels) < 2
                or not re.fullmatch(r"[a-z0-9.-]+", host)
                or all(char.isdigit() or char == "." for char in host)
                or any(not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part
                ) for part in labels)):
            return None

    if port not in TLS_PORTS:
        return None
    safe_label = re.sub(r"[\r\n\t]", " ", label.strip())[:80]
    return host, port, safe_label


def _parse_addresses(raw, source_format):
    if re.search(r"(?im)\$(?:sstp|socks5?|https?)://", raw):
        raise CloudflareSourceError(
            "检测到带出口链接的 gate nodes.txt；请交给 EdgeTunnel 生成最终订阅，不能当作纯入口地址文件")
    address_text = raw
    if source_format == "cloudflare-speedtest-csv":
        try:
            rows = csv.reader(io.StringIO(raw.lstrip("\ufeff")))
            headers = next(rows, None)
            normalized = [
                re.sub(r"\s+", "", value).casefold() for value in headers or []
            ]
            column = next(
                (index for index, header in enumerate(normalized)
                 if header in ADDRESS_HEADERS),
                None,
            )
            if column is None:
                raise CloudflareSourceError(
                    "CloudflareSpeedTest CSV 中没有 IP 地址列"
                )
            address_text = "\n".join(
                row[column] for row in rows if column < len(row)
            )
        except csv.Error:
            raise CloudflareSourceError("CloudflareSpeedTest CSV 格式无效") from None
    elif source_format != "addresses":
        raise CloudflareSourceError("Cloudflare 地址文件格式无效")

    addresses = []
    seen = set()
    for line in address_text.splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        address = _parse_address(line)
        if address is None:
            continue
        host, port, label = address
        key = (host, port)
        if key not in seen:
            addresses.append(address)
            seen.add(key)
        if len(addresses) >= MAX_ADDRESSES:
            break

    if not addresses:
        raise CloudflareSourceError("Cloudflare 地址文件中没有有效的 TLS 地址")
    return addresses


def get_cloudflare_proxies(
    session,
    *,
    subscription_url=None,
    subscription_file=None,
    addresses_file=None,
    addresses_format="addresses",
    template_index=1,
    max_candidates=DEFAULT_MAX_CANDIDATES,
    timeout=(5, 10),
):
    """Read Worker routes or CFnew chains; only standalone routes allow address overrides."""
    validate_candidate_limit(max_candidates)
    if isinstance(template_index, bool) or not isinstance(template_index, int) or template_index < 1:
        raise CloudflareSourceError("Cloudflare 模板序号必须为正整数")
    raw = _read_subscription(session, subscription_url, subscription_file, timeout)
    candidates = _parse_worker_subscription(raw, max_candidates)
    if not candidates:
        raise CloudflareSourceError("Cloudflare 来源没有可用的 Worker 节点；请提供最终 URI 或 Clash YAML 订阅")

    if not addresses_file:
        return candidates[:max_candidates]
    if any(proxy.get("type") == "openvpn" for proxy in candidates):
        raise CloudflareSourceError("CFnew 家宽链式订阅不能用地址文件替换出口；请在 CFnew 中配置前置优选地址")
    if template_index < 1 or template_index > len(candidates):
        raise CloudflareSourceError(
            "Cloudflare 模板序号超出可用 VLESS/WS/TLS 节点范围"
        )

    address_path = Path(addresses_file)
    try:
        if address_path.stat().st_size > MAX_SOURCE_BYTES:
            raise CloudflareSourceError("Cloudflare 地址文件超过 4 MiB")
        address_bytes = address_path.read_bytes()
    except OSError:
        raise CloudflareSourceError(
            f"Cloudflare 地址文件无法读取: {addresses_file}"
        ) from None
    if len(address_bytes) > MAX_SOURCE_BYTES:
        raise CloudflareSourceError("Cloudflare 地址文件超过 4 MiB")
    address_raw = _decode_source(address_bytes)

    addresses = _parse_addresses(address_raw, addresses_format)[:max_candidates]
    template = candidates[template_index - 1]
    expanded = []
    for index, (server, port, label) in enumerate(addresses, start=1):
        proxy = copy.deepcopy(template)
        proxy["server"] = server
        proxy["port"] = port
        proxy["name"] = f"CF-{index:03d}-{label or server}"
        expanded.append(proxy)
    return expanded


def _is_valid_uuid(value):
    try:
        uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def get_cloudflare_templates(proxies, networks=None, *, limit=MAX_AUTOMATIC_SOURCE_TEMPLATES):
    """Select reusable templates, covering distinct Worker hosts before variants."""
    templates_by_host = {}
    seen = set()

    for proxy in proxies or []:
        if not isinstance(proxy, dict):
            continue
        if (str(proxy.get("type", "")).lower() != "vless"
                or str(proxy.get("network", "")).lower() != "ws"
                or proxy.get("tls") is not True
                or proxy.get("reality-opts")
                or proxy.get("flow")
                or proxy.get("dialer-proxy")
                or not _is_valid_uuid(proxy.get("uuid"))):
            continue

        raw_port = proxy.get("port")
        try:
            server_ip = ipaddress.ip_address(
                str(proxy.get("server", "")).strip().strip("[]")
            )
        except (TypeError, ValueError):
            continue
        if isinstance(raw_port, bool) or str(raw_port).strip() != "443":
            continue
        port = 443
        if server_ip.version != 4:
            continue
        if networks is not None and not any(
                server_ip.version == network.version and server_ip in network
                for network in networks):
            continue

        servername = proxy.get("servername")
        if not isinstance(servername, str) or not servername.strip():
            continue
        ws_options = proxy.get("ws-opts")
        if not isinstance(ws_options, dict):
            continue
        headers = ws_options.get("headers")
        if not isinstance(headers, dict):
            continue
        host = next(
            (value for key, value in headers.items()
             if isinstance(key, str) and key.lower() == "host"),
            None,
        )
        if not isinstance(host, str) or not host.strip():
            continue

        path = ws_options.get("path", "/")
        if not isinstance(path, str) or not path.strip():
            continue
        alpn = proxy.get("alpn")
        if alpn:
            alpn_values = [alpn] if isinstance(alpn, str) else alpn
            if (not isinstance(alpn_values, (list, tuple))
                    or not any(str(value).lower() == "http/1.1"
                               for value in alpn_values)):
                continue

        signature = json.dumps({key: value for key, value in proxy.items()
                                if key not in ("name", "server", "port")
                                and not key.startswith("_")}, sort_keys=True, default=str)
        if signature in seen:
            continue

        template = copy.deepcopy(proxy)
        template["port"] = port
        template["ws-opts"]["path"] = path
        template["ws-opts"]["headers"] = {
            key: value for key, value in headers.items() if str(key).lower() != "host"}
        template["ws-opts"]["headers"]["Host"] = host
        templates_by_host.setdefault(host.strip().casefold().rstrip("."), []).append(template)
        seen.add(signature)
        if limit == 1:
            return [template]

    templates = []
    # Subscription ordering often groups many variants of the same expired Worker.
    # Cover other hosts before spending the budget on those variants.
    groups = list(templates_by_host.values())
    for variant_index in range(max((len(group) for group in groups), default=0)):
        for group in groups:
            if variant_index >= len(group):
                continue
            templates.append(group[variant_index])
            if limit is not None and len(templates) >= limit:
                return templates

    return templates


def expand_cloudflare_proxies(templates, addresses, *, max_candidates=40, networks=None):
    """Clone compatible templates onto ranked IPv4 addresses without mutating inputs."""
    validate_candidate_limit(max_candidates)
    if not templates or not addresses:
        return []

    expanded = []
    seen_addresses = set()
    for address_index, address in enumerate(addresses, start=1):
        raw_ip = address.get("ip") if isinstance(address, dict) else address
        try:
            ip = ipaddress.ip_address(str(raw_ip))
        except ValueError:
            continue
        if (ip.version != 4 or str(ip) in seen_addresses
                or (networks is not None and not any(
                    ip.version == network.version and ip in network
                    for network in networks))):
            continue

        seen_addresses.add(str(ip))
        for template_index, template in enumerate(templates, start=1):
            proxy = copy.deepcopy(template)
            proxy["server"] = str(ip)
            proxy["port"] = 443
            proxy["name"] = f"CF-{template_index:02d}-{address_index:03d}-{ip}"
            proxy = tag_source(proxy, "cloudflare_auto", "cloudflare_auto")
            expanded.append(proxy)
            if len(expanded) >= max_candidates:
                return expanded
    return expanded
