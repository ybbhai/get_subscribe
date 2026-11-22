import asyncio
import base64
import binascii
import concurrent.futures
import json
import logging
import os
import re
import ssl
import threading
import time
import urllib.parse
from collections import Counter
from time import monotonic
from typing import Optional, Tuple, List

import aiohttp
import requests
from requests.adapters import HTTPAdapter

from utils.clash_manager import ClashMetaManager, _normalize_proxies, select_export_proxies, find_free_port_block, supports_openvpn
from utils.proxy_chain import DEPENDENCIES_KEY
from utils.exit_quality import ExitInspector, unknown
from utils.node_policy import (load_node_policy, rank_proxies, quality_tier, TIER_LABELS,
                               meets_performance_floor, select_inspection_candidates)
from utils.selection_report import write_selection_report
from utils.source_tracking import proxy_source_ids, stage_counts

logger = logging.getLogger(__name__)

# 批量测速 worker 的端口窗口起点；每个 worker 独占 20 个端口，避免互相抢占
_WORKER_PORT_BASE = 18000
# Do not make the bulk downloads compete with each other on this machine.
_DOWNLOAD_LOCK = threading.Lock()


def b64_decode_text(raw: str) -> Optional[str]:
    """
    宽松解码订阅里出现的 base64 文本。

    订阅源常见三种写法，原先的 ``base64.b64decode(raw + "==")`` 只兼容第一种：
      1. 标准 base64，带/不带 ``=`` 填充
      2. URL-safe base64（``-``/``_`` 代替 ``+``/``/``），常见于 SIP002 的 ss 链接
      3. 换行/空格包裹的多行内容

    解码失败返回 None，由调用方决定跳过该节点。
    """
    if not raw:
        return None
    cleaned = re.sub(r"\s+", "", raw)
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    # 去掉已有的填充后重新补齐，避免出现 "===="
    cleaned = cleaned.rstrip("=")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=False).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as e:
        logger.debug("base64 解码失败: %s", type(e).__name__)
        return None


def decode_unicode_name(name: str) -> str:
    """将节点名称中的 Unicode 编码转换为正常字符"""
    if not name:
        return name

    def replace_unicode(match):
        code_point = int(match.group(1), 16)
        try:
            return chr(code_point)
        except ValueError:
            return match.group(0)

    # 匹配 \uXXXX 格式的 Unicode 编码
    result = re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, name)
    # 匹配 \xXX 格式的十六进制编码
    result = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), result)
    return result




def decode_vmess(link):
    raw = link.replace("vmess://", "")
    data = b64_decode_text(raw)
    if data is None:
        return None
    try:
        obj = json.loads(data)
    except ValueError as e:
        logger.debug("vmess 节点 JSON 解析失败: %s", type(e).__name__)
        return None
    if not isinstance(obj, dict):
        return None

    # 字段缺失保护：add/port/id 为必填字段，缺失时直接跳过该节点
    if "add" not in obj or "port" not in obj or "id" not in obj:
        return None

    network = obj.get("net") or "tcp"
    proxy = {
        "name": obj.get("ps", "vmess-node"),
        "type": "vmess",
        "server": obj["add"],
        "port": int(obj["port"]),
        "uuid": obj["id"],
        "alterId": int(obj.get("aid", 0)),
        "cipher": obj.get("scy", "auto"),
        "network": network,
        "tls": obj.get("tls") == "tls",
    }

    # sni 缺失时内核会退回 server 作为 SNI，导致 CDN 落地证书校验失败，需显式透传
    sni = obj.get("sni") or obj.get("host") or ""
    if sni:
        proxy["servername"] = sni

    alpn = obj.get("alpn")
    if alpn:
        proxy["alpn"] = [item for item in str(alpn).split(",") if item]

    if network == "ws":
        proxy["ws-opts"] = {
            "path": obj.get("path", "/"),
            "headers": {"Host": obj.get("host", "")}
        }
    elif network == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": obj.get("path", "")}

    return proxy


def decode_vless(link):
    u = urllib.parse.urlparse(link)
    q = urllib.parse.parse_qs(u.query)

    # 必填字段保护：hostname 或 port 缺失时返回 None
    if not u.hostname or u.port is None:
        return None

    # security=reality 同样需要开启 TLS，否则内核在拨号期直接报
    # "failed to use vision, maybe tls is not enable"
    security = (q.get("security", ["none"])[0] or "none").lower()
    network = q.get("type", ["tcp"])[0] or "tcp"
    tls_enabled = security in ("tls", "reality", "xtls")

    proxy = {
        "name": urllib.parse.unquote(u.fragment) or "vless-node",
        "type": "vless",
        "server": u.hostname,
        "port": u.port,
        "uuid": u.username,
        "network": network,
        "tls": tls_enabled,
    }

    sni = q.get("sni", [""])[0] or q.get("host", [""])[0]
    if sni:
        proxy["servername"] = sni

    if tls_enabled:
        # REALITY 基于 uTLS，缺少 client-fingerprint 时内核校验能过但拨号必失败：
        # "REALITY is based on uTLS, please set a client-fingerprint"
        proxy["client-fingerprint"] = q.get("fp", ["chrome"])[0] or "chrome"
        alpn = q.get("alpn", [""])[0]
        if alpn:
            proxy["alpn"] = [item for item in alpn.split(",") if item]
        if q.get("allowInsecure", ["0"])[0] == "1" or q.get("insecure", ["0"])[0] == "1":
            proxy["skip-cert-verify"] = True

    if "flow" in q and tls_enabled:
        proxy["flow"] = q["flow"][0]

    if network == "ws":
        proxy["ws-opts"] = {
            "path": q.get("path", ["/"])[0],
            "headers": {
                "Host": q.get("host", [""])[0]
            }
        }
    elif network == "grpc":
        proxy["grpc-opts"] = {
            "grpc-service-name": q.get("serviceName", [""])[0] or q.get("path", [""])[0]
        }

    if security == "reality":
        proxy["reality-opts"] = {
            "public-key": q.get("pbk", [""])[0],
            "short-id": q.get("sid", [""])[0]
        }

    return proxy


def _ss_plugin_opts(plugin_spec):
    """把 SIP002 的 plugin 串转换为 Mihomo 的 plugin / plugin-opts。

    SIP002 写法：``plugin=obfs-local;obfs=http;obfs-host=example.com``
    形如 ``name;key=value;flag``，flag 为空值的键视为布尔开关。
    """
    if not plugin_spec:
        return None, None
    parts = [part for part in plugin_spec.split(";") if part]
    plugin_name = parts[0]
    raw_opts = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            raw_opts[key.strip()] = value.strip()
        else:
            raw_opts[part.strip()] = True

    if plugin_name in ("obfs-local", "simple-obfs", "obfs"):
        opts = {}
        mode = raw_opts.get("obfs") or raw_opts.get("mode")
        if mode:
            opts["mode"] = mode
        host = raw_opts.get("obfs-host") or raw_opts.get("host")
        if host:
            opts["host"] = host
        return "obfs", opts or None

    if plugin_name == "v2ray-plugin":
        opts = {}
        mode = raw_opts.get("mode")
        if isinstance(mode, str) and mode:
            opts["mode"] = mode
        host = raw_opts.get("host")
        if isinstance(host, str) and host:
            opts["host"] = host
        path = raw_opts.get("path")
        if isinstance(path, str) and path:
            opts["path"] = path
        if raw_opts.get("tls") is True:
            opts["tls"] = True
        return "v2ray-plugin", opts or None

    logger.debug("不支持的 ss plugin: %s，忽略插件参数", plugin_name)
    return None, None


def decode_ss(link):
    """解析 ss 链接，同时兼容旧式整体 base64 与 SIP002 两种写法。

    旧式：``ss://base64(method:password@host:port)#name``
    SIP002：``ss://base64url(method:password)@host:port?plugin=...#name``

    原实现只支持旧式，遇到 SIP002 会直接返回 None，导致大量 ss 节点被丢弃。
    """
    raw = link[len("ss://"):] if link.startswith("ss://") else link

    name = "ss-node"
    if "#" in raw:
        raw, fragment = raw.split("#", 1)
        name = urllib.parse.unquote(fragment) or name

    query = ""
    if "?" in raw:
        raw, query = raw.split("?", 1)
    raw = raw.rstrip("/")
    q = urllib.parse.parse_qs(query)

    hostport = None
    if "@" in raw:
        # SIP002：userinfo 既可以是 base64url(method:password)，也允许直接写
        # 百分号编码的明文 method:password。base64 字母表不含 ":"，
        # 因此用是否含 ":" 即可无歧义地区分两种写法。
        userinfo, hostport = raw.rsplit("@", 1)
        if ":" in userinfo or "~" in userinfo:
            credentials = urllib.parse.unquote(userinfo)
        else:
            credentials = b64_decode_text(userinfo)
            if not credentials:
                logger.debug("ss 节点 userinfo 解码失败")
                return None
        decoded = credentials
    else:
        decoded = b64_decode_text(raw)
        if not decoded:
            logger.debug("ss 节点 base64 解码失败")
            return None

    # 先分离地址，再按第一个凭据分隔符拆分；口令中的 :、~、@ 都必须保留。
    try:
        if hostport is not None:
            credentials, server = decoded, hostport
        else:
            credentials, server = decoded.rsplit("@", 1)
        # 保留旧订阅的 method~password 兼容格式，标准 method:password 优先。
        method, password = re.split(r"[:~]", credentials, maxsplit=1)
        host, port = server.rsplit(":", 1)
        proxy = {
            "name": name,
            "type": "ss",
            "server": host.strip("[]"),
            "port": int(port),
            "cipher": method.strip(),
            "password": password,
        }
    except (ValueError, AttributeError) as e:
        logger.debug("ss 节点格式解析失败: %s", type(e).__name__)
        return None

    plugin, plugin_opts = _ss_plugin_opts(q.get("plugin", [""])[0])
    if plugin:
        proxy["plugin"] = plugin
        if plugin_opts:
            proxy["plugin-opts"] = plugin_opts

    return proxy


def decode_hysteria2(link):
    u = urllib.parse.urlparse(link)
    q = urllib.parse.parse_qs(u.query)

    # 必填字段保护：hostname/port/password 缺失时返回 None
    if not u.hostname or u.port is None or not u.username:
        return None

    return {
        "name": urllib.parse.unquote(u.fragment) or "hysteria2-node",
        "type": "hysteria2",
        "server": u.hostname,
        "port": u.port,
        "password": urllib.parse.unquote(u.username),
        "sni": q.get("sni", [""])[0],
        "skip-cert-verify": q.get("insecure", ["0"])[0] == "1"
    }


async def test_link_async(
        session: aiohttp.ClientSession,
        link: str,
        proxies: Optional[dict] = None,
        timeout: int = 10
) -> Tuple[str, bool, float, int]:
    """
    异步测试链接，返回 (链接, 是否成功, 延时秒数, 下载字节数)
    """
    start_time = time.perf_counter()
    downloaded_bytes = 0
    response_body = bytearray()
    try:
        async with session.get(
                link,
                proxy=proxies.get('http') if proxies else None,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True
        ) as response:
            # 限制读取量，避免测速下载完整网页或无限流响应。
            async for chunk in response.content.iter_chunked(8192):
                downloaded_bytes += len(chunk)
                if link == "https://chatgpt.com/api/auth/providers":
                    response_body.extend(chunk)
                if downloaded_bytes >= 1024 * 1024:
                    downloaded_bytes = 1024 * 1024
                    break
            elapsed = time.perf_counter() - start_time
            target_host = urllib.parse.urlparse(link).hostname
            final_host = response.url.host
            success = 200 <= response.status < 300 and (
                final_host == target_host or final_host.endswith("." + target_host)
            )
            if link in ("https://www.gstatic.com/generate_204", "https://www.google.com/generate_204"):
                success = success and response.status == 204
            if link == "https://speed.cloudflare.com/__down?bytes=1048576":
                success = success and downloaded_bytes == 1024 * 1024
            if success and link == "https://chatgpt.com/api/auth/providers":
                try:
                    providers = json.loads(response_body)
                    success = isinstance(providers, dict) and any(
                        isinstance(provider, dict) and provider.get("id") == "openai"
                        for provider in providers.values()
                    )
                except (ValueError, UnicodeDecodeError):
                    success = False
            return link, success, elapsed, downloaded_bytes
    except asyncio.TimeoutError:
        elapsed = time.perf_counter() - start_time
        logger.debug("link test timeout: %s", link)
        return link, False, elapsed, 0
    except Exception as e:
        elapsed = time.perf_counter() - start_time
        logger.debug("link test error: %s -> %s", link, e)
        return link, False, elapsed, 0


async def test_links_concurrent(
        links: List[str],
        proxies: Optional[dict] = None,
        timeout: int = 10,
        max_concurrent: int = 10
) -> List[Tuple[str, bool, float, int]]:
    """
    并发测试多个链接
    返回: [(链接, 是否成功, 延时秒数, 下载字节数), ...]
    """
    # 创建连接池
    max_concurrent = max(1, min(max_concurrent, 50))
    semaphore = asyncio.Semaphore(max_concurrent)
    connector = aiohttp.TCPConnector(limit=max_concurrent)

    async with aiohttp.ClientSession(
            connector=connector, trust_env=False) as session:
        async def limited_test(link):
            async with semaphore:
                return await test_link_async(session, link, proxies, timeout)

        tasks = [limited_test(link) for link in links]

        # 并发执行所有任务；return_exceptions=True 防止单个 task 异常导致其他 task 被 cancel
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        # 过滤掉异常结果（test_link_async 内部已捕获大部分异常，此处兜底）
        results = [r for r in raw_results if isinstance(r, tuple)]
        return list(results)


def test_proxy_alive(http_port, timeout=8):
    proxies = {
        "http": f"http://127.0.0.1:{http_port}",
        "https": f"http://127.0.0.1:{http_port}",
    }
    links = [
        "https://www.google.com",
        "https://tv.youtube.com/welcome",
        "https://github.com"
    ]

    logger.debug("开始并发测试链接（端口 %s）...", http_port)
    start_time = time.time()
    # 多线程并发调用test_link方法，并获取结果
    # 并发测试链接
    results = asyncio.run(test_links_concurrent(
        links=links,
        proxies=proxies,
        timeout=timeout,
        max_concurrent=5
    ))
    # 打印结果
    total_time = time.time() - start_time
    success_count = sum(1 for _, success, _, _ in results if success)
    logger.debug("连通性测试完成，端口 %s: 成功 %d/%d，总耗时 %.2f 秒", http_port, success_count, len(results), total_time)
    for link, success, elapsed, downloaded_bytes in results:
        speed_kbps = (downloaded_bytes * 8 / elapsed / 1000) if elapsed > 0 and downloaded_bytes > 0 else 0
        logger.debug("  %s | %.2fs | %.0fKB/s | %s", "OK" if success else "FAIL", elapsed, speed_kbps, link)
    return success_count == len(links)


def test_node_metrics(node, http_port, timeout=6):
    """
    测试单个节点的延时和网速，返回节点信息和性能指标
    （同步入口，内部调用 asyncio.run）
    """
    return asyncio.run(_test_node_metrics_async(node, http_port, timeout))


async def _test_node_metrics_async(node, http_port, timeout=6):
    """
    异步版本：测试单个节点的延时和网速。
    接收已有的 http_port，构建代理后并发请求 4 个测试目标。
    """
    timeout = max(timeout, 6)
    is_openvpn = node.get("type") == "openvpn"
    if is_openvpn:
        # Native OpenVPN and CFnew chains need time for the shared handshake.
        timeout = max(timeout, 35)
    proxies = {
        "http": f"http://127.0.0.1:{http_port}",
        "https": f"http://127.0.0.1:{http_port}",
    }

    # 定义测试链接（针对不同类型的服务）
    test_links = [
        ("google", "https://www.google.com/generate_204"),
        ("youtube", "https://www.youtube.com"),
        ("chatgpt", "https://chatgpt.com/api/auth/providers"),
        ("github", "https://github.com"),
    ]

    results = {
        "node": node,
        "google_latency": None,
        "youtube_latency": None,
        "chatgpt_latency": None,
        "github_latency": None,
        "google_speed_kbps": 0,
        "youtube_speed_kbps": 0,
        "chatgpt_speed_kbps": 0,
        "github_speed_kbps": 0,
        "avg_latency": None,
        "service_avg_latency": None,
        "avg_speed_kbps": 0,
        "health_check_passed": False,
        "download_passed": False,
        "is_available": False,
    }

    try:
        if is_openvpn:
            # Mihomo may return a short dial timeout while its independent
            # 30s OpenVPN handshake is still running. Keep this same node
            # selected and retry service probes within one 35s readiness budget.
            # The outer deadline also prevents aiohttp timeout rounding from
            # extending a late retry beyond the shared budget.
            deadline = monotonic() + 35
            service_urls = {url for service, url in test_links if service != "github"}
            raw_results = []
            while True:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
                try:
                    raw_results = await asyncio.wait_for(
                        test_links_concurrent([url for _, url in test_links], proxies,
                                              timeout=remaining, max_concurrent=5),
                        timeout=remaining,
                    )
                except asyncio.TimeoutError:
                    break
                if any(success and link in service_urls for link, success, _, _ in raw_results):
                    break
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
                # Failed HTTP dials may return immediately; avoid a busy loop.
                await asyncio.sleep(min(0.25, remaining))
        else:
            raw_results = await test_links_concurrent(
                [url for _, url in test_links],
                proxies,
                timeout=timeout,
                max_concurrent=5
            )

        # 防御：若上游 test_links_concurrent 因内部异常返回不足 4 项，记录并跳过
        if len(raw_results) != len(test_links):
            logger.debug("metrics raw_results 长度 %d != test_links %d，仅处理有效项",
                         len(raw_results), len(test_links))
        services_by_url = {url: service for service, url in test_links}
        for r in raw_results:
            link, success, elapsed, downloaded_bytes = r
            service = services_by_url[link]
            if success:
                speed_kbps = (downloaded_bytes * 8 / elapsed / 1000) if elapsed > 0 else 0
                results[f"{service}_latency"] = round(elapsed * 1000, 1)  # 转为毫秒
                results[f"{service}_speed_kbps"] = round(speed_kbps, 1)

        # 计算平均延时和速度
        latencies = [results[f"{s}_latency"] for s in ["google", "youtube", "chatgpt", "github"] if results.get(f"{s}_latency")]
        if latencies:
            results["service_avg_latency"] = round(sum(latencies) / len(latencies), 1)
        service_available = any(results.get(f"{s}_latency") is not None for s in ["google", "youtube", "chatgpt"])
        results["is_available"] = service_available
        if service_available:
            health_results = await test_links_concurrent(
                ["https://www.gstatic.com/generate_204"],
                proxies, timeout=timeout, max_concurrent=1
            )
            results["health_check_passed"] = any(success for _, success, _, _ in health_results)
            for _, success, elapsed, _ in health_results:
                if success:
                    results["avg_latency"] = round(elapsed * 1000, 1)
                    break
            if results["avg_latency"] is None:
                # Both endpoints are empty-body probes. A full page download is
                # not comparable latency evidence and must not be substituted.
                results["avg_latency"] = results["google_latency"]
        if service_available:
            # Acquire without blocking an event loop; concurrent workers share
            # one bulk-transfer slot. The request deadline excludes queue time.
            while not _DOWNLOAD_LOCK.acquire(blocking=False):
                await asyncio.sleep(0.05)
            try:
                speed_results = await test_links_concurrent(
                    ["https://speed.cloudflare.com/__down?bytes=1048576"],
                    proxies, timeout=timeout, max_concurrent=1
                )
            finally:
                _DOWNLOAD_LOCK.release()
            for _, success, elapsed, downloaded_bytes in speed_results:
                if success and elapsed > 0 and downloaded_bytes == 1024 * 1024:
                    results["download_passed"] = True
                    results["avg_speed_kbps"] = round(downloaded_bytes * 8 / elapsed / 1000, 1)

    except Exception as e:
        logger.warning("Metrics test error for %s: %s", node.get('name', 'unknown'), e)

    return results


def requires_tcp_probe(proxy):
    """Only a direct TCP dial is meaningful for these candidate transports."""
    return not ((proxy.get("dialer-proxy") and proxy.get(DEPENDENCIES_KEY))
                or str(proxy.get("type", "")).lower() in ("hysteria", "hysteria2", "tuic", "openvpn"))


async def test_proxy_telnet_async(proxy, timeout=5):
    """异步 TCP 连接测试，利用 Linux epoll 提高并发效率"""
    server = proxy.get("server", "")
    port = proxy.get("port")
    if not server or port is None:
        return None
    if not requires_tcp_probe(proxy):
        # These paths still require an actual protocol/service test afterwards.
        return proxy
    host = server.strip('[]')
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return proxy
    except Exception as e:
        logger.debug("TCP test failed: %s:%s - %s", server, port, e)
        return None


async def test_proxies_async(proxies, timeout=5, max_concurrent=200):
    """
    批量异步 TCP 测试，使用信号量限制并发数，避免大量节点时端口耗尽。
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def limited_test(proxy):
        async with semaphore:
            return await test_proxy_telnet_async(proxy, timeout=timeout)

    tasks = [limited_test(p) for p in proxies]
    # return_exceptions=True：单个节点抛出非 Exception 异常（如 CancelledError）时
    # 不会连带取消其余全部探测任务
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)
    results = []
    for proxy, result in zip(proxies, raw_results):
        if isinstance(result, BaseException):
            logger.debug("TCP 测试异常（%s）: %s", proxy.get("name", "?"), result)
            continue
        if result is not None:
            results.append(result)
    return results


class _ProbeAudit:
    """Only aggregate stages/reasons; never store proxy credentials or core logs."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counts = Counter()

    def record(self, nodes, phase, reason):
        with self._lock:
            for node in nodes:
                for source in proxy_source_ids(node):
                    self._counts[(source, phase, reason)] += 1

    def snapshot(self):
        with self._lock:
            return [{"source": source, "phase": phase, "reason": reason, "count": count}
                    for (source, phase, reason), count in sorted(self._counts.items())]


def _test_batch_nodes(batch_proxies, dirs, timeout, worker_id, inspector=None,
                      mode="full", policy=None, audit=None):
    """批量测试：一个 Clash 实例同时测试多个节点，并记录性能指标"""
    # 端口不能写死：用户本机开着代理客户端时 7890/7891/9090 基本都被占用，
    # 采集实例绑定失败会让整批节点测试直接作废（表现为 0 个可用节点）。
    # 每个 worker 分配一段互不重叠的端口窗口，避免并行实例互相抢端口。
    window_start = _WORKER_PORT_BASE + worker_id * 20
    window_stop = window_start + 20
    http_port, socks_port = find_free_port_block(
        size=2, start=window_start, stop=window_start + 10, step=1)
    # mixed（HTTP 与 SOCKS 共用）之外的 controller 需要单独一段
    controller_port, _ = find_free_port_block(
        size=1, start=window_start + 10, stop=window_stop, step=1)
    if http_port is None or controller_port is None:
        logger.error("worker %d 找不到空闲端口，跳过该批次", worker_id)
        if audit:
            audit.record(batch_proxies, mode, "ports_unavailable")
        return []
    config_name = f"clash_test_{worker_id}.yaml"
    log_name = f"clash_test_{worker_id}.log"
    config_path = os.path.join(dirs, config_name)
    log_path = os.path.join(dirs, log_name)

    manager = ClashMetaManager(
        'base_template.yaml',
        config_name,
        controller_port=controller_port,
        http_port=http_port,
        socks_port=socks_port,
        log_file=log_path,
    )

    metrics_results = []
    started = False
    split_failed_batch = False
    policy = policy or load_node_policy()

    try:
        manager.write_config(batch_proxies, output_path=config_path)
        manager.start(config_path=config_path)
        started = True

        # 对每个节点：先通过 Clash API 切换到该节点，再测性能
        for node in batch_proxies:
            node_name = node.get("name", "unknown")
            # 切换到当前测试的节点（必须，否则测的是默认选中节点）
            if not manager.switch_proxy(node_name):
                logger.warning("切换代理 %s 失败，跳过", node_name)
                if audit:
                    audit.record([node], mode, "switch_failed")
                continue

            node_metrics = test_node_metrics(node, http_port, timeout)
            if node_metrics["is_available"]:
                # 复制节点，避免修改调用方传入的原始字典
                proxy_copy = dict(node)
                # 清理节点名称中的 Unicode 编码
                proxy_copy["name"] = decode_unicode_name(proxy_copy.get("name", ""))
                # 附加性能指标（仅在有有效数据时写入，避免 None 导致排序崩溃）
                proxy_copy["_latency"] = node_metrics["avg_latency"]
                proxy_copy["_speed_kbps"] = node_metrics["avg_speed_kbps"]
                proxy_copy["_download_passed"] = node_metrics.get("download_passed") is True
                proxy_copy["_service_latency_ms"] = {
                    service: node_metrics.get(f"{service}_latency")
                    for service in ("google", "youtube", "chatgpt", "github")
                }
                proxy_copy["_categories"] = {
                    service for service in ("google", "youtube", "chatgpt")
                    if node_metrics[f"{service}_latency"] is not None
                }
                if mode == "verify":
                    # Only services working on both passes receive group access.
                    proxy_copy["_categories"].intersection_update(node.get("_categories", ()))
                eligible = meets_performance_floor(proxy_copy, policy) and bool(proxy_copy["_categories"])
                proxy_copy["_exit_quality"] = unknown("awaiting_inspection" if eligible else "performance_floor")
                if mode == "verify":
                    proxy_copy["_verification"] = "passed" if eligible else "failed"
                elif mode == "measure":
                    proxy_copy["_verification"] = "pending"
                # TEST still points at this exact node, including its dialer chain.
                if mode == "full" or (mode == "verify" and eligible):
                    try:
                        inspector = inspector or ExitInspector(policy)
                        proxy_copy["_exit_quality"] = inspector.inspect(http_port)
                    except Exception as error:
                        logger.warning("出口属性查询失败（%s），保留服务实测结果", type(error).__name__)
                        proxy_copy["_exit_quality"] = unknown("lookup_failed")
                if audit and not eligible:
                    audit.record([node], mode, "performance_floor")
                metrics_results.append(proxy_copy)
                logger.debug("  -> %s: OK (延迟: %sms, 速度: %.0fkbit/s)",
                             proxy_copy["name"], node_metrics["avg_latency"], node_metrics["avg_speed_kbps"])
            else:
                logger.debug("  -> %s: FAIL", node.get("name", "unknown"))
                if audit:
                    audit.record([node], mode, "service_failed")
    except Exception as e:
        logger.error("Batch test failed (worker_id=%d): %s", worker_id, type(e).__name__)
        # A malformed proxy must not invalidate the other 19 candidates. Only
        # retry early parse/exit errors; timeouts and missing binaries are global.
        split_failed_batch = (not started and len(batch_proxies) > 1
                              and isinstance(e, (ValueError, RuntimeError)))
        if audit:
            audit.record(batch_proxies, mode, "batch_split" if split_failed_batch else
                         "batch_start_failed" if not started else "batch_runtime_failed")
    finally:
        manager.stop()
        for path in (config_path, log_path):
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass
    if split_failed_batch:
        middle = len(batch_proxies) // 2
        for part in (batch_proxies[:middle], batch_proxies[middle:]):
            metrics_results.extend(_test_batch_nodes(
                part, dirs, timeout, worker_id, inspector, mode, policy, audit))
    return metrics_results


def sort_proxies_by_performance(proxies, policy=None):
    """Rank quality tiers first, then latency and download speed within each tier."""
    return rank_proxies(proxies or [], policy)


def _run_probe_batches(proxies, dirs, timeout, inspector, policy, audit, mode, workers):
    if not proxies:
        return []
    batches = [proxies[i:i + 20] for i in range(0, len(proxies), 20)]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(batches))) as executor:
        future_map = {
            executor.submit(_test_batch_nodes, batch, dirs, timeout, worker_id,
                            inspector, mode, policy, audit): (worker_id, batch)
            for worker_id, batch in enumerate(batches)
        }
        completed = 0
        for future in concurrent.futures.as_completed(future_map):
            worker_id, batch = future_map[future]
            completed += len(batch)
            try:
                results.extend(future.result())
            except Exception as error:
                audit.record(batch, mode, "worker_failed")
                logger.error("Batch test error (worker_id=%d): %s", worker_id, type(error).__name__)
            logger.info("%s 已测试 %d/%d 个节点，服务可用: %d（worker_id=%d）",
                        mode, completed, len(proxies), len(results), worker_id)
    return results


def _stage_counts(proxies):
    return stage_counts(proxies)


def test_nodes(proxies, env, dirs, timeout=6, diagnostics=None):
    """
    批量测试节点，并发启动多个 Clash 实例。

    多 Worker 设计说明：
    - 将节点按 batch_size 分批，每批内的所有节点由 1 个 Clash 实例（1 个 worker）处理
    - 不同批次之间并行执行（最多 worker_count 个 Clash 实例同时运行）
    - 每个 worker 在互不重叠的端口窗口内动态申请空闲端口
      （窗口 = _WORKER_PORT_BASE + worker_id * 20），避免互抢端口；
      不能写死 7890/7891/9090，本机代理客户端通常已占用这些端口
    - 同一批内所有节点共享同一个 Clash 实例，通过 proxy-groups 切换测试
    """
    policy = load_node_policy(profile=env)
    inspector = ExitInspector(policy, profile=env)
    diagnostics = dict(diagnostics or {})
    diagnostics["profile"] = env
    stages = diagnostics.setdefault("stage_counts", {})
    stages["test_input"] = _stage_counts(proxies)
    audit = _ProbeAudit()
    status = inspector.capabilities()
    if status["enabled"] and not status["available"]:
        logger.warning("家宽识别模式已自动开启，但未配置 IPAPI_IS_KEY 或 config/exit_quality.yaml；"
                       "本轮仅检测低风险，家宽属性保持未知")
    logger.info("节点性能门槛：完整下载 >= %.0f kbit/s，204 响应耗时 <= %.0fms",
                policy.min_speed_kbps, policy.max_latency_ms)
    if not proxies:
        write_selection_report([], [], policy, dirs, diagnostics=diagnostics, inspection=status)
        return []

    if any(proxy.get("type") == "openvpn" for proxy in proxies) and not supports_openvpn():
        logger.warning("跳过 OpenVPN 候选：完整配置字段需要 Mihomo >= 1.19.30；请查看 openvpn_runtime 诊断或设置 MIHOMO_BINARY")
        audit.record([proxy for proxy in proxies if proxy.get("type") == "openvpn"],
                     "measure", "unsupported_core")
        proxies = [proxy for proxy in proxies if proxy.get("type") != "openvpn"]
        if not proxies:
            diagnostics["probe_failures"] = audit.snapshot()
            write_selection_report([], [], policy, dirs, diagnostics=diagnostics, inspection=status)
            return []

    # Match runtime/export normalization so switch_proxy uses the actual name,
    # including when callers supply duplicate RSS/CF routes directly.
    proxies = _normalize_proxies([
        dict(proxy, name=decode_unicode_name(proxy.get("name", "")) or "proxy")
        for proxy in proxies
    ])

    logger.info("开始批量测试节点（并发启动多个 Clash 实例）...")
    start_time = time.time()

    mode = "measure" if env == "prod" else "full"
    results = _run_probe_batches(proxies, dirs, timeout, inspector, policy, audit,
                                mode, 4 if env == "prod" else 8)
    stages["service_passed"] = _stage_counts(results)
    stages["performance_passed"] = _stage_counts([
        p for p in results if meets_performance_floor(p, policy)])
    measured_results = results
    if env == "prod":
        for proxy in measured_results:
            proxy["_verification"] = "not_selected"
            proxy["_exit_quality"] = unknown("round_lookup_budget" if meets_performance_floor(proxy, policy)
                                            else "performance_floor")
        remaining = list(results)
        attempted = []
        verified = []
        results = []
        while remaining and len(results) < policy.max_lookups_per_round:
            candidates = select_inspection_candidates(
                remaining, policy.max_lookups_per_round - len(results), policy)
            if not candidates:
                break
            candidate_names = {p["name"] for p in candidates}
            remaining = [p for p in remaining if p["name"] not in candidate_names]
            attempted.extend(candidates)
            for proxy in candidates:
                proxy["_verification"] = "failed"
                proxy["_exit_quality"] = unknown("verification_failed")
            logger.info("prod 复测性能最优候选 %d 个，再查询出口；未复测通过的候选不导出", len(candidates))
            wave = _run_probe_batches(candidates, dirs, timeout, inspector, policy, audit, "verify", 4)
            verified.extend(wave)
            results.extend(p for p in wave if p.get("_verification") == "passed")
            # Failed rechecks did not spend an exit lookup. Fill those slots
            # from the next qualified candidates instead of wasting the budget.
        replacements = {p["name"]: p for p in verified}
        measured_results = [replacements.get(p["name"], p) for p in measured_results]
        stages["verification_candidates"] = _stage_counts(attempted)
        stages["verification_passed"] = _stage_counts(results)
        stages["exit_checked"] = _stage_counts(results)

    total_time = time.time() - start_time
    logger.info("批量测试完成，总耗时: %.2f 秒", total_time)
    logger.info("成功节点: %d/%d", len(results), len(proxies))

    # 每个服务分别选择最优的可用等级，再在等级内按性能排序。
    if results:
        results = select_export_proxies(rank_proxies(results, policy), policy=policy)
        for tier, label in TIER_LABELS.items():
            logger.info("%s：实测 %d，保留 %d", label,
                        sum(quality_tier(p, policy) == tier for p in measured_results),
                        sum(quality_tier(p, policy) == tier for p in results))
    stages["selected"] = _stage_counts(results)
    diagnostics["probe_failures"] = audit.snapshot()
    write_selection_report(measured_results, results, policy, dirs,
                           diagnostics=diagnostics, inspection=inspector.capabilities())

    if results:
        manager = ClashMetaManager('base_template.yaml', 'test_config.yaml')
        if env != "dev":
            manager.save_config(results, os.path.join(dirs, "clash.yaml"), policy=policy)
        else:
            # dev 模式不覆盖投放文件，但必须刷新 clash/proxy_generated.yaml：
            # 下次启动要靠它借上次的有效节点访问被墙的订阅源。
            # 不刷新的话缓存永远停在占位配置上，本地反复运行也只能直连。
            manager.save_config(results, os.path.join(dirs, "clash.yaml"),
                                mirror_only=True, policy=policy)
            logger.warning(
                "当前为 dev 环境，未写入 %s；已刷新采集缓存，如需导出请使用 -p prod",
                os.path.join(dirs, "clash.yaml"),
            )
    elif env == "prod":
        logger.warning("本轮没有通过性能与复测要求的节点，未生成新 clash.yaml；"
                       "若目录已有旧文件，它不代表本轮结果，请查看 node_selection_report.json")

    return results


def _decode_v2ray_subscription(content):
    """接受明文 URI 列表或 Base64 编码的 URI 列表。"""
    if not content:
        return None

    supported_schemes = ("vless://", "ss://", "vmess://", "hysteria2://")
    if any(line.strip().lstrip("\ufeff").startswith(supported_schemes)
           for line in content.splitlines()):
        return content

    return b64_decode_text(content)


def v2ray_2_clash(file_path=None, content=None):
    nodes = None
    if file_path and os.path.exists(file_path):
        # 每行是一个 base64 编码的订阅内容，需全部解码后拼接
        decoded_lines = []
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                if not line:
                    continue
                txt = _decode_v2ray_subscription(line.strip())
                if txt:
                    decoded_lines.append(txt)
        if decoded_lines:
            nodes = "\n".join(decoded_lines)
    elif content:
        nodes = _decode_v2ray_subscription(content)
    proxies = []
    name_list = {}  # name -> 出现次数（从1开始）
    if nodes:
        for node in nodes.splitlines():
            node = node.strip().lstrip("\ufeff")
            try:
                proxy = None
                if node.startswith("vless://"):
                    proxy = decode_vless(node)
                elif node.startswith("ss://"):
                    proxy = decode_ss(node)
                elif node.startswith("vmess://"):
                    proxy = decode_vmess(node)
                elif node.startswith("hysteria2://"):
                    proxy = decode_hysteria2(node)
                if proxy:
                    original_name = proxy["name"]
                    if original_name not in name_list:
                        name_list[original_name] = 1
                    else:
                        # 追加后缀使名字唯一，计数基于原始名字
                        name_list[original_name] += 1
                        proxy["name"] = f"{original_name}-{name_list[original_name]}"
                    proxies.append(proxy)
            except Exception as e:
                logger.debug("解析节点失败: %s", type(e).__name__)
    # if proxies:
    #     proxies = test_nodes(proxies)
    # print(proxies)
    return proxies


def _is_dialable_host(server):
    """判断 server 是否是内核能够拨号的合法主机名或 IP。

    真实订阅里出现过 ``server: "@@168.126.234.247"`` 这类脏数据（ss 口令里带
    "@"，被错误切分后残留到地址段）。这种节点能通过 YAML 校验，但内核在
    拨号期只会报 DNS 解析失败，用户看到的现象就是"分组里的节点无法使用"。
    """
    host = str(server or "").strip()
    if not host:
        return False
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    # 主机名只允许字母、数字、连字符、点和下划线；IPv6 额外允许冒号。
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:")
    if any(char not in allowed for char in host):
        return False
    # 不允许以连字符/点开头结尾，也不允许出现连续的点
    if host[0] in "-." or host[-1] in "-." or ".." in host:
        return False
    return True


def filter_proxies(proxies):
    if not proxies:
        return []
    candidates = []
    for proxy in proxies:
        if not isinstance(proxy, dict):
            logger.debug("订阅节点不是对象，跳过: %r", proxy)
            continue
        port = proxy.get("port")
        if isinstance(port, bool):
            port = None
        elif isinstance(port, str) and port.isdecimal():
            try:
                port = int(port)
            except ValueError:
                port = None
        if not isinstance(port, int) or not 1 <= port <= 65535:
            logger.debug("节点端口无效，丢弃: %s (%r)", proxy.get("name", "?"), proxy.get("port"))
            continue
        # 必填字段缺失的节点直接丢弃
        if proxy.get("server") is None or proxy.get("type") is None:
            logger.debug("节点缺少必填字段（server/port/type），丢弃: %s", proxy.get("name", "?"))
            continue
        # 地址段含非法字符（如 "@@1.2.3.4"）时内核无法解析，直接丢弃
        if not _is_dialable_host(proxy.get("server")):
            logger.warning("节点 server 不是合法主机名，丢弃: %s (%r)",
                           proxy.get("name", "?"), proxy.get("server"))
            continue
        # 用浅拷贝避免修改调用方的原始 dict，同时清理名称中的 Unicode 编码
        proxy_copy = dict(proxy)
        proxy_copy["port"] = port
        proxy_copy["name"] = decode_unicode_name(proxy_copy.get("name", ""))
        candidates.append(proxy_copy)

    # 去重键必须覆盖节点全部有效字段。
    # 原实现用 (server, port, type, cipher, uuid) 作为键，会把下列互不相同的节点误判为重复：
    #   - ss 同 host:port:cipher 但 password 不同
    #   - trojan / hysteria2 同 host:port 但 password 不同
    #   - vless 同 host:port:uuid 但 ws-opts 路径、network(tcp/grpc)、sni、alpn 不同
    # 这类节点在本函数中被丢弃后就再也无法进入后续测速环节，属于静默丢节点。
    # _normalize_proxies 用「除 name 外全部字段的 JSON」作为身份，并负责名称去重。
    return _normalize_proxies(candidates)


def clean_yaml_content(content):
    # 修复名称中异常的引号（如 "🇫🇷FR-"2001:bc8:32d7:302::10"-090" 这类格式）
    content = re.sub(r'(name: )"([^"]+)"([^,}]+)', r'\1\2\3', content)
    # 修复换行导致的语法错误
    content = re.sub(r',\s*\n\s+tls:', r', tls:', content)
    return content


def parse_proxy_line(line):
    """
    最终版代理行修复函数（仅做语法清理，不负责解析）
    核心：只做必要的格式修复，将解析逻辑完全剥离
    """
    # 1. 基础清理：合并换行、移除空白、清理多余符号
    line = line.strip().replace("\n", "").replace("\r", "").replace("\t", " ").replace("。", "")

    # 2. 修复name字段异常引号（IPv6+emoji场景）
    line = re.sub(r'(name:\s*)([^,}]+)"([^,}]+)', r'\1\2\3', line)  # 移除孤立引号
    line = re.sub(r'(name:\s*)"([^,}]+)"', r'\1\2', line)  # 移除首尾引号

    # 3. 标准化IPv6地址（仅清理，不添加引号，避免JSON冲突）
    line = re.sub(r'(server:\s*)"([0-9a-fA-F:]+)"', r'\1\2', line)  # 移除IPv6多余引号
    line = re.sub(r'(Host:\s*)"([0-9a-fA-F:]+)"', r'\1\2', line)  # ws-headers内IPv6

    # 4. 补全语法闭合符（解决<stream end>报错）
    open_brace = line.count("{")
    close_brace = line.count("}")
    if open_brace > close_brace:
        line += "}" * (open_brace - close_brace)

    # 5. 清理特殊字段的多余符号
    line = re.sub(r',\s*}', r'}', line)  # 移除末尾多余逗号
    line = re.sub(r'\s+', ' ', line)  # 合并多空格

    return line


def parse_single_proxy(line):
    """
    终极解析方案：放弃JSON/YAML整体解析，手动拆分字段构建字典
    优点：完全规避语法报错，兼容所有异常格式
    """
    # 第一步：基础修复
    fixed_line = parse_proxy_line(line)
    # 去掉行首的 "- " 和首尾的 {}
    fixed_line = fixed_line.lstrip('- ').strip('{}').strip()

    # 第二步：拆分字段（核心逻辑：处理嵌套字典ws-headers）
    proxy_dict = {}
    # 匹配嵌套字典 ws-headers: {Host: xxx}
    ws_headers_match = re.search(r'ws-headers:\s*\{([^}]+)\}', fixed_line)
    if ws_headers_match:
        # 提取并解析ws-headers
        ws_headers_str = ws_headers_match.group(1).strip()
        ws_headers = {}
        for h_item in ws_headers_str.split(','):
            if ':' in h_item:
                h_key, h_val = h_item.split(':', 1)
                ws_headers[h_key.strip()] = h_val.strip()
        proxy_dict['ws-headers'] = ws_headers
        # 从原行中移除ws-headers字段（避免重复解析）
        fixed_line = fixed_line.replace(ws_headers_match.group(0), '')

    # 第三步：拆分剩余普通字段
    # 按逗号拆分（排除ws-headers内的逗号）
    fields = re.split(r',\s*(?![^{}]*\})', fixed_line)
    for field in fields:
        field = field.strip()
        if not field or ':' not in field:
            continue
        # 拆分键值对（只按第一个冒号拆分，兼容值含冒号的场景如ws-path）
        key, value = field.split(':', 1)
        key = key.strip()
        value = value.strip()

        # 第四步：值类型转换（还原原始类型）
        if value.lower() == 'true':
            proxy_dict[key] = True
        elif value.lower() == 'false':
            proxy_dict[key] = False
        elif value.isdigit():
            proxy_dict[key] = int(value)
        elif value.startswith('"') and value.endswith('"'):
            proxy_dict[key] = value.strip('"')  # 移除值的引号
        else:
            proxy_dict[key] = value  # 保留原始字符串

    return proxy_dict if proxy_dict else None


def parse_special_clash(content):
    """解析 YAML 文件中的 proxies 列表，兼容不规则格式"""
    proxies = []

    # 1. 提取 proxies 下的所有代理条目行
    proxies_block = re.search(r"proxies:\s*(.*?)(?=\n\w+:|\Z)", content, re.DOTALL)
    if not proxies_block:
        return proxies

    # 2. 拆分每行代理条目（处理换行/空格问题）
    lines = re.findall(r"- \{.*?\}", proxies_block.group(1), re.DOTALL)

    # 3. 逐行修复并解析
    merged_lines = []
    current_line = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- {"):
            # 新条目：先处理上一条
            if current_line:
                merged_lines.append(current_line)
            current_line = stripped
        else:
            # 续行：合并到当前条目
            current_line += stripped

    # 加入最后一条
    if current_line:
        merged_lines.append(current_line)

    # 3. 逐行修复并解析
    for idx, line in enumerate(merged_lines):
        proxy = parse_single_proxy(line)
        if proxy:
            proxies.append(proxy)
        else:
            logger.debug("第%d行解析失败（内容为空）", idx + 1)

    return proxies


# 解决SSL协议兼容问题的适配器
class SSLAdapter(HTTPAdapter):
    """强制 TLSv1.2+ 的 requests HTTPAdapter。

    原实现自己 new 了 PoolManager 且没有把 **pool_kwargs 传下去，也绕过了父类
    初始化，requests 在新版本里传入的 pool 参数会被静默忽略；另外
    ``ssl.OP_NO_TLSv1`` 系列在 Python 3.10+ 已废弃，改用 minimum_version 更稳妥。
    """

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        pool_kwargs["ssl_context"] = context
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        proxy_kwargs["ssl_context"] = context
        return super().proxy_manager_for(proxy, **proxy_kwargs)
