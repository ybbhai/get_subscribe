import asyncio
import base64
import concurrent.futures
import json
import logging
import os
import re
import socket
import ssl
import time
import urllib.parse
from typing import Optional, Tuple, List, Any

import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager

from utils.clash_manager import ClashMetaManager

logger = logging.getLogger(__name__)




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
    data = base64.b64decode(raw + "==").decode()
    obj = json.loads(data)

    # 字段缺失保护：add/port/id 为必填字段，缺失时直接跳过该节点
    if "add" not in obj or "port" not in obj or "id" not in obj:
        return None

    proxy = {
        "name": obj.get("ps", "vmess-node"),
        "type": "vmess",
        "server": obj["add"],
        "port": int(obj["port"]),
        "uuid": obj["id"],
        "alterId": int(obj.get("aid", 0)),
        "cipher": obj.get("scy", "auto"),
        "network": obj.get("net", "tcp"),
        "tls": obj.get("tls") == "tls",
    }

    if obj.get("net") == "ws":
        proxy["ws-opts"] = {
            "path": obj.get("path", "/"),
            "headers": {"Host": obj.get("host", "")}
        }

    return proxy


def decode_vless(link):
    u = urllib.parse.urlparse(link)
    q = urllib.parse.parse_qs(u.query)

    # 必填字段保护：hostname 或 port 缺失时返回 None
    if not u.hostname or u.port is None:
        return None

    proxy = {
        "name": urllib.parse.unquote(u.fragment) or "vless-node",
        "type": "vless",
        "server": u.hostname,
        "port": u.port,
        "uuid": u.username,
        "network": q.get("type", ["tcp"])[0],
        "tls": q.get("security", ["none"])[0] == "tls",
    }

    if "flow" in q:
        proxy["flow"] = q["flow"][0]

    if proxy["network"] == "ws":
        proxy["ws-opts"] = {
            "path": q.get("path", ["/"])[0],
            "headers": {
                "Host": q.get("host", [""])[0]
            }
        }

    if "sni" in q:
        proxy["servername"] = q["sni"][0]

    if q.get("security", [""])[0] == "reality":
        proxy["reality-opts"] = {
            "public-key": q.get("pbk", [""])[0],
            "short-id": q.get("sid", [""])[0]
        }

    return proxy


def decode_ss(link):
    raw = link.replace("ss://", "")
    if "#" in raw:
        raw, name = raw.split("#", 1)
        name = urllib.parse.unquote(name)
    else:
        name = "ss-node"

    try:
        decoded = base64.b64decode(raw + "==").decode()
    except Exception as e:
        logger.debug("ss 节点 base64 解码失败: %s... %s", link[:40], e)
        return None

    # 标准格式：method:password@host:port；新规范：method~password@host:port（~ 开头是加密口令）
    try:
        if "~" in decoded:
            method, rest = decoded.split("~", 1)
            password, server = rest.split("@", 1)
        else:
            method, rest = decoded.split(":", 1)
            password, server = rest.split("@", 1)
        host, port = server.rsplit(":", 1)
        return {
            "name": name,
            "type": "ss",
            "server": host,
            "port": int(port),
            "cipher": method,
            "password": password
        }
    except (ValueError, AttributeError) as e:
        logger.debug("ss 节点格式解析失败: %s... %s", link[:40], e)
        return None


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
        "password": u.username,
        "sni": q.get("sni", [""])[0],
        "skip-cert-verify": q.get("insecure", ["0"])[0] == "1"
    }


def test_link(link, proxies, timeout=10):
    try:
        r = requests.get(
            link,
            proxies=proxies,
            timeout=timeout,
        )
        logger.debug("test success: %s -> %s", link, r.status_code)
        return True
    except Exception as e:
        logger.debug("test failed: %s -> %s", link, e)
        return False


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

    async with aiohttp.ClientSession(connector=connector) as session:
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
    proxies = {
        "http": f"http://127.0.0.1:{http_port}",
        "https": f"http://127.0.0.1:{http_port}",
    }

    # 定义测试链接（针对不同类型的服务）
    test_links = [
        ("google", "https://www.google.com"),
        ("youtube", "https://www.youtube.com"),
        ("chatgpt", "https://chatgpt.com"),
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
        "avg_speed_kbps": 0,
        "is_available": False,
    }

    try:
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

        if results["chatgpt_latency"] is None:
            auth_results = await test_links_concurrent(
                ["https://chatgpt.com/api/auth/providers"],
                proxies, timeout=timeout, max_concurrent=1
            )
            for _, success, elapsed, downloaded_bytes in auth_results:
                if success:
                    results["chatgpt_latency"] = round(elapsed * 1000, 1)
                    results["chatgpt_speed_kbps"] = round(
                        downloaded_bytes * 8 / elapsed / 1000, 1) if elapsed > 0 else 0

        # 计算平均延时和速度
        latencies = [results[f"{s}_latency"] for s in ["google", "youtube", "chatgpt", "github"] if results.get(f"{s}_latency")]
        if latencies:
            results["avg_latency"] = round(sum(latencies) / len(latencies), 1)
        results["is_available"] = any(results.get(f"{s}_latency") is not None for s in ["google", "youtube", "chatgpt"])
        if results["is_available"]:
            speed_results = await test_links_concurrent(
                ["https://speed.cloudflare.com/__down?bytes=1048576"],
                proxies, timeout=timeout, max_concurrent=1
            )
            for _, success, elapsed, downloaded_bytes in speed_results:
                if success and elapsed > 0:
                    results["avg_speed_kbps"] = round(downloaded_bytes * 8 / elapsed / 1000, 1)

    except Exception as e:
        logger.warning("Metrics test error for %s: %s", node.get('name', 'unknown'), e)

    return results


async def test_proxy_telnet_async(proxy, timeout=5):
    """异步 TCP 连接测试，利用 Linux epoll 提高并发效率"""
    server = proxy.get("server", "")
    port = proxy.get("port")
    if not server or port is None:
        return None
    # IPv6 裸字面量需加方括号，否则 asyncio.open_connection 解析失败
    if ':' in server and not server.startswith('['):
        host = f"[{server}]"
    else:
        host = server
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
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


async def _test_single_node(node, env, dirs, timeout, worker_id):
    http_port = 7900 + worker_id * 10
    socks_port = http_port + 1
    controller_port = 9090 + worker_id
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

    try:
        manager.write_config([node], env=env, output_path=config_path)
        manager.start(config_path=config_path)
        alive = test_proxy_alive(http_port, timeout=timeout)
        return node if alive else None
    except Exception as e:
        logger.error("Single node test failed for %s: %s", node.get('name', 'unknown'), e)
        return None
    finally:
        manager.stop()
        for path in (config_path, log_path):
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass


def _test_batch_nodes(batch_proxies, env, dirs, timeout, worker_id):
    """批量测试：一个 Clash 实例同时测试多个节点，并记录性能指标"""
    http_port = 7900 + worker_id * 10
    socks_port = http_port + 1
    controller_port = 9090 + worker_id
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

    try:
        manager.write_config(batch_proxies, env=env, output_path=config_path)
        manager.start(config_path=config_path)

        # 对每个节点：先通过 Clash API 切换到该节点，再测性能
        for node in batch_proxies:
            node_name = node.get("name", "unknown")
            # 切换到当前测试的节点（必须，否则测的是默认选中节点）
            if not manager.switch_proxy(node_name):
                logger.warning("切换代理 %s 失败，跳过", node_name)
                continue

            node_metrics = test_node_metrics(node, http_port, timeout)
            if node_metrics["is_available"]:
                # 复制节点，避免修改调用方传入的原始字典
                proxy_copy = dict(node)
                # 清理节点名称中的 Unicode 编码
                proxy_copy["name"] = decode_unicode_name(proxy_copy.get("name", ""))
                # 附加性能指标（仅在有有效数据时写入，避免 None 导致排序崩溃）
                if node_metrics["avg_latency"] is not None:
                    proxy_copy["_latency"] = node_metrics["avg_latency"]
                proxy_copy["_speed_kbps"] = node_metrics["avg_speed_kbps"]
                proxy_copy["_categories"] = {
                    service for service in ("google", "youtube", "chatgpt")
                    if node_metrics[f"{service}_latency"] is not None
                }
                metrics_results.append(proxy_copy)
                logger.debug("  -> %s: OK (延迟: %sms, 速度: %.0fkbit/s)",
                             proxy_copy["name"], node_metrics["avg_latency"], node_metrics["avg_speed_kbps"])
            else:
                logger.debug("  -> %s: FAIL", node.get("name", "unknown"))

        return metrics_results
    except Exception as e:
        logger.error("Batch test failed (worker_id=%d): %s", worker_id, e)
        return []
    finally:
        manager.stop()
        for path in (config_path, log_path):
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass


def sort_proxies_by_performance(proxies):
    """
    根据性能指标对节点进行排序
    优先选择延迟低、速度快的节点
    同时考虑节点的服务类别匹配
    """
    if not proxies:
        return []

    def proxy_sort_key(proxy):
        # 获取性能指标，默认值表示无数据
        latency = proxy.get("_latency")
        speed = proxy.get("_speed_kbps", 0) or 0
        categories = proxy.get("_categories", set())

        # 没有有效延迟数据，排在最后
        if latency is None:
            return (float("inf"), 0, 0)

        # 评分：低延迟和高速度都有益
        # 延迟权重更高（0.7），速度权重较低（0.3）
        latency_score = 1000 / (latency + 1)  # 防止除零
        speed_score = min(speed / 100, 100)  # 归一化到 0-100

        # 综合评分（越大越好：低延迟 + 高速度）
        total_score = latency_score * 0.7 + speed_score * 0.3

        # 特殊服务加分（类别越多越优先）
        category_bonus = len(categories) * 5

        # 排序键（升序，键越小越靠前）：
        # -total_score   → 总评分越高越靠前
        # -category_bonus→ 匹配类别越多越靠前
        # latency        → 延迟越低越靠前（最终 tie-breaker）
        return (-total_score, -category_bonus, latency)

    # 按评分排序
    sorted_proxies = sorted(proxies, key=proxy_sort_key)

    return sorted_proxies


def test_nodes(proxies, env, dirs, timeout=6):
    """
    批量测试节点，并发启动多个 Clash 实例。

    多 Worker 设计说明：
    - 将节点按 batch_size 分批，每批内的所有节点由 1 个 Clash 实例（1 个 worker）处理
    - 不同批次之间并行执行（最多 worker_count 个 Clash 实例同时运行）
    - 每个 worker 使用独立端口（http_port = 7900 + worker_id * 10），互不干扰
    - 同一批内所有节点共享同一个 Clash 实例，通过 proxy-groups 切换测试
    """
    if not proxies:
        return []

    # Clash 要求代理名称唯一；解码后再分配名称，避免转义名称产生碰撞。
    used_names = set()
    name_counts = {}
    normalized_proxies = []
    for proxy in proxies:
        proxy_copy = dict(proxy)
        base_name = decode_unicode_name(proxy_copy.get("name", "")) or "proxy"
        name = base_name
        suffix = name_counts.get(base_name, 1)
        while name in used_names:
            name = f"{base_name}-{suffix}"
            suffix += 1
        name_counts[base_name] = suffix
        used_names.add(name)
        proxy_copy["name"] = name
        normalized_proxies.append(proxy_copy)
    proxies = normalized_proxies

    logger.info("开始批量测试节点（并发启动多个 Clash 实例）...")
    start_time = time.time()

    # 每批测试数量（一个 Clash 实例可同时处理多个节点）
    batch_size = 20

    # 将节点均分为多个 batch
    batches = [proxies[i:i + batch_size] for i in range(0, len(proxies), batch_size)]
    # 最大并发 worker 数 = 实际 batch 数（不超过 8）
    worker_count = min(8, len(batches))
    results = []

    # 使用线程池并发处理各 batch，每个 batch 对应 1 个 worker（1 个 Clash 实例）
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(_test_batch_nodes, batch, env, dirs, timeout, worker_id): (worker_id, batch)
            for worker_id, batch in enumerate(batches)
        }

        completed = 0
        for future in concurrent.futures.as_completed(future_map):
            worker_id, batch = future_map[future]
            completed += len(batch)
            try:
                alive_nodes = future.result()
                results.extend(alive_nodes)
            except Exception as e:
                logger.error("Batch test error (worker_id=%d): %s", worker_id, e)
            logger.info("已测试 %d/%d 个节点，可用节点: %d（worker_id=%d）",
                        completed, len(proxies), len(results), worker_id)

    total_time = time.time() - start_time
    logger.info("批量测试完成，总耗时: %.2f 秒", total_time)
    logger.info("成功节点: %d/%d", len(results), len(proxies))

    # 按性能排序
    if results:
        results = sort_proxies_by_performance(results)[:50]
        logger.info("节点已按性能排序（延迟低、速度快的在前）")

    if env != "dev" and results:
        manager = ClashMetaManager('base_template.yaml', 'test_config.yaml')
        manager.save_config(results, os.path.join(dirs, "clash.yaml"))

    return results


def v2ray_2_clash(file_path=None, content=None):
    nodes = None
    if file_path and os.path.exists(file_path):
        # 每行是一个 base64 编码的订阅内容，需全部解码后拼接
        decoded_lines = []
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                if not line:
                    continue
                try:
                    data = line.strip()
                    decoded_lines.append(base64.b64decode(data).decode("utf-8"))
                except Exception as e:
                    logger.debug("base64 解码失败（%s）: %s", data[:40], e)
        if decoded_lines:
            nodes = "\n".join(decoded_lines)
    elif content:
        try:
            nodes = base64.b64decode(content).decode("utf-8")
        except Exception as e:
            logger.debug("base64 解码失败: %s", e)
    proxies = []
    name_list = {}  # name -> 出现次数（从1开始）
    if nodes:
        for node in nodes.splitlines():
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
                logger.debug("解析失败: %s... %s", node[:40], e)
    # if proxies:
    #     proxies = test_nodes(proxies)
    # print(proxies)
    return proxies


def filter_proxies(proxies):
    if not proxies:
        return []
    proxies_set = []
    filtered_proxies = []
    proxy_name_map = {}
    for proxy in proxies:
        # 获取proxy节点信息（避免用 type 作变量名遮蔽内置函数）
        server = proxy.get("server")
        port = proxy.get("port")
        proxy_type = proxy.get("type")
        # 必填字段缺失的节点直接丢弃
        if server is None or port is None or proxy_type is None:
            logger.debug("节点缺少必填字段（server/port/type），丢弃: %s", proxy.get("name", "?"))
            continue
        cipher = proxy.get("cipher", "")
        uuid = proxy.get("uuid", "")
        # 检查是否已经存在相同的proxy节点
        if (server, port, proxy_type, cipher, uuid) not in proxies_set:
            proxies_set.append((server, port, proxy_type, cipher, uuid))
            # 用浅拷贝避免修改调用方的原始 dict
            proxy_copy = dict(proxy)
            name = proxy_copy.get("name", "")
            # 清理名称中的 Unicode 编码
            name = decode_unicode_name(name)
            if name not in proxy_name_map:
                proxy_name_map[name] = 1
                proxy_copy["name"] = name
            else:
                proxy_copy["name"] = f"{name}-{proxy_name_map[name]}"
                proxy_name_map[name] += 1
            filtered_proxies.append(proxy_copy)
    return filtered_proxies


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
            logger.debug("第%d行解析失败（内容为空）：%s...", idx + 1, line[:80])

    return proxies


# 解决SSL协议兼容问题的适配器
class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        """创建启用证书验证的 TLSv1.2+ SSL 上下文。"""
        context = ssl.create_default_context()
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # 仅启用 TLSv1.2+

        # 保存池参数（用于序列化/反序列化，与父类行为一致）
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=context,
        )
