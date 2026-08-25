import asyncio
import base64
import concurrent.futures
import json
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


# 节点分类关键词（用于标记节点特性）
NODE_CATEGORY_KEYWORDS = {
    "google": ["google", "ggl", "谷歌", "美国", "日本", "新加坡", "hk", "tw", "jp", "sg", "us"],
    "youtube": ["youtube", "yt", "谷歌", "美国", "日本", "新加坡", "hk", "tw", "jp", "sg", "us"],
    "chatgpt": ["chatgpt", "openai", "anthropic", "美国", "日本", "新加坡", "hk", "tw", "jp", "sg", "us"],
}


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


def classify_proxy(proxy: dict) -> set:
    """根据节点名称关键词分类节点"""
    name = proxy.get("name", "").lower()
    categories = set()
    for category, keywords in NODE_CATEGORY_KEYWORDS.items():
        if any(kw in name for kw in keywords):
            categories.add(category)
    return categories


def decode_vmess(link):
    raw = link.replace("vmess://", "")
    data = base64.b64decode(raw + "==").decode()
    obj = json.loads(data)

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

    decoded = base64.b64decode(raw + "==").decode()
    method, rest = decoded.split(":")
    password, server = rest.split("@")
    host, port = server.split(":")

    return {
        "name": name,
        "type": "ss",
        "server": host,
        "port": int(port),
        "cipher": method,
        "password": password
    }


def decode_hysteria2(link):
    u = urllib.parse.urlparse(link)
    q = urllib.parse.parse_qs(u.query)

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
        print("test success: ", r)
        return True
    except Exception as e:
        print(e)
        # traceback.print_exc()
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
    start_time = time.time()
    downloaded_bytes = 0
    try:
        async with session.get(
                link,
                proxy=proxies.get('http') if proxies else None,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True
        ) as response:
            # 读取响应内容以计算下载量
            async for chunk in response.content.iter_chunked(8192):
                downloaded_bytes += len(chunk)
            elapsed = time.time() - start_time
            success = response.status < 400
            return link, success, elapsed, downloaded_bytes
    except asyncio.TimeoutError:
        elapsed = time.time() - start_time
        return link, False, elapsed, 0
    except Exception as e:
        elapsed = time.time() - start_time
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
    connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=False)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for link in links:
            task = test_link_async(session, link, proxies, timeout)
            tasks.append(task)

        # 并发执行所有任务
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)


def test_proxy_alive(socks_port, timeout=8):
    proxies = {
        "http": f"http://127.0.0.1:{socks_port}",
        "https": f"http://127.0.0.1:{socks_port}",
    }
    links = [
        "https://www.google.com",
        "https://tv.youtube.com/welcome",
        "https://github.com"
    ]

    print("开始并发测试链接...")
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
    print(f"\n测试完成，总耗时: {total_time:.2f}秒")
    print("=" * 50)

    success_count = sum(1 for _, success, _, _ in results if success)
    print(f"成功: {success_count}/{len(results)}")
    print(f"失败: {len(results) - success_count}/{len(results)}")
    print("\n详细结果:")
    for link, success, elapsed, downloaded_bytes in results:
        status = "✅ 成功" if success else "❌ 失败"
        speed_kbps = (downloaded_bytes * 8 / elapsed / 1000) if elapsed > 0 and downloaded_bytes > 0 else 0
        print(f"{status} | {elapsed:.2f}s | {speed_kbps:.0f}KB/s | {link}")
    return success_count == len(links)


def test_node_metrics(node, http_port, timeout=6):
    """
    测试单个节点的延时和网速，返回节点信息和性能指标
    """
    proxies = {
        "http": f"http://127.0.0.1:{http_port}",
        "https": f"http://127.0.0.1:{http_port}",
    }

    # 定义测试链接（针对不同类型的服务）
    test_links = [
        ("google", "https://www.google.com"),
        ("youtube", "https://www.youtube.com"),
        ("chatgpt", "https://api.openai.com"),
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
        raw_results = asyncio.run(test_links_concurrent(
            [url for _, url in test_links],
            proxies,
            timeout=timeout,
            max_concurrent=5
        ))

        for (service, _), (link, success, elapsed, downloaded_bytes) in zip(test_links, raw_results):
            if success:
                speed_kbps = (downloaded_bytes * 8 / elapsed / 1000) if elapsed > 0 else 0
                results[f"{service}_latency"] = round(elapsed * 1000, 1)  # 转为毫秒
                results[f"{service}_speed_kbps"] = round(speed_kbps, 1)

        # 计算平均延时和速度
        latencies = [results[f"{s}_latency"] for s in ["google", "youtube", "chatgpt", "github"] if results.get(f"{s}_latency")]
        speeds = [results[f"{s}_speed_kbps"] for s in ["google", "youtube", "chatgpt", "github"] if results.get(f"{s}_speed_kbps")]

        if latencies:
            results["avg_latency"] = round(sum(latencies) / len(latencies), 1)
        if speeds:
            results["avg_speed_kbps"] = round(sum(speeds) / len(speeds), 1)

        results["is_available"] = any(results.get(f"{s}_latency") is not None for s in ["google", "youtube", "chatgpt"])

    except Exception as e:
        print(f"Metrics test error for {node.get('name', 'unknown')}: {e}")

    return results


def test_proxy_telnet(proxy, timeout=8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((proxy["server"], proxy["port"]))
        s.close()
        print("proxy ip test success: ", proxy["server"], proxy["port"])
        return proxy
    except Exception as e:
        print("proxy ip test failed: ", e)
        return None


async def test_proxy_telnet_async(proxy, timeout=5):
    """异步 TCP 连接测试，利用 Linux epoll 提高并发效率"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy["server"], proxy["port"]),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return proxy
    except Exception as e:
        return None


async def test_proxies_async(proxies, timeout=5):
    """批量异步 TCP 测试"""
    tasks = [test_proxy_telnet_async(p, timeout=timeout) for p in proxies]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


def _test_single_node(node, env, dirs, timeout, worker_id):
    http_port = 7890 + worker_id * 10
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
        print(f"Batch test failed for {node.get('name', 'unknown')}: {e}")
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
    http_port = 7890 + worker_id * 10
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

        # 先测试整体连通性
        overall_alive = test_proxy_alive(http_port, timeout=timeout)

        if not overall_alive:
            return []

        # 对每个节点进行详细的性能测试
        for node in batch_proxies:
            node_metrics = test_node_metrics(node, http_port, timeout)
            if node_metrics["is_available"]:
                # 清理节点名称中的 Unicode 编码
                original_name = node.get("name", "")
                node["name"] = decode_unicode_name(original_name)
                # 添加性能指标到节点
                node["_latency"] = node_metrics["avg_latency"]
                node["_speed_kbps"] = node_metrics["avg_speed_kbps"]
                node["_categories"] = classify_proxy(node)
                metrics_results.append(node)
                print(f"  → {node['name']}: OK (延迟: {node_metrics['avg_latency']}ms, 速度: {node_metrics['avg_speed_kbps']:.0f}KB/s)")
            else:
                print(f"  → {node.get('name', 'unknown')}: FAIL")

        return metrics_results
    except Exception as e:
        print(f"Batch test failed: {e}")
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
        # 获取性能指标，默认为最大值（排在最后）
        latency = proxy.get("_latency", 999999)
        speed = proxy.get("_speed_kbps", 0)
        categories = proxy.get("_categories", set())

        # 如果没有性能数据，使用默认值
        if latency == 999999:
            return (1, 0, 0)  # 排在最后

        # 评分：低延迟和高速度都有益
        # 延迟权重更高（0.7），速度权重较低（0.3）
        latency_score = 1000 / (latency + 1)  # 防止除零
        speed_score = min(speed / 100, 100)  # 归一化到 0-100

        # 综合评分
        total_score = latency_score * 0.7 + speed_score * 0.3

        # 特殊服务加分（如果有类别标记）
        category_bonus = len(categories) * 5

        return (-total_score, -category_bonus, latency)  # 负号表示降序

    # 按评分排序
    sorted_proxies = sorted(proxies, key=proxy_sort_key)

    # 清理内部性能指标字段
    for proxy in sorted_proxies:
        proxy.pop("_latency", None)
        proxy.pop("_speed_kbps", None)
        proxy.pop("_categories", None)

    return sorted_proxies


def test_nodes(proxies, env, dirs, timeout=6):
    if not proxies:
        return []

    print("开始批量测试节点（并发启动多个 Clash 实例）...")
    start_time = time.time()

    # 每批测试数量（一个 Clash 实例可管理多个节点）
    batch_size = 20
    worker_count = min(8, len(proxies))
    results = []

    count = 0
    for batch_start in range(0, len(proxies), batch_size):
        batch = proxies[batch_start:batch_start + batch_size]
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(worker_count, len(batch))) as executor:
            future_map = {
                executor.submit(_test_batch_nodes, batch, env, dirs, timeout, slot): (slot, batch)
                for slot in range(len(batch))
            }

            for future in concurrent.futures.as_completed(future_map):
                slot, batch = future_map[future]
                try:
                    alive_nodes = future.result()
                    results.extend(alive_nodes)
                    count += len(batch)
                    print(f"已测试 {count}/{len(proxies)} 个节点，可用节点: {len(results)}")
                except Exception as e:
                    print(f"Batch test error: {e}")

    total_time = time.time() - start_time
    print(f"批量测试完成，总耗时: {total_time:.2f}秒")
    print(f"成功节点: {len(results)}/{len(proxies)}")

    # 按性能排序
    if results:
        results = sort_proxies_by_performance(results)
        print("节点已按性能排序（延迟低、速度快的在前）")

    if env != "dev" and results:
        manager = ClashMetaManager('base_template.yaml', 'test_config.yaml')
        manager.save_config(results, os.path.join(dirs, "clash.yaml"))

    return results


def v2ray_2_clash(file_path=None, content=None):
    nodes = None
    if file_path and os.path.exists(file_path):
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                if not line:
                    continue
                try:
                    data = line.strip()
                    decoded = base64.b64decode(data).decode("utf-8")
                    nodes = decoded
                except Exception as e:
                    print(e)
    elif content:
        try:
            nodes = base64.b64decode(content).decode("utf-8")
        except Exception as e:
            print(e)
    proxies = []
    name_list = {}
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
                    if proxy["name"] not in name_list:
                        name_list[proxy["name"]] = 1
                    elif proxy["name"] in name_list:
                        proxy["name"] = proxy["name"] + str(name_list[proxy["name"]])
                        name_list[proxy["name"]] = name_list[proxy["name"]] + 1
                    proxies.append(proxy)
            except Exception as e:
                print("解析失败:", node[:40], e)
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
        # 获取proxy节点信息
        server = proxy["server"]
        port = proxy["port"]
        type = proxy["type"]
        cipher = proxy.get("cipher", "")
        uuid = proxy.get("uuid", "")
        # 检查是否已经存在相同的proxy节点
        if (server, port, type, cipher, uuid) not in proxies_set:
            proxies_set.append((server, port, type, cipher, uuid))
            name = proxy["name"]
            # 清理名称中的 Unicode 编码
            name = decode_unicode_name(name)
            if name not in proxy_name_map:
                proxy_name_map[name] = 1
            else:
                proxy["name"] = name + "-" + str(proxy_name_map[name])
                proxy_name_map[name] += 1
            filtered_proxies.append(proxy)
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
            print(f"⚠️  第{idx + 1}行解析失败（内容为空）：{line}...")

    return proxies


# 解决SSL协议兼容问题的适配器
class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        # 创建SSL上下文，兼容TLSv1.2，关闭所有验证
        context = ssl.create_default_context()
        context.check_hostname = False  # 关闭主机名检查
        context.verify_mode = ssl.CERT_NONE  # 关闭证书验证
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # 仅启用TLSv1.2+

        # 初始化PoolManager，只传必要参数，避免重复
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=context
        )
