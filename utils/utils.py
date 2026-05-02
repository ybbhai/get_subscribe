import asyncio
import base64
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
) -> Tuple[str, bool, float]:
    """
    异步测试链接
    返回: (链接, 是否成功, 耗时)
    """
    start_time = time.time()
    try:
        async with session.get(
                link,
                proxy=proxies.get('http') if proxies else None,
                timeout=aiohttp.ClientTimeout(total=timeout)
        ) as response:
            # 可以根据状态码判断成功与否
            success = response.status < 400
            elapsed = time.time() - start_time
            print(f"test success: {link} - Status: {response.status}")
            return link, success, elapsed
    except asyncio.TimeoutError:
        elapsed = time.time() - start_time
        print(f"Timeout: {link} - Timeout after {timeout}s")
        return link, False, elapsed
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"Error testing {link}: {str(e)}")
        return link, False, elapsed


async def test_links_concurrent(
        links: List[str],
        proxies: Optional[dict] = None,
        timeout: int = 10,
        max_concurrent: int = 10
) -> tuple[BaseException | Any, BaseException | Any, BaseException | Any, BaseException | Any, BaseException | Any]:
    """
    并发测试多个链接
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
        return results


def test_proxy_alive(socks_port, timeout=8):
    proxies = {
        "http": "socks5h://127.0.0.1:7890",
        "https": "socks5h://127.0.0.1:7890",
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

    success_count = sum(1 for _, success, _ in results if success)
    print(f"成功: {success_count}/{len(results)}")
    print(f"失败: {len(results) - success_count}/{len(results)}")
    print("\n详细结果:")
    # 判断results是否都为False
    for link, success, elapsed in results:
        status = "✅ 成功" if success else "❌ 失败"
        print(f"{status} | {elapsed:.2f}s | {link}")
    return success_count == len(links)


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


def test_nodes(proxies, env, dirs, timeout=6):
    if not proxies:
        return

    manager = ClashMetaManager('base_template.yaml', 'test_config.yaml')
    manager.write_config(proxies, env=env, file_path=os.path.join(dirs, "clash.yaml"))

    manager.start()
    if os.name == "nt":
        print("windows")
    else:
        print("linux")

    results = []
    try:
        count = 1
        alive_count = 0
        total = 100
        for node in proxies:
            name = node["name"]
            print(f"Testing: {name}")

            manager.switch_proxy(proxy_name=name)
            time.sleep(5)

            alive = test_proxy_alive(7891, timeout=timeout)
            if alive:
                alive_count += 1
                results.append(node)
                if alive_count >= total:
                    print(f"Reached total alive count: {alive_count}. Stopping tests.")
                    break

            print(f" → {name}: {'OK' if alive else 'FAIL'}. {count} / {len(proxies)}. proxies: {alive_count}")
            count += 1
    except Exception as e:
        print("Error during testing:", e)
        # traceback.print_exc()
    finally:
        manager.stop()
        if env != "dev" and results:
            manager.clear_test()
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
            if name not in proxy_name_map:
                proxy_name_map[name] = 1
            else:
                proxy["name"] = proxy["name"] + "-" + str(proxy_name_map[name])
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
