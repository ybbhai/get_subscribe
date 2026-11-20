import argparse
import asyncio
from html.parser import HTMLParser
import ipaddress
import logging
import os
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import quote, urlsplit

import feedparser
import requests
import yaml
from urllib3.util.retry import Retry

from utils.utils import test_nodes, v2ray_2_clash, SSLAdapter, clean_yaml_content, parse_special_clash, filter_proxies, \
    test_proxies_async
from utils.clash_manager import GENERATED_PROXY_CONFIG, read_listen_ports, find_free_port_block

requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [pid=%(process)d] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

ok_code = [200, 201, 202, 203, 204, 205, 206]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "log")

# 主 Clash 实例（用于拉取订阅时走本地代理）
MAIN_PROXY_CONFIG = "proxy.yaml"
# proxy.yaml 里写的是 external-controller: 127.0.0.1:9099 / mixed-port: 7890，
# 这里只作为 read_listen_ports() 的兜底默认值使用。
MAIN_CONTROLLER_PORT = 9099
MAIN_MIXED_PORT = 7890
# 节点可用性判定：必须用该节点真的抓到订阅数据。
# 旧实现请求 https://www.gstatic.com/generate_204 返回 204 就算可用，
# 但节点能连 gstatic 并不等于能抓订阅站，判定结果是假的。
BOOTSTRAP_MAX_PROBE_NODES = 12
BOOTSTRAP_PROBE_TIMEOUT_SECONDS = 8
# 单个节点的探测总预算（秒）。探针地址有多个，预算按地址数分摊而不是每个都等满，
# 否则 12 个节点 × 4 个地址 × 8 秒会让启动卡到十分钟。
# 多源探测最多 4 个 URL；12 秒预算会把单次读取压到 3 秒，
# 实际网络稍慢时就会让每个来源都以 ReadTimeout 失败。
BOOTSTRAP_NODE_BUDGET_SECONDS = 24
# 启动等待：首次运行要联网下载 geoip.metadb，给足时间；兜底配置则只需快速验证
BOOTSTRAP_LAUNCH_WAIT_SECONDS = 30
FALLBACK_LAUNCH_WAIT_SECONDS = 15
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
RSS_URL = "https://www.cfmem.com/feeds/posts/default?alt=rss"
SUBSCRIPTION_TIMEOUT = (5, 10)

# 默认循环间隔（小时）。README 与 CI cron 都是 2 小时一轮。
DEFAULT_INTERVAL_HOURS = 2.0


def acquire_instance_lock(lock_path=None):
    """单实例运行保护；返回的文件句柄需保持存活以维持锁。"""
    lock_path = lock_path or os.path.join(BASE_DIR, "log", "main.lock")
    os.makedirs(os.path.dirname(os.path.abspath(lock_path)), exist_ok=True)
    lock_file = open(lock_path, "a+", encoding="utf-8")
    try:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            if os.fstat(lock_file.fileno()).st_size == 0:
                lock_file.write("\0")
                lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock_file.close()
        return None

    lock_file.seek(0)
    lock_file.truncate()
    lock_file.write(f"{os.getpid()}\n")
    lock_file.flush()
    return lock_file


def write_log(content, level="INFO"):
    """写入月度日志文件，同时输出到控制台"""
    date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    update_log = f"[{date_str}] [{level}] {content}"
    logger.log(getattr(logging, level, logging.INFO), content)
    # 日志目录必须基于脚本位置，否则从其他工作目录启动时会写到意外位置
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(os.path.join(LOG_DIR, f'{time.strftime("%Y-%m", time.localtime(time.time()))}-update.log'), 'a',
              encoding="utf-8") as f:
        f.write(update_log + "\n")


_FALLBACK_PROXY_CACHE = None


# 常见本地代理客户端端口（Clash/Verge、v2rayN、SSR、Surge、Windows 系统代理）
_LOCAL_PROXY_PORTS = (7890, 7891, 7897, 7898, 10808, 10809, 1080, 1081,
                      20171, 20172, 8080, 8889)


def _proxy_reachable(proxy_url, timeout=0.4):
    try:
        parsed = urlsplit(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
        host, port = parsed.hostname, parsed.port
    except (TypeError, ValueError):
        # Malformed proxy environment variables should be skipped, not abort collection.
        return False
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _redact_url(url):
    """Reduce a potentially credential-bearing URL to its scheme and authority."""
    try:
        raw_url = str(url)
        parsed = urlsplit(raw_url if "://" in raw_url else f"http://{raw_url}")
        host = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return "<invalid URL>"
    if not parsed.scheme or not host:
        return "<invalid URL>"
    host = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{host}" + (f":{port}" if port is not None else "")


def _is_subscription_payload(url, content):
    """Return whether a successful HTTP body contains recognizable subscription data."""
    if url == RSS_URL or "feeds/posts" in url:
        entries = getattr(feedparser.parse(content), "entries", [])
        return any(_extract_subscription_urls(entry.get("summary", ""))
                   for entry in entries if isinstance(entry, dict))

    try:
        decoded = content.decode("utf-8-sig")
    except (AttributeError, UnicodeDecodeError):
        return False
    if decoded.lstrip().lower().startswith(("<!doctype html", "<html")):
        return False

    try:
        parsed = yaml.safe_load(clean_yaml_content(decoded))
    except yaml.YAMLError:
        parsed = None
    nodes = parsed.get("proxies") if isinstance(parsed, dict) else None
    if isinstance(nodes, list) and any(
            isinstance(node, dict) and node.get("server") and node.get("port")
            and node.get("type") for node in nodes):
        return True
    if parse_special_clash(decoded):
        return True
    return bool(v2ray_2_clash(content=decoded))


def _proxy_actually_works(proxy_url, timeout=6):
    """真的用这个代理抓一次订阅数据，确认它能当出口。

    端口能连只说明有进程在监听（可能是测速残留实例、无关服务），
    必须实际拉到订阅内容才算合格出口。判定对象是“本机出口代理”，
    不是“订阅节点可用性”，不要混用。
    """
    proxy_url = proxy_url if "://" in proxy_url else f"http://{proxy_url}"
    try:
        targets = _probe_targets(limit=1)[:2]
    except Exception:  # 探针地址解析失败不应阻断出口探测
        targets = [RSS_URL]
    with requests.Session() as session:
        session.trust_env = False
        session.proxies = {"http": proxy_url, "https": proxy_url}
        for url in targets:
            try:
                response = session.get(url, timeout=timeout,
                                       headers={"User-Agent": USER_AGENT})
            except requests.exceptions.RequestException:
                continue
            content = response.content
            if response.status_code not in ok_code or len(content) < 256:
                continue
            if _is_subscription_payload(url, content):
                return True
    return False


def _detect_fallback_proxy():
    """直连回退时使用的出口代理。

    探的是**出口可用性**，不是节点可用性：用户本机通常开着代理客户端，
    但 Linux/macOS 下 requests 只读环境变量、不读系统代理设置，
    所以没设 HTTP_PROXY 时 requests 走的是真直连，被墙的订阅源必然抓不到。
    这里按“环境变量 → 常见本地代理端口”的顺序找一个真的能出网的出口，
    每个候选都必须真实请求成功才算数，避免误用一个监听中的无关端口。
    找不到就返回 None，由 requests 按自己的默认规则处理。
    """
    global _FALLBACK_PROXY_CACHE
    if _FALLBACK_PROXY_CACHE is not None:
        return _FALLBACK_PROXY_CACHE or None

    candidates = []
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                "ALL_PROXY", "all_proxy"):
        value = (os.environ.get(key) or "").strip()
        if value:
            candidates.append(value)
    candidates.extend(f"http://127.0.0.1:{port}" for port in _LOCAL_PROXY_PORTS)

    seen = set()
    tested = 0
    # 最多真实验证 2 个可连的候选，避免一堆监听端口把启动拖成分钟级
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if not _proxy_reachable(candidate):
            continue
        tested += 1
        if tested > 2:
            break
        if not _proxy_actually_works(candidate):
            logger.debug("代理候选 %s 端口可连但无法出网，跳过", _redact_url(candidate))
            continue
        _FALLBACK_PROXY_CACHE = candidate
        logger.info("直连回退将使用出口代理: %s", _redact_url(candidate))
        return candidate

    _FALLBACK_PROXY_CACHE = ""
    logger.warning("未找到可用的本地出口代理，直连回退将使用系统/环境默认规则")
    return None


def _subscription_session(use_local_proxy, proxy_port):
    """构建订阅请求会话。

    走本地 Clash 时必须忽略环境代理，否则请求可能在本地代理之前又被
    HTTP_PROXY/HTTPS_PROXY 转发一次。
    走直连回退时则必须优先使用真实存在的代理出口：原实现无条件
    trust_env=False，导致“本机开着代理”的机器上直连回退必然被判为失败。
    """
    session = requests.Session()
    session.verify = (os.environ.get('REQUESTS_CA_BUNDLE')
                      or os.environ.get('CURL_CA_BUNDLE') or True)
    if use_local_proxy:
        session.trust_env = False
        proxy_url = f'http://127.0.0.1:{proxy_port or MAIN_MIXED_PORT}'
        session.proxies = {'http': proxy_url, 'https': proxy_url}
    else:
        detected = _detect_fallback_proxy()
        if detected:
            session.trust_env = False
            session.proxies = {'http': detected, 'https': detected}
        else:
            # 没有探测到代理时退回 requests 默认行为（环境变量 / 系统代理）
            session.trust_env = True
    return session


def get_subscribe_proxies(use_local_proxy=True, proxy_port=None):
    with _subscription_session(use_local_proxy, proxy_port) as session:
        return _get_rss_proxies(session)


class _SubscriptionLinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() != "a" or self._href is None:
            return
        href = self._href.strip()
        label = " ".join(self._text).strip().lower()
        if href.startswith(("http://", "https://")):
            if "v2ray" in label or "xray" in label or href.rstrip("/").endswith("/v2ray"):
                self.links.append(("v2ray", href))
            elif ("clash" in label or "mihomo" in label
                  or href.rstrip("/").endswith(("/mihomo", "/clash"))):
                self.links.append(("clash", href))
        self._href = None
        self._text = []


def _extract_subscription_urls(summary):
    parser = _SubscriptionLinkParser()
    parser.feed(summary or "")
    urls = {}
    for kind, url in parser.links:
        urls[kind] = url

    if urls:
        return urls

    legacy_patterns = {
        "v2ray": r">V2Ray/XRay\s*-&gt;\s*(https?://.*?)</span>",
        "clash": r">clash\s*-&gt;\s*(https?://.*?)</span>",
    }
    for kind, pattern in legacy_patterns.items():
        matches = re.findall(pattern, summary or "", re.IGNORECASE)
        if matches:
            urls[kind] = matches[-1].replace("&amp;", "&").strip()
    return urls


def _get_rss_proxies(session):
    try:
        with session.get(RSS_URL, timeout=SUBSCRIPTION_TIMEOUT) as response:
            response.raise_for_status()
            rss = feedparser.parse(response.content)
    except requests.exceptions.RequestException as e:
        logger.error("拉取 RSS 失败: %s", e)
        return []

    # feedparser 对象用属性访问，不用 dict.get
    entries = getattr(rss, "entries", []) if rss else []
    if not entries:
        write_log("更新失败！无法拉取原网站内容", "ERROR")
        return []
    update_list = []
    summary = entries[0].get("summary")
    if not summary:
        write_log("暂时没有可用的订阅更新", "WARN")
        return []
    subscription_urls = _extract_subscription_urls(summary)
    proxies = []
    # 获取普通订阅链接
    v2ray_url = subscription_urls.get("v2ray")
    if v2ray_url:
        # 只请求合法 URL，避免捕获到非 URL 文本
        if not v2ray_url.startswith(("http://", "https://")):
            logger.warning("v2ray 订阅 URL 无效，跳过: %s", _redact_url(v2ray_url))
        else:
            try:
                v2ray_req = session.get(v2ray_url, timeout=SUBSCRIPTION_TIMEOUT)
            except requests.exceptions.RequestException as e:
                # 单个订阅源失败不能终止整个采集流程，否则后续 URL/节点全部丢失
                logger.error("请求 v2ray 订阅失败（%s）：%s", _redact_url(v2ray_url),
                             type(e).__name__)
                write_log(f"请求 v2ray 订阅失败：{_redact_url(v2ray_url)}", "WARN")
            else:
                v2ray_code = v2ray_req.status_code
                if v2ray_code not in ok_code:
                    write_log(f"获取 v2ray 订阅失败：{_redact_url(v2ray_url)} - {v2ray_code}", "WARN")
                else:
                    update_list.append(f"v2ray: {v2ray_code}")
                    proxies.extend(v2ray_2_clash(content=v2ray_req.text))
    # 获取clash订阅链接
    clash_url = subscription_urls.get("clash")
    if clash_url:
        # 只请求合法 URL，避免捕获到非 URL 文本
        if not clash_url.startswith(("http://", "https://")):
            logger.warning("clash 订阅 URL 无效，跳过: %s", _redact_url(clash_url))
        else:
            try:
                clash_req = session.get(clash_url, timeout=SUBSCRIPTION_TIMEOUT)
            except requests.exceptions.RequestException as e:
                # 同上：clash 订阅失败不应丢弃已解析出的 v2ray 节点
                logger.error("请求 clash 订阅失败（%s）：%s", _redact_url(clash_url),
                             type(e).__name__)
                write_log(f"请求 clash 订阅失败：{_redact_url(clash_url)}", "WARN")
            else:
                clash_code = clash_req.status_code
                if clash_code not in ok_code:
                    write_log(f"获取 clash 订阅失败：{_redact_url(clash_url)} - {clash_code}", "WARN")
                else:
                    update_list.append(f"clash: {clash_code}")
                    try:
                        clash_content = clash_req.content.decode("utf-8-sig")
                        parsed = yaml.safe_load(clash_content)
                        clash_nodes = parsed.get("proxies") if isinstance(parsed, dict) else None
                        if isinstance(clash_nodes, list):
                            proxies.extend(clash_nodes)
                        else:
                            logger.warning("clash 订阅内容中无有效 proxies 列表，跳过: %s",
                                           _redact_url(clash_url))
                    except (UnicodeDecodeError, yaml.YAMLError) as e:
                        logger.error("解析 clash 订阅内容失败（%s）：%s",
                                     _redact_url(clash_url), type(e).__name__)
    if not subscription_urls:
        logger.warning("RSS 已返回条目，但最新条目的摘要中未匹配到订阅链接")
    logger.info("RSS 订阅获取结果: %s，共 %d 个节点", update_list, len(proxies))
    return proxies


def load_urls(config_path):
    """从配置文件读取URL列表，忽略注释行和空行"""
    urls = []
    with open(config_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                urls.append(line)
    return urls


def get_clash_proxies(use_local_proxy=True, proxy_port=None):
    # 获取当前时间，并转换成yyyyMMdd格式的字符串
    now = time.localtime(time.time())
    day = time.strftime('%d', now)
    year = time.strftime('%Y', now)
    month = time.strftime('%m', now)
    stamp = time.strftime('%Y%m%d', now)

    # 从配置文件读取URL
    config_path = os.path.join(os.path.dirname(__file__), 'config', 'urls.txt')
    urls = load_urls(config_path)
    proxies = []
    # 创建 session 并配置 SSL 适配器、超时、重试策略
    session = _subscription_session(use_local_proxy, proxy_port)
    retry = Retry(total=1, connect=0, read=0, other=0, status=1,
                  status_forcelist=(500, 502, 503, 504),
                  respect_retry_after_header=False, raise_on_status=False)
    session.mount("https://", SSLAdapter(max_retries=retry))
    session.mount("http://", SSLAdapter(max_retries=retry))
    # 设置超时时间（连接超时5秒，读取超时10秒）
    timeout = SUBSCRIPTION_TIMEOUT
    try:
        for raw_url in urls:
            try:
                url = raw_url.format(stamp=stamp, year=year, month=month, day=day)
            except (KeyError, IndexError, ValueError) as error:
                logger.warning("Clash 订阅源格式错误，跳过 %s（%s）",
                               _redact_url(raw_url), type(error).__name__)
                continue
            # 获取链接文件内容
            raw_content = None
            try:
                req = session.get(url,
                                  timeout=timeout,
                                  headers={
                                      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
                if req.status_code not in ok_code:
                    logger.warning("Clash 订阅返回 HTTP %d: %s", req.status_code, _redact_url(url))
                    continue
                raw_content = req.content.decode("utf-8-sig")
                if (req.headers.get("Content-Type", "").lower().startswith("text/html")
                        or raw_content.lstrip().lower().startswith(("<!doctype html", "<html"))):
                    logger.warning("Clash 订阅返回 HTML 页面，跳过: %s", _redact_url(url))
                    continue
                content = clean_yaml_content(raw_content)
                try:
                    parsed = yaml.safe_load(content)
                except yaml.YAMLError:
                    parsed = None
                nodes = parsed.get("proxies") if isinstance(parsed, dict) else None
                if not isinstance(nodes, list):
                    nodes = parse_special_clash(raw_content)
                if not nodes:
                    logger.warning("Clash 订阅响应中未解析到节点: %s", _redact_url(url))
                proxies.extend(nodes)
            except Exception as error:
                logger.warning("获取 Clash 订阅失败: %s（%s）",
                               _redact_url(url), type(error).__name__)
    finally:
        session.close()
    return proxies


def _write_bootstrap_config(source_path, output_path, mixed_port=None, controller_port=None):
    """写出只含采集节点的最小配置。

    端口默认沿用旧常量，但调用方应传入动态空闲端口：用户本机的代理客户端
    通常占用 7890/7891/9090，写死端口会让采集实例直接绑定失败。
    """
    with open(source_path, encoding="utf-8") as source:
        exported = yaml.safe_load(source)
    nodes = exported.get("proxies") if isinstance(exported, dict) else None
    nodes = _filter_bootstrap_nodes(nodes)
    if not nodes:
        raise ValueError("上次生成的配置中没有可用的节点列表")

    group_name = "SUBSCRIPTION"
    names = [node["name"] for node in nodes]
    while group_name in names:
        group_name += "-"
    config = {
        "mixed-port": mixed_port or MAIN_MIXED_PORT,
        "external-controller": f"127.0.0.1:{controller_port or MAIN_CONTROLLER_PORT}",
        "allow-lan": False,
        "mode": "rule",
        "proxies": nodes,
        "proxy-groups": [{
            "name": group_name,
            "type": "select",
            "proxies": names,
        }],
        "rules": [f"MATCH,{group_name}"],
    }
    with open(output_path, "w", encoding="utf-8") as output:
        yaml.safe_dump(config, output, allow_unicode=True)
    return group_name


def _filter_bootstrap_nodes(nodes):
    """丢弃绑定在本机回环地址的节点，避免误用采集/测速占位配置。"""
    if not isinstance(nodes, list):
        return []
    usable = []
    rejected = 0
    for node in nodes:
        if not isinstance(node, dict):
            rejected += 1
            continue
        host = str(node.get("server", "")).strip().lower().strip("[]")
        is_loopback = host == "localhost" or host.endswith(".localhost")
        try:
            is_loopback = is_loopback or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if is_loopback:
            rejected += 1
        else:
            usable.append(node)
    if rejected:
        logger.warning("忽略 %d 个无效或指向本机回环地址的采集节点", rejected)
    return usable


def _launch_clash(exe_path, config_path, log_path, wait_seconds, data_dir=None):
    """用指定配置启动一个 Clash 进程，并轮询 API 确认就绪。

    成功返回 (proc, mixed_port, controller_port)，失败返回 (None, None, None) 并已清理进程。
    controller 和 HTTP 代理端口都从实际启动配置读取，避免与运行时端口不一致。
    """
    controller_port, mixed_port = read_listen_ports(
        config_path, MAIN_CONTROLLER_PORT, MAIN_MIXED_PORT)
    command = [exe_path, "-f", config_path]
    if data_dir is not None:
        command.extend(["-d", data_dir])
    try:
        with open(log_path, "w", encoding="utf-8") as log_handle:
            proc = subprocess.Popen(
                command,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
            )
    except OSError as e:
        logger.error("启动 Clash 进程失败（%s）: %s", config_path, e)
        return None, None, None

    api_url = f"http://127.0.0.1:{controller_port}/version"
    deadline = time.monotonic() + wait_seconds
    with requests.Session() as session:
        session.trust_env = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                logger.error("Clash 进程提前退出（exit_code=%s），详情见 %s",
                             proc.returncode, log_path)
                return None, None, None
            try:
                if session.get(api_url, timeout=1).status_code == 200 and proc.poll() is None:
                    return proc, mixed_port, controller_port
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.5)

    logger.error("Clash API 在 %d 秒内未就绪，详情见 %s", wait_seconds, log_path)
    stop_proxies(proc)
    return None, None, None


def _probe_targets(limit=3):
    """节点可用性判定要真实抓取的地址：RSS 源 + 若干真实 Clash 订阅源。

    订阅源地址里带 {stamp} 占位符，源站当天没更新就会 404。只取 urls.txt 的
    第一条会让“源站今天没发”变成“所有节点都不可用”，所以多取几条提高命中率。
    """
    targets = [RSS_URL]
    if limit <= 0:
        return targets
    try:
        urls = load_urls(os.path.join(BASE_DIR, "config", "urls.txt"))
    except OSError as error:
        logger.warning("读取订阅源列表失败: %s", error)
        urls = []
    now = time.localtime(time.time())
    # URL 列表按站点分组时，取前几行可能重复命中同一个故障域名，
    # 导致每个节点都测同一批不可用站点，却完全不检查后面的独立源。
    # RSS 已占用一个探测名额；订阅源按 hostname 去重后再选，扩大故障域多样性。
    rss_host = urlsplit(RSS_URL).hostname
    seen_hosts = {rss_host} if rss_host else set()
    selected_sources = 0
    for raw in urls:
        try:
            url = raw.format(
                stamp=time.strftime('%Y%m%d', now),
                year=time.strftime('%Y', now),
                month=time.strftime('%m', now),
                day=time.strftime('%d', now),
            )
        except (KeyError, IndexError, ValueError) as error:
            logger.debug("订阅源占位符无法替换，跳过 %s: %s",
                         _redact_url(raw), type(error).__name__)
            continue

        host = urlsplit(url).hostname
        if not host or host in seen_hosts:
            continue
        targets.append(url)
        seen_hosts.add(host)
        selected_sources += 1
        if selected_sources >= limit:
            break
    return list(dict.fromkeys(targets))


def _probe_subscription_via_proxy(proxy_port, urls, timeout=None):
    """用本地 Clash 出口真实请求订阅源，确认该节点确实能代理抓取数据。

    返回 (是否可用, 说明)。判定标准是“拿到可解析的真实内容”，
    而不是“本地端口能连”或“某个 204 探针能通”。
    必须至少有一个订阅源真实拉到数据，才算这个节点可用。

    ``timeout`` 是这个节点的**总预算**，会按探针地址数平摊；单条地址至少留
    2 秒，避免第一个地址卡满预算后剩余地址完全没机会。
    """
    proxy_url = f"http://127.0.0.1:{proxy_port or MAIN_MIXED_PORT}"
    total_budget = timeout or BOOTSTRAP_NODE_BUDGET_SECONDS
    deadline = time.monotonic() + total_budget
    failures = []
    with requests.Session() as session:
        session.trust_env = False
        session.proxies = {"http": proxy_url, "https": proxy_url}
        for index, url in enumerate(urls):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failures.append("探测预算耗尽")
                break
            remaining_targets = len(urls) - index
            request_timeout = min(
                BOOTSTRAP_PROBE_TIMEOUT_SECONDS,
                total_budget / len(urls),
                max(2.0, remaining / remaining_targets),
            )
            try:
                response = session.get(
                    url, timeout=request_timeout,
                    headers={"User-Agent": USER_AGENT})
                status = response.status_code
                content = response.content
            except requests.exceptions.RequestException as error:
                failures.append(f"{_redact_url(url)} 请求失败: {type(error).__name__}")
                continue

            if status not in ok_code:
                failures.append(f"{_redact_url(url)} HTTP {status}")
                continue
            if len(content) < 256:
                failures.append(f"{_redact_url(url)} 响应过短（{len(content)} 字节）")
                continue
            if not _is_subscription_payload(url, content):
                failures.append(f"{_redact_url(url)} 响应不是可识别的订阅数据")
                continue
            return True, f"{_redact_url(url)} HTTP {status} / {len(content)} 字节"
    return False, "；".join(failures) or "无可用订阅源"


def _check_bootstrap_proxy(proc, port, group_name, node_names,
                           max_wait_seconds=None, controller_port=None):
    """切换节点，并用真实订阅源验证它能否代理抓取数据。

    判定依据必须是“这个节点真的抓到了订阅数据”：旧实现只请求
    gstatic/generate_204 看是否 204，那只能证明“能上网”，
    不能证明它抓得到订阅站，等于用一个假指标放行节点。
    """
    controller_port = controller_port or MAIN_CONTROLLER_PORT
    group_url = (f"http://127.0.0.1:{controller_port}"
                 f"/proxies/{quote(group_name, safe='')}")
    probe_urls = _probe_targets()
    candidates = list(node_names)[:BOOTSTRAP_MAX_PROBE_NODES]
    if not candidates:
        return False
    # 每个节点有独立的探测预算，整体超时按节点数放大（额外留出切换开销）
    if max_wait_seconds is None:
        max_wait_seconds = BOOTSTRAP_NODE_BUDGET_SECONDS * len(candidates) + 10
    deadline = time.monotonic() + max_wait_seconds

    with requests.Session() as api_session:
        api_session.trust_env = False
        for node_name in candidates:
            if proc.poll() is not None or time.monotonic() >= deadline:
                return False

            try:
                switched = api_session.put(
                    group_url,
                    json={"name": node_name},
                    timeout=3,
                )
                switched.raise_for_status()
                current = api_session.get(group_url, timeout=3)
                current.raise_for_status()
                if current.json().get("now") != node_name:
                    logger.warning("Clash 未切换到节点 %s，尝试下一个节点", node_name)
                    continue
            except (requests.exceptions.RequestException, ValueError) as error:
                logger.warning("切换采集节点失败: %s（%s）", node_name, error)
                continue

            remaining = deadline - time.monotonic()
            if proc.poll() is not None or remaining <= 0:
                return False

            ok, detail = _probe_subscription_via_proxy(
                port, probe_urls,
                timeout=min(BOOTSTRAP_NODE_BUDGET_SECONDS, remaining))
            if ok:
                logger.info("采集节点 %s 可正常代理抓取订阅数据（%s）", node_name, detail)
                return True
            logger.warning("采集节点 %s 无法抓取订阅数据（%s），尝试下一个节点",
                           node_name, detail)
    return False


def start_proxies():
    """优先用上次保存的节点启动采集代理，失败时回退到本地配置。"""
    path = os.path.join(os.path.dirname(__file__), "clash")
    exe = "linux-compatible" if os.name != "nt" else "windows-compatible.exe"
    exe_path = os.path.join(path, exe)
    if not os.path.isfile(exe_path):
        logger.error("Clash 可执行文件不存在: %s，将直连拉取订阅", exe_path)
        return None, None

    bootstrap_log = os.path.join(path, "clash-bootstrap.log")
    source_paths = [
        os.path.join(path, GENERATED_PROXY_CONFIG),
        os.path.join(path, MAIN_PROXY_CONFIG),
    ]
    for source_path in source_paths:
        if not os.path.isfile(source_path):
            continue
        with tempfile.TemporaryDirectory() as runtime_dir:
            config_path = os.path.join(runtime_dir, "bootstrap.yaml")
            # 端口必须动态分配：本机代理客户端通常占着 7890/9090，写死会绑定失败
            mixed_port, _ = find_free_port_block(size=1, start=17000, stop=17700)
            controller_port, _ = find_free_port_block(size=1, start=17700, stop=18000)
            if mixed_port is None or controller_port is None:
                mixed_port, controller_port = MAIN_MIXED_PORT, MAIN_CONTROLLER_PORT
            try:
                group_name = _write_bootstrap_config(
                    source_path, config_path, mixed_port=mixed_port,
                    controller_port=controller_port)
            except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as error:
                logger.warning("无法从 %s 准备采集节点: %s", source_path, error)
            else:
                wait_seconds = (BOOTSTRAP_LAUNCH_WAIT_SECONDS
                                if os.path.basename(source_path) == GENERATED_PROXY_CONFIG
                                else FALLBACK_LAUNCH_WAIT_SECONDS)
                proc, port, actual_controller = _launch_clash(
                    exe_path, config_path, bootstrap_log, wait_seconds, data_dir=path)
                if proc:
                    with open(config_path, encoding="utf-8") as config_file:
                        runtime_config = yaml.safe_load(config_file)
                    node_names = runtime_config["proxy-groups"][0]["proxies"]
                    if _check_bootstrap_proxy(proc, port, group_name, node_names,
                                              controller_port=actual_controller):
                        logger.info("采集代理已通过出站检查，HTTP 端口 %s", port)
                        return proc, port
                    logger.warning("配置 %s 中没有可用采集节点，停止并继续检查其他配置；详情见 %s",
                                   os.path.basename(source_path), bootstrap_log)
                    stop_proxies(proc)

    logger.warning("未能启动任何本地代理配置，将直连拉取订阅")
    return None, None


def stop_proxies(proc):
    if proc:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("Clash 进程未在 5 秒内退出，强制终止...")
            proc.kill()
            proc.wait()


def _collect_proxies(proxies, use_local_proxy, proxy_port):
    """把 RSS 与 Clash 两类订阅源的结果追加到 proxies。

    单个源抛异常不能中断整轮采集，否则另一类源已经拿到的节点会全部丢失。
    """
    try:
        proxies.extend(get_subscribe_proxies(use_local_proxy=use_local_proxy,
                                             proxy_port=proxy_port) or [])
    except Exception as e:
        logger.error("获取 RSS 订阅节点时发生未预期异常: %s", e, exc_info=True)
    try:
        proxies.extend(get_clash_proxies(use_local_proxy=use_local_proxy,
                                         proxy_port=proxy_port))
    except Exception as e:
        logger.error("获取 Clash 订阅节点时发生未预期异常: %s", e, exc_info=True)


def main(env, dirs):
    # 每轮重新探测出口代理：常驻模式下用户可能中途才启动代理客户端，
    # 若沿用上一轮的负缓存（空字符串）就会永远走直连，再也抓不到被墙的源站。
    global _FALLBACK_PROXY_CACHE
    _FALLBACK_PROXY_CACHE = None

    proc, proxy_port = start_proxies()
    if proc is None:
        logger.warning("没有通过检查的 Clash 采集节点，本轮尝试直连订阅源")

    proxies = []
    try:
        route = f"本地 Clash 127.0.0.1:{proxy_port or MAIN_MIXED_PORT}" if proc else "直连"
        logger.info("本轮 RSS 与 Clash 订阅请求使用 %s", route)
        _collect_proxies(proxies, proc is not None, proxy_port)

        # 本地代理这一轮一个节点都没抓到（节点在中途失效/被限速），
        # 不能就此判定本轮失败：退到直连再试一次，否则整轮产出为 0。
        if proc is not None and not proxies:
            logger.warning("经本地代理未抓到任何节点，改用直连重试一次")
            stop_proxies(proc)
            proc = None
            _FALLBACK_PROXY_CACHE = None
            _collect_proxies(proxies, False, None)
    finally:
        stop_proxies(proc)
    proxies = filter_proxies(proxies)

    logger.info("去重后共 %d 个节点", len(proxies))

    # 异步 TCP 连通性测试（利用 Linux epoll）
    timeout = 5
    if len(proxies) > 1000:
        timeout = 2
    elif len(proxies) > 500:
        timeout = 4

    logger.info("开始异步 TCP 测试，共 %d 个节点...", len(proxies))
    available_proxies = asyncio.run(test_proxies_async(proxies, timeout=timeout))
    logger.info("TCP 测试通过: %d/%d 个节点", len(available_proxies), len(proxies))

    # 测试 proxies 的可用性
    if available_proxies:
        available_proxies = test_nodes(available_proxies, env, dirs, timeout)
    logger.info("可用节点总数: %d", len(available_proxies))
    # 回传结果，便于入口/调用方判断本次是否真的产出了配置
    return available_proxies


def parse_command_args():
    """
    解析命令行参数，支持 -p/--profile 和 -d/--directory 参数，顺序不限
    返回：解析后的参数字典
    """
    # 1. 创建参数解析器
    parser = argparse.ArgumentParser(
        description="解析命令行参数示例：支持-p（环境，可选）和-d（目录，可选）参数，顺序不限",
        formatter_class=argparse.RawTextHelpFormatter  # 保持帮助文本格式
    )

    # 2. 添加需要的参数（-p/--profile 是短参数/长参数，required=True 表示必传）
    parser.add_argument(
        '-p', '--profile',  # 参数名：短参数-p，长参数--profile
        type=str,          # 参数类型：字符串
        required=False,     # 是否必传：是
        help='运行环境标识，例如 dev/prod/test'
    )

    parser.add_argument(
        '-d', '--directory',  # 参数名：短参数-d，长参数--directory
        type=str,
        required=False,
        help='目标目录路径，例如 ./data 或 /home/user/dir'
    )

    parser.add_argument(
        '--interval',  # 循环间隔（小时）
        type=float,
        required=False,
        default=DEFAULT_INTERVAL_HOURS,
        help=f'循环执行的间隔小时数，默认 {DEFAULT_INTERVAL_HOURS:g}（仅在不带 --once 时生效）'
    )

    parser.add_argument(
        '--once',  # 只跑一次，供 cron / CI 使用
        action='store_true',
        help='只执行一次后退出（CI / 外部 cron 场景），默认是定时循环执行'
    )

    # 3. 解析参数（自动处理参数顺序，忽略顺序差异）
    args = parser.parse_args()

    # 4. 转换为字典（方便使用）
    return {
        'profile': args.profile,
        'directory': args.directory,
        'interval': args.interval,
        'once': args.once,
    }


def run_round(env, dirs):
    """执行一轮完整的订阅采集与测速，返回可用节点列表。

    异常向上抛出，由调用方决定是直接退出（--once）还是继续下一轮（循环模式）。
    """
    results = main(env, dirs)
    if results:
        logger.info("本次更新完成，可用节点 %d 个，环境 %s，输出目录 %s",
                    len(results), env, dirs)
    else:
        logger.error("本次更新未产出任何可用节点，未写入配置")
    return results


def install_stop_handlers(stop_event):
    """注册 SIGINT/SIGTERM，让常驻进程能被 systemd/docker stop 优雅结束。"""

    def _handler(signum, _frame):
        logger.info("收到退出信号 %s，本轮结束后停止循环", signum)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            # 非主线程或平台不支持该信号时忽略
            logger.debug("注册信号 %s 失败，忽略", sig)


def wait_next_round(seconds, stop_event):
    """可被退出信号提前唤醒的等待；返回 True 表示收到退出信号。"""
    logger.info("等待 %.1f 分钟后进行下一轮更新...", seconds / 60)
    return stop_event.wait(seconds)


def run_forever(env, dirs, interval_hours):
    """定时循环执行：启动后立即跑一轮，之后每 interval_hours 小时重复一次。"""
    interval_seconds = interval_hours * 3600
    stop_event = threading.Event()
    install_stop_handlers(stop_event)
    round_no = 0
    while not stop_event.is_set():
        round_no += 1
        logger.info("第 %d 轮订阅更新开始（间隔 %.1f 小时）", round_no, interval_hours)
        try:
            run_round(env, dirs)
        except Exception:
            # 单轮失败不能让常驻进程退出，否则定时更新就断了
            logger.exception("第 %d 轮订阅更新异常，继续下一轮", round_no)
        if wait_next_round(interval_seconds, stop_event):
            break
    logger.info("已停止定时循环，共执行 %d 轮", round_no)


# 主函数入口
if __name__ == '__main__':
    instance_lock = acquire_instance_lock()
    if instance_lock is None:
        logger.warning("检测到已有订阅更新进程（%s），本次启动退出", BASE_DIR)
        raise SystemExit(0)

    # 接收运行时用参数-p/-d指定的参数
    # 解析命令行参数
    args = parse_command_args()

    env = "dev"
    if "profile" in args and args["profile"]:
        env = args["profile"]
    # 默认输出到 subscribe/，与 README 描述的 subscribe/clash.yaml 保持一致
    dirs = os.path.join(os.path.dirname(__file__), "subscribe")
    if "directory" in args and args["directory"]:
        dirs = args["directory"]

    interval_hours = args.get("interval") or DEFAULT_INTERVAL_HOURS
    if interval_hours <= 0:
        logger.error("--interval 必须大于 0，当前为 %s", interval_hours)
        raise SystemExit(1)

    if args.get("once"):
        # 单次执行：供 GitHub Actions / 系统 cron 等外部调度器调用
        try:
            results = run_round(env, dirs)
        except Exception:
            logger.exception("订阅更新流程异常中止")
            raise SystemExit(1)
        if not results:
            raise SystemExit(2)
    else:
        # 默认行为：常驻定时循环执行
        run_forever(env, dirs, interval_hours)
