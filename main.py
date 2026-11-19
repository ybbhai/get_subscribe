import argparse
import asyncio
from html.parser import HTMLParser
import ipaddress
import logging
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from urllib.parse import quote

import feedparser
import requests
import yaml
from urllib3.util.retry import Retry

from utils.utils import test_nodes, v2ray_2_clash, SSLAdapter, clean_yaml_content, parse_special_clash, filter_proxies, \
    test_proxies_async
from utils.clash_manager import GENERATED_PROXY_CONFIG, read_listen_ports

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
BOOTSTRAP_CHECK_URL = "https://www.gstatic.com/generate_204"
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


def _subscription_session(use_local_proxy, proxy_port):
    session = requests.Session()
    session.trust_env = False
    session.verify = (os.environ.get('REQUESTS_CA_BUNDLE')
                      or os.environ.get('CURL_CA_BUNDLE') or True)
    if use_local_proxy:
        proxy_url = f'http://127.0.0.1:{proxy_port or MAIN_MIXED_PORT}'
        session.proxies = {'http': proxy_url, 'https': proxy_url}
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
            logger.warning("v2ray 订阅 URL 无效，跳过: %s", v2ray_url[:80])
        else:
            try:
                v2ray_req = session.get(v2ray_url, timeout=SUBSCRIPTION_TIMEOUT)
            except requests.exceptions.RequestException as e:
                # 单个订阅源失败不能终止整个采集流程，否则后续 URL/节点全部丢失
                logger.error("请求 v2ray 订阅失败：%s", e)
                write_log(f"请求 v2ray 订阅失败：{v2ray_url}", "WARN")
            else:
                v2ray_code = v2ray_req.status_code
                if v2ray_code not in ok_code:
                    write_log(f"获取 v2ray 订阅失败：{v2ray_url} - {v2ray_code}", "WARN")
                else:
                    update_list.append(f"v2ray: {v2ray_code}")
                    proxies.extend(v2ray_2_clash(content=v2ray_req.text))
    # 获取clash订阅链接
    clash_url = subscription_urls.get("clash")
    if clash_url:
        # 只请求合法 URL，避免捕获到非 URL 文本
        if not clash_url.startswith(("http://", "https://")):
            logger.warning("clash 订阅 URL 无效，跳过: %s", clash_url[:80])
        else:
            try:
                clash_req = session.get(clash_url, timeout=SUBSCRIPTION_TIMEOUT)
            except requests.exceptions.RequestException as e:
                # 同上：clash 订阅失败不应丢弃已解析出的 v2ray 节点
                logger.error("请求 clash 订阅失败：%s", e)
                write_log(f"请求 clash 订阅失败：{clash_url}", "WARN")
            else:
                clash_code = clash_req.status_code
                if clash_code not in ok_code:
                    write_log(f"获取 clash 订阅失败：{clash_url} - {clash_code}", "WARN")
                else:
                    update_list.append(f"clash: {clash_code}")
                    clash_content = clash_req.content.decode("utf-8")
                    try:
                        parsed = yaml.safe_load(clash_content)
                        if parsed and "proxies" in parsed:
                            proxies.extend(parsed["proxies"])
                        else:
                            logger.warning("clash 订阅内容中无 proxies 字段，跳过: %s", clash_url)
                    except yaml.YAMLError as e:
                        logger.error("解析 clash 订阅 YAML 失败（%s）: %s", clash_url, e)
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
        for url in urls:
            url = url.format(stamp=stamp, year=year, month=month, day=day)
            # 获取链接文件内容
            raw_content = None
            try:
                req = session.get(url,
                                  timeout=timeout,
                                  headers={
                                      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
                if req.status_code not in ok_code:
                    logger.warning("Clash 订阅返回 HTTP %d: %s", req.status_code, url)
                    continue
                raw_content = req.content.decode("utf-8-sig")
                if (req.headers.get("Content-Type", "").lower().startswith("text/html")
                        or raw_content.lstrip().lower().startswith(("<!doctype html", "<html"))):
                    logger.warning("Clash 订阅返回 HTML 页面，跳过: %s", url)
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
                    logger.warning("Clash 订阅响应中未解析到节点: %s", url)
                proxies.extend(nodes)
            except Exception as error:
                logger.warning("获取 Clash 订阅失败: %s（%s）", url, error)
    finally:
        session.close()
    return proxies


def _write_bootstrap_config(source_path, output_path):
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
        "mixed-port": MAIN_MIXED_PORT,
        "external-controller": f"127.0.0.1:{MAIN_CONTROLLER_PORT}",
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


def _config_has_proxy_nodes(config_path):
    try:
        with open(config_path, encoding="utf-8") as source:
            config = yaml.safe_load(source)
    except (OSError, yaml.YAMLError):
        return False
    return isinstance(config, dict) and bool(config.get("proxies"))


def _launch_clash(exe_path, config_path, log_path, wait_seconds, data_dir=None):
    """用指定配置启动一个 Clash 进程，并轮询 API 确认就绪。

    成功返回 (proc, mixed_port)，失败返回 (None, None) 并已清理进程。
    controller 和 HTTP 代理端口从实际启动配置读取。
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
        return None, None

    api_url = f"http://127.0.0.1:{controller_port}/version"
    deadline = time.monotonic() + wait_seconds
    with requests.Session() as session:
        session.trust_env = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                logger.error("Clash 进程提前退出（exit_code=%s），详情见 %s",
                             proc.returncode, log_path)
                return None, None
            try:
                if session.get(api_url, timeout=1).status_code == 200 and proc.poll() is None:
                    return proc, mixed_port
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.5)

    logger.error("Clash API 在 %d 秒内未就绪，详情见 %s", wait_seconds, log_path)
    stop_proxies(proc)
    return None, None


def _check_bootstrap_proxy(proc, port, group_name, node_names, max_wait_seconds=45):
    """逐个测试节点、切换到首个可用节点，并验证代理确实能出站。"""
    controller_url = f"http://127.0.0.1:{MAIN_CONTROLLER_PORT}"
    deadline = time.monotonic() + max_wait_seconds
    with _subscription_session(True, port) as proxy_session, requests.Session() as api_session:
        api_session.trust_env = False
        for node_name in node_names:
            if proc.poll() is not None or time.monotonic() >= deadline:
                return False

            encoded_name = quote(node_name, safe="")
            try:
                delay = api_session.get(
                    f"{controller_url}/proxies/{encoded_name}/delay",
                    params={"url": BOOTSTRAP_CHECK_URL, "timeout": 3000},
                    timeout=4,
                )
                if delay.status_code != 200 or not delay.json().get("delay"):
                    logger.warning("采集节点不可用，尝试下一个节点: %s", node_name)
                    continue

                switched = api_session.put(
                    f"{controller_url}/proxies/{quote(group_name, safe='')}",
                    json={"name": node_name},
                    timeout=3,
                )
                switched.raise_for_status()
                current = api_session.get(
                    f"{controller_url}/proxies/{quote(group_name, safe='')}",
                    timeout=3,
                )
                current.raise_for_status()
                if current.json().get("now") != node_name:
                    logger.warning("Clash 未切换到节点 %s，尝试下一个节点", node_name)
                    continue

                with proxy_session.get(
                        BOOTSTRAP_CHECK_URL, timeout=5, allow_redirects=False) as response:
                    if response.status_code == 204 and proc.poll() is None:
                        logger.info("采集节点已就绪并通过出站检查: %s", node_name)
                        return True
                logger.warning("节点 %s 延迟探测通过但出站检查失败，继续切换", node_name)
            except (requests.exceptions.RequestException, ValueError, AttributeError) as error:
                logger.warning("采集节点探测失败，尝试下一个节点: %s（%s）", node_name, error)
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
            try:
                group_name = _write_bootstrap_config(source_path, config_path)
            except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as error:
                logger.warning("无法从 %s 准备采集节点: %s", source_path, error)
            else:
                proc, port = _launch_clash(exe_path, config_path, bootstrap_log, 10,
                                           data_dir=path)
                if proc:
                    with open(config_path, encoding="utf-8") as config_file:
                        runtime_config = yaml.safe_load(config_file)
                    node_names = runtime_config["proxy-groups"][0]["proxies"]
                    if _check_bootstrap_proxy(proc, port, group_name, node_names):
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


def main(env, dirs):
    proc, proxy_port = start_proxies()
    if proc is None:
        logger.error("没有可用的 Clash 采集节点，本轮中止，不请求订阅源")
        return []

    proxies = []
    try:
        route = f"本地 Clash 127.0.0.1:{proxy_port or MAIN_MIXED_PORT}"
        logger.info("本轮 RSS 与 Clash 订阅请求使用 %s", route)
        try:
            proxies.extend(get_subscribe_proxies(use_local_proxy=True,
                                                proxy_port=proxy_port) or [])
        except Exception as e:
            logger.error("获取 RSS 订阅节点时发生未预期异常: %s", e, exc_info=True)
        try:
            proxies.extend(get_clash_proxies(use_local_proxy=True,
                                             proxy_port=proxy_port))
        except Exception as e:
            logger.error("获取 Clash 订阅节点时发生未预期异常: %s", e, exc_info=True)
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
