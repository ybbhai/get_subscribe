import argparse
import asyncio
import logging
import os
import re
import signal
import subprocess
import threading
import time

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
    format="[%(asctime)s] [%(levelname)s] %(message)s",
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

# 默认循环间隔（小时）。README 与 CI cron 都是 2 小时一轮。
DEFAULT_INTERVAL_HOURS = 2.0


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


def get_subscribe_proxies(use_local_proxy=True, proxy_port=None):
    dirs = './subscribe'
    if not os.path.exists(dirs):
        os.makedirs(dirs)
    log_dir = "./log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    port = proxy_port or MAIN_MIXED_PORT
    old_http = os.environ.get('HTTP_PROXY')
    old_https = os.environ.get('HTTPS_PROXY')

    if use_local_proxy:
        os.environ['HTTP_PROXY'] = f'http://127.0.0.1:{port}'
        os.environ['HTTPS_PROXY'] = f'http://127.0.0.1:{port}'

    rss = None
    try:
        rss = feedparser.parse('https://www.cfmem.com/feeds/posts/default?alt=rss')
    except Exception as e:
        logger.error("拉取 RSS 失败: %s", e)
        return []
    finally:
        if use_local_proxy:
            if old_http:
                os.environ['HTTP_PROXY'] = old_http
            else:
                os.environ.pop('HTTP_PROXY', None)

            if old_https:
                os.environ['HTTPS_PROXY'] = old_https
            else:
                os.environ.pop('HTTPS_PROXY', None)

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
    v2ray_list = re.findall(r">V2Ray/XRay -&gt; (.*?)</span>", summary)
    proxies = []
    # 获取普通订阅链接
    if any(v2ray_list) and not v2ray_list[-1].startswith("订阅地址生成失败"):
        v2ray_url = v2ray_list[-1].replace('&amp;', '&').strip()
        # 只请求合法 URL，避免捕获到非 URL 文本
        if not v2ray_url.startswith(("http://", "https://")):
            logger.warning("v2ray 订阅 URL 无效，跳过: %s", v2ray_url[:80])
        else:
            try:
                v2ray_req = requests.get(v2ray_url, timeout=30)
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
    clash_list = re.findall(r">clash -&gt; (.*?)</span>", summary)
    # 获取clash订阅链接
    if any(clash_list) and not clash_list[-1].startswith("订阅地址生成失败"):
        clash_url = clash_list[-1].replace('&amp;', '&').strip()
        # 只请求合法 URL，避免捕获到非 URL 文本
        if not clash_url.startswith(("http://", "https://")):
            logger.warning("clash 订阅 URL 无效，跳过: %s", clash_url[:80])
        else:
            try:
                clash_req = requests.get(clash_url, timeout=30)
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
    port = proxy_port or MAIN_MIXED_PORT
    clash_proxies = {
        'http': f'http://127.0.0.1:{port}',
        'https': f'http://127.0.0.1:{port}'
    }

    proxies = []
    # 创建 session 并配置 SSL 适配器、超时、重试策略
    session = requests.Session()
    if use_local_proxy:
        session.proxies = clash_proxies
    retry = Retry(total=3, connect=3, read=3, backoff_factor=0.5,
                  status_forcelist=(429, 500, 502, 503, 504))
    session.mount("https://", SSLAdapter(max_retries=retry))
    session.mount("http://", SSLAdapter(max_retries=retry))
    # 设置超时时间（连接超时5秒，读取超时10秒）
    timeout = (5, 10)
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
                logger.debug("获取yaml文件结果: %s", req.status_code)
                if req.status_code in ok_code:
                    raw_content = req.content.decode("utf-8")
                    content = clean_yaml_content(raw_content)
                    parsed = yaml.safe_load(content)
                    if parsed and "proxies" in parsed:
                        proxies.extend(parsed["proxies"])
                    else:
                        logger.warning("URL %s 响应中无 proxies 字段，尝试特殊解析...", url)
                        proxies.extend(parse_special_clash(content))
            except Exception as e:
                if raw_content:
                    # yaml 解析失败时，尝试特殊解析
                    try:
                        proxies.extend(parse_special_clash(raw_content))
                    except Exception as e2:
                        logger.error("获取proxy失败（特殊解析也失败）：%s 原因：%s / %s", url, e, e2)
                else:
                    logger.error("获取proxy失败：%s 原因：%s", url, e)
    finally:
        session.close()
    return proxies


def _launch_clash(exe_path, config_path, log_path, wait_seconds):
    """用指定配置启动一个 Clash 进程，并轮询 API 确认就绪。

    成功返回 (proc, mixed_port)，失败返回 (None, None) 并已清理进程。
    controller/mixed 端口直接从配置文件读取，因为生成配置用 9090/7890，
    而 proxy.yaml 用 9099/7890，写死会导致“进程已就绪却轮询不到”的假失败。
    """
    controller_port, mixed_port = read_listen_ports(
        config_path, MAIN_CONTROLLER_PORT, MAIN_MIXED_PORT)
    try:
        with open(log_path, "w", encoding="utf-8") as log_handle:
            proc = subprocess.Popen(
                [exe_path, "-f", config_path],
                stdout=log_handle,
                stderr=subprocess.STDOUT,
            )
    except OSError as e:
        logger.error("启动 Clash 进程失败（%s）: %s", config_path, e)
        return None, None

    api_url = f"http://127.0.0.1:{controller_port}/version"
    for _ in range(wait_seconds * 2):
        if proc.poll() is not None:
            logger.error("Clash 进程提前退出（exit_code=%s），配置: %s",
                         proc.returncode, config_path)
            return None, None
        try:
            if requests.get(api_url, timeout=1).status_code == 200:
                return proc, mixed_port
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.5)

    logger.error("Clash API 在 %d 秒内未就绪，终止进程: %s", wait_seconds, config_path)
    stop_proxies(proc)
    return None, None


def start_proxies():
    """启动主 Clash 实例（用于订阅拉取时走本地代理）。

    配置选择顺序：
      1. ``clash/proxy_generated.yaml``（上次生成的真实节点配置）——用它拉订阅
         才能访问被墙的订阅源，是引入该文件的主要目的；
      2. ``clash/proxy.yaml``（默认直连兜底配置）。

    生成配置带 1 万多条规则且依赖 geoip.metadb，首次启动需要联网下载 geo 数据，
    因此给它更长的等待时间；若它启动失败则回退到 proxy.yaml，避免整次采集没有代理。

    返回 (proc, mixed_port)；无法启动时返回 (None, None)，main() 需做保护。
    """
    path = os.path.join(os.path.dirname(__file__), "clash")
    exe = "linux-compatible" if os.name != "nt" else "windows-compatible.exe"
    exe_path = os.path.join(path, exe)
    if not os.path.isfile(exe_path):
        logger.error("Clash 可执行文件不存在: %s，跳过订阅拉取", exe_path)
        return None, None

    # 生成配置优先；它含真实节点，但启动更慢（需下载 geo 数据）
    candidates = [
        (os.path.join(path, GENERATED_PROXY_CONFIG), 60),
        (os.path.join(path, MAIN_PROXY_CONFIG), 10),
    ]
    log_path = os.path.join(path, "clash.log")
    for config_path, wait_seconds in candidates:
        if not os.path.isfile(config_path) or os.path.getsize(config_path) == 0:
            logger.debug("配置缺失或为空，跳过: %s", config_path)
            continue
        logger.info("尝试使用配置启动本地代理: %s", os.path.basename(config_path))
        proc, mixed_port = _launch_clash(exe_path, config_path, log_path, wait_seconds)
        if proc:
            logger.info("主 Clash 已就绪（%s），HTTP 端口 %s",
                        os.path.basename(config_path), mixed_port)
            return proc, mixed_port

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
    proxies = []
    try:
        if proc is None:
            logger.warning("主 Clash 未启动，仍尝试获取可直连订阅源")
        try:
            proxies.extend(get_subscribe_proxies(use_local_proxy=proc is not None,
                                                proxy_port=proxy_port) or [])
        except Exception as e:
            logger.error("获取 RSS 订阅节点时发生未预期异常: %s", e, exc_info=True)
        try:
            proxies.extend(get_clash_proxies(use_local_proxy=proc is not None,
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
