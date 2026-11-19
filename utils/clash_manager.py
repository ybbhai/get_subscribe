import logging
import json
import os
import socket
import yaml
import subprocess
import time
import requests

BIN_PATH = os.path.join(os.path.dirname(__file__), "../clash")
logger = logging.getLogger(__name__)

# 上次生成的完整配置副本，落在 clash/ 下供下一次采集时启动本地代理使用
GENERATED_PROXY_CONFIG = "proxy_generated.yaml"


def _is_port_free(port):
    """尝试监听该端口，用来判断能否分配给 Clash 实例。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def find_free_port_block(size=2, start=17000, stop=17700, step=10):
    """找一段连续空闲端口，返回 (起始端口, 结束端口)；找不到返回 (None, None)。

    不能写死 7890/7891/9090：用户本机开着代理客户端时这些端口几乎总是被占用，
    Clash 会直接绑定失败，整批节点测试就全部作废。调用方若需要并行起多个实例，
    请传入互不重叠的 [start, stop) 窗口，避免两个 worker 抢到同一段端口。
    """
    for base in range(start, stop, step):
        ports = range(base, base + size)
        if all(_is_port_free(port) for port in ports):
            return base, base + size - 1
    logger.warning("端口区间 [%s, %s) 内找不到连续 %d 个空闲端口", start, stop, size)
    return None, None


def _local_api_session():
    """访问本机 Clash REST API 专用的 session。

    必须 trust_env=False：本机 API 请求一旦被 HTTP_PROXY/HTTPS_PROXY 转发到
    外部代理，就会拿到 502/超时，表现为“Clash 起不来”“节点切不过去”，
    而实际上内核运行正常。用户的 no_proxy 不一定包含 127.0.0.1。
    """
    session = requests.Session()
    session.trust_env = False
    return session


def read_listen_ports(config_path, default_controller=9090, default_mixed=7890):
    """读取配置文件里实际生效的 controller 与 http 端口。

    生成的配置来自 base_template.yaml（controller 9090 / port 7890），
    而 proxy.yaml 用的是 9099，两者不一致；健康检查必须按文件里的真实值来，
    否则会出现“进程已就绪但轮询不到”的假失败。
    """
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        logger.warning("读取 %s 端口配置失败: %s", config_path, e)
        return default_controller, default_mixed

    controller_port = default_controller
    controller = config.get("external-controller")
    if isinstance(controller, str) and ":" in controller:
        _, _, port_text = controller.rpartition(":")
        if port_text.isdigit():
            controller_port = int(port_text)

    mixed_port = default_mixed
    for key in ("mixed-port", "port"):
        value = config.get(key)
        if isinstance(value, int) and value > 0:
            mixed_port = value
            break
    return controller_port, mixed_port


def _normalize_proxies(proxies):
    normalized = []
    seen_nodes = set()
    used_names = set()
    name_counts = {}
    for proxy in proxies or []:
        proxy_copy = dict(proxy)
        identity_data = {
            key: value for key, value in proxy_copy.items()
            if key != "name"
        }
        # 对 _categories 等集合类型进行排序，确保序列化结果一致
        if isinstance(identity_data.get('_categories'), set):
            identity_data['_categories'] = sorted(identity_data['_categories'])
        identity = json.dumps(identity_data, sort_keys=True, ensure_ascii=False, default=str)
        if identity in seen_nodes:
            continue
        seen_nodes.add(identity)

        base_name = str(proxy_copy.get("name") or "proxy")
        name = base_name
        suffix = name_counts.get(base_name, 1)
        while name in used_names:
            name = f"{base_name}-{suffix}"
            suffix += 1
        name_counts[base_name] = suffix
        used_names.add(name)
        proxy_copy["name"] = name
        normalized.append(proxy_copy)
    return normalized


def select_export_proxies(proxies, limit=50):
    selected_indexes = set()
    required = {"google", "youtube", "chatgpt"}
    for categories in (required, {"google"}, {"youtube"}, {"chatgpt"}):
        candidate = next((index for index, proxy in enumerate(proxies)
                          if categories.issubset(proxy.get("_categories", set()))), None)
        if candidate is not None and len(selected_indexes) < limit:
            selected_indexes.add(candidate)
    for index in range(len(proxies)):
        if len(selected_indexes) >= limit:
            break
        selected_indexes.add(index)
    return [proxy for index, proxy in enumerate(proxies) if index in selected_indexes]


class ClashMetaManager:
    def __init__(self, base, test, controller_port=9090, http_port=7890, socks_port=7891,
                 secret="test-secret", log_file="clash.log"):
        self.base = os.path.join(BIN_PATH, base)
        self.test = os.path.join(BIN_PATH, test)
        self.test_template = os.path.join(BIN_PATH, "test_template.yaml")
        # 模板文件缺失/路径写错时提前抛清晰异常，避免 start() 时才发现
        for label, path in (("base template", self.base), ("test_template", self.test_template)):
            if not os.path.isfile(path):
                raise FileNotFoundError(f"{label} not found: {path}")
        self.proc = None
        self._log_handle = None
        self.controller_port = controller_port
        self.http_port = http_port
        self.socks_port = socks_port
        self.secret = secret
        self.log_file = log_file

    @property
    def api(self):
        return f"http://127.0.0.1:{self.controller_port}"

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.secret}"}

    def write_config(self, proxies, output_path=None):
        with open(self.test_template, "r", encoding="utf-8") as f:
            base_config = yaml.safe_load(f)

        base_config["port"] = self.http_port
        base_config["socks-port"] = self.socks_port
        base_config["external-controller"] = f"127.0.0.1:{self.controller_port}"
        base_config["secret"] = self.secret

        proxies = _normalize_proxies(proxies)
        base_config["proxies"] = [
            {key: value for key, value in proxy.items() if not key.startswith("_")}
            for proxy in proxies
        ]
        proxy_names = [p["name"] for p in proxies]
        # 只将节点加入第一个 select 组（"TEST"），其他组保持原样
        groups = base_config.get("proxy-groups")
        if groups:
            groups[0]["proxies"] = proxy_names

        target_path = output_path or self.test
        target_dir = os.path.dirname(target_path)
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)

        with open(target_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(base_config, f, allow_unicode=True)

    def start(self, config_path=None):
        """
        启动 Clash 实例，并轮询 API 确认真正就绪（最多等待 30 秒）。
        比固定 time.sleep(5) 更可靠。
        """
        exe = "linux-compatible" if os.name != "nt" else "windows-compatible.exe"
        exe_path = os.path.join(BIN_PATH, exe)
        target_path = config_path or self.test

        self._log_handle = open(self.log_file, "w", encoding="utf-8")

        self.proc = subprocess.Popen(
            [exe_path, "-f", target_path],
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
        )
        # 轮询 external-controller API 确认 Clash 已就绪
        api_url = f"{self.api}/version"
        with _local_api_session() as session:
            for _ in range(30):
                # 提前终止：若进程已退出（配置错误、端口占用等），无需继续等待
                if self.proc.poll() is not None:
                    logger.error("Clash 进程提前退出（exit_code=%s），config=%s",
                                 self.proc.returncode, target_path)
                    raise RuntimeError(f"Clash exited before readiness: {target_path}")
                try:
                    r = session.get(api_url, headers=self.headers, timeout=2)
                    if r.status_code == 200:
                        return
                except requests.exceptions.RequestException:
                    pass
                time.sleep(1)
        raise TimeoutError(f"Clash API not ready within 30 seconds: {target_path}")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
            self.proc = None
        if self._log_handle:
            try:
                self._log_handle.close()
            except Exception:
                pass
            self._log_handle = None

    def switch_proxy(self, proxy_name=None) -> bool:
        """
        通过 Clash REST API 将 TEST 组切换到指定节点。
        切换后轮询确认节点已生效（最多等待 10 秒）。

        返回 True 表示切换成功；返回 False 表示切换失败或超时，
        调用方应跳过该节点的测试（避免用错误节点测数据）。
        """
        try:
            with _local_api_session() as session:
                r = session.put(
                    f"{self.api}/proxies/TEST",
                    json={"name": proxy_name},
                    headers=self.headers,
                    timeout=3,
                )
                r.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.warning("switch_proxy PUT 失败（%s）: %s", proxy_name, e)
            return False

        # 轮询确认当前选中节点已切换为 proxy_name
        last_now = None
        with _local_api_session() as session:
            for _ in range(10):
                try:
                    status = session.get(
                        f"{self.api}/proxies/TEST",
                        headers=self.headers,
                        timeout=2,
                    ).json()
                    last_now = status.get("now")
                    if last_now == proxy_name:
                        return True
                except requests.exceptions.RequestException:
                    pass
                except (ValueError, AttributeError) as e:
                    # API 返回非 JSON 或字段缺失
                    logger.debug("switch_proxy GET 解析失败: %s", e)
                    pass
                time.sleep(0.5)

        # 超时未确认切换成功，记录实际状态便于排查
        logger.warning("switch_proxy: 等待节点 %s 生效超时（当前 now=%s）", proxy_name, last_now)
        return False

    def save_config(self, proxies, clash_name, mirror_only=False):
        """写出最终配置；``mirror_only=True`` 时只刷新采集缓存，不碰投放文件。

        dev 模式需要刷新 clash/proxy_generated.yaml（下次启动靠它借上次的有效
        节点），但绝不能覆盖 subscribe/clash.yaml —— 那是投放产物。
        """
        with open(self.base, "r", encoding="utf-8") as f:
            base_config = yaml.safe_load(f)

        proxies = select_export_proxies(_normalize_proxies(proxies))
        base_config["proxies"] = [
            {key: value for key, value in proxy.items() if not key.startswith("_")}
            for proxy in proxies
        ]
        groups = base_config.get("proxy-groups")
        if groups is None:
            logger.warning("save_config: base 配置中无 proxy-groups，跳过组更新")
            groups = []
        selection = next((group["name"] for group in groups if "节点选择" in group["name"]), None)
        automatic = next((group["name"] for group in groups if "自动选择" in group["name"]), None)
        global_names = [proxy["name"] for proxy in proxies
                if {"google", "youtube", "chatgpt"}.issubset(proxy.get("_categories", set()))]
        for group in groups:
            group_type = group.get("type", "")
            group_name = group.get("name", "")
            service = next((service for service in ("google", "youtube", "chatgpt")
                            if service in group_name.lower()), None)
            if service:
                members = [proxy["name"] for proxy in proxies
                           if service in proxy.get("_categories", set())]
                group["proxies"] = members or ["REJECT"]
                group["type"] = "url-test" if members else "select"
                if members:
                    group.update({
                        "url": {
                            "google": "https://www.google.com/generate_204",
                            "youtube": "https://www.youtube.com",
                            "chatgpt": "https://chatgpt.com/api/auth/providers",
                        }[service],
                        "expected-status": 204 if service == "google" else 200,
                        "interval": 120, "timeout": 6000, "lazy": False,
                        "tolerance": 50,
                    })
                else:
                    for key in ("url", "interval", "expected-status", "timeout", "lazy", "tolerance"):
                        group.pop(key, None)
                continue
            if group_type == "select" and "节点选择" in group_name:
                group["proxies"] = list(dict.fromkeys(
                    ([automatic] if automatic else []) + global_names)) or ["REJECT"]
            elif group_type == "url-test":
                group["proxies"] = global_names or ["REJECT"]
                group.update({"url": "https://www.gstatic.com/generate_204",
                              "expected-status": 204, "interval": 120,
                              "timeout": 6000, "lazy": False, "tolerance": 50})
            elif group_type == "select" and selection in group.get("proxies", []):
                group["proxies"] = list(dict.fromkeys(group["proxies"] +
                    ([automatic] if automatic else []) + global_names))

        global_group = next((group for group in groups if group.get("name") == "GLOBAL"), None)
        if global_group is None:
            global_group = {"name": "GLOBAL", "type": "select"}
            groups.append(global_group)
        global_group["type"] = "select"
        global_group["include-all"] = False
        global_group["proxies"] = list(dict.fromkeys(
            [name for name in (selection, automatic) if name] + global_names)) or ["REJECT"]
        base_config["proxy-groups"] = groups
        base_config.setdefault("profile", {})["store-selected"] = True

        target_path = clash_name
        if not os.path.isabs(target_path) and not os.path.dirname(target_path):
            target_path = os.path.join(BIN_PATH, target_path)
        if not mirror_only:
            target_dir = os.path.dirname(target_path)
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)
            with open(target_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(base_config, f, allow_unicode=True)

        # 在 clash/ 下留一份副本，供下一次采集时用真实节点启动本地代理
        # （main.start_proxies 会优先读取它，见 GENERATED_PROXY_CONFIG）。
        # 这份缓存不更新的话，下次启动永远没有可用采集节点，只能一路直连。
        mirror_path = os.path.join(BIN_PATH, GENERATED_PROXY_CONFIG)
        if mirror_only or os.path.abspath(mirror_path) != os.path.abspath(target_path):
            try:
                with open(mirror_path, "w", encoding="utf-8") as f:
                    yaml.safe_dump(base_config, f, allow_unicode=True)
                logger.info("已写入代理配置副本: %s", mirror_path)
            except OSError as e:
                # 副本只是优化项，写失败不应影响主配置产出
                logger.warning("写入代理配置副本失败（%s）: %s", mirror_path, e)
