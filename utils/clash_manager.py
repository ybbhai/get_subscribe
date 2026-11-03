import logging
import json
import os
import yaml
import subprocess
import time
import requests

BIN_PATH = os.path.join(os.path.dirname(__file__), "../clash")
logger = logging.getLogger(__name__)


def _normalize_proxies(proxies):
    normalized = []
    seen_nodes = set()
    used_names = set()
    name_counts = {}
    for proxy in proxies or []:
        proxy_copy = dict(proxy)
        identity_data = {
            key: value for key, value in proxy_copy.items()
            if key != "name" and not key.startswith("_")
        }
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

    def write_config(self, proxies, env=None, file_path=None, output_path=None):
        with open(self.test_template, "r", encoding="utf-8") as f:
            base_config = yaml.safe_load(f)

        base_config["port"] = self.http_port
        base_config["socks-port"] = self.socks_port
        base_config["external-controller"] = f"127.0.0.1:{self.controller_port}"
        base_config["secret"] = self.secret

        # prod 环境下，如果提供了历史配置文件，将其中的节点合并进来
        if env == "prod" and file_path and os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    test_config = yaml.safe_load(f)
                if test_config and test_config.get("proxies"):
                    proxies = list(proxies or [])
                    proxies.extend(test_config["proxies"])
            except Exception as e:
                logger.warning("合并历史配置失败（%s）: %s", file_path, e)

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
        for _ in range(30):
            # 提前终止：若进程已退出（配置错误、端口占用等），无需继续等待
            if self.proc.poll() is not None:
                logger.error("Clash 进程提前退出（exit_code=%s），config=%s",
                             self.proc.returncode, target_path)
                raise RuntimeError(f"Clash exited before readiness: {target_path}")
            try:
                r = requests.get(api_url, headers=self.headers, timeout=2)
                if r.status_code == 200:
                    return
            except requests.exceptions.ConnectionError:
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
            r = requests.put(
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
        for _ in range(10):
            try:
                status = requests.get(
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

    def list_proxies(self):
        url = f"{self.api}/proxies"
        return requests.get(url, headers=self.headers).json()

    def save_config(self, proxies, clash_name):
        with open(self.base, "r", encoding="utf-8") as f:
            base_config = yaml.safe_load(f)

        proxies = _normalize_proxies(proxies)[:50]
        base_config["proxies"] = [
            {key: value for key, value in proxy.items() if not key.startswith("_")}
            for proxy in proxies
        ]
        proxy_names = [p["name"] for p in proxies]
        groups = base_config.get("proxy-groups")
        if groups is None:
            logger.warning("save_config: base 配置中无 proxy-groups，跳过组更新")
            groups = []
        selection = next((group["name"] for group in groups if "节点选择" in group["name"]), None)
        automatic = next((group["name"] for group in groups if "自动选择" in group["name"]), None)
        for group in groups:
            group_type = group.get("type", "")
            group_name = group.get("name", "")
            service = next((service for service in ("google", "youtube", "chatgpt")
                            if service in group_name.lower()), None)
            if service:
                members = [proxy["name"] for proxy in proxies
                           if service in proxy.get("_categories", set())]
                group["proxies"] = list(dict.fromkeys(members + [name for name in
                    (selection, automatic) if name])) or ["DIRECT"]
                group["type"] = "select"
                group.pop("url", None)
                group.pop("interval", None)
                continue
            if group_type == "select" and "节点选择" in group_name:
                group["proxies"] = list(dict.fromkeys(
                    ([automatic] if automatic else []) + group.get("proxies", []) + proxy_names))
            elif group_type == "url-test":
                group["proxies"] = proxy_names or ["DIRECT"]
            elif group_type == "select" and selection in group.get("proxies", []):
                group["proxies"] = list(dict.fromkeys(group["proxies"] +
                    ([automatic] if automatic else []) + proxy_names))

        global_group = next((group for group in groups if group.get("name") == "GLOBAL"), None)
        if global_group is None:
            global_group = {"name": "GLOBAL", "type": "select"}
            groups.append(global_group)
        global_group["type"] = "select"
        global_group["include-all"] = False
        global_group["proxies"] = [name for name in (selection, automatic) if name] + proxy_names or ["DIRECT"]
        base_config["proxy-groups"] = groups
        base_config.setdefault("profile", {})["store-selected"] = True

        target_path = clash_name
        if not os.path.isabs(target_path) and not os.path.dirname(target_path):
            target_path = os.path.join(BIN_PATH, target_path)
        target_dir = os.path.dirname(target_path)
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(base_config, f, allow_unicode=True)

    def clear_test(self):
        if os.path.exists(self.test):
            os.remove(self.test)
