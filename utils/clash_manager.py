import os
import yaml
import subprocess
import time
import requests

BIN_PATH = os.path.join(os.path.dirname(__file__), "../clash")

class ClashMetaManager:
    def __init__(self, base, test, controller_port=9090, http_port=7890, socks_port=7891, secret="test-secret", log_file="clash.log"):
        self.base = os.path.join(BIN_PATH, base)
        self.test = os.path.join(BIN_PATH, test)
        self.test_template = os.path.join(BIN_PATH, "test_template.yaml")
        self.proc = None
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

        if env and file_path and env == "prod" and os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                test_config = yaml.safe_load(f)
            proxies = list(proxies)
            proxies.extend(test_config["proxies"])

        base_config["proxies"] = proxies
        proxy_names = [p["name"] for p in proxies]
        base_config["proxy-groups"][0]["proxies"] = proxy_names

        target_path = output_path or self.test
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        with open(target_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(base_config, f, allow_unicode=True)

    def start(self, config_path=None):
        exe = "linux-compatible" if os.name != "nt" else "windows-compatible.exe"
        exe_path = os.path.join(BIN_PATH, exe)
        target_path = config_path or self.test

        self._log_handle = open(self.log_file, "w", encoding="utf-8")

        self.proc = subprocess.Popen(
            [exe_path, "-f", target_path],
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
        )
        time.sleep(5)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
            self.proc = None
        if hasattr(self, "_log_handle") and self._log_handle:
            try:
                self._log_handle.close()
            except Exception:
                pass
            self._log_handle = None

    def switch_proxy(self, proxy_name=None):
        r = requests.put(
            f"{self.api}/proxies/TEST",
            json={"name": proxy_name},
            headers=self.headers,
            timeout=3,
        )
        r.raise_for_status()
        time.sleep(6)

    def list_proxies(self):
        url = f"{self.api}/proxies"
        return requests.get(url, headers=self.headers).json()

    def save_config(self, proxies, clash_name):
        with open(self.base, "r", encoding="utf-8") as f:
            base_config = yaml.safe_load(f)

        base_config["proxies"] = proxies
        proxy_names = [p["name"] for p in proxies]
        groups = base_config["proxy-groups"]
        for group in groups:
            group["proxies"].extend(proxy_names)
        # base_config["proxy-groups"][0]["proxies"] = [p["name"] for p in proxies]

        with open(os.path.join(BIN_PATH, clash_name), "w", encoding="utf-8") as f:
            yaml.safe_dump(base_config, f, allow_unicode=True)

    def clear_test(self):
        if os.path.exists(self.test):
            os.remove(self.test)
