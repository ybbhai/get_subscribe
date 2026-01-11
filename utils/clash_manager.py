import os
import yaml
import subprocess
import time
import requests

BIN_PATH = os.path.join(os.path.dirname(__file__), "../clash")

API = "http://127.0.0.1:9090"
HEADERS = {"Authorization": "Bearer test-secret"}

class ClashMetaManager:
    def __init__(self, base, test):
        self.base = os.path.join(BIN_PATH, base)
        self.test = os.path.join(BIN_PATH, test)
        self.test_template = os.path.join(BIN_PATH, "test_template.yaml")
        self.proc = None

    def write_config(self, proxies, env=None, file_path=None):
        with open(self.test_template, "r", encoding="utf-8") as f:
            base_config = yaml.safe_load(f)

        if env and file_path and env == "prod" and os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                test_config = yaml.safe_load(f)
            proxies.extend(test_config["proxies"])

        base_config["proxies"] = proxies
        proxy_names = [p["name"] for p in proxies]
        base_config["proxy-groups"][0]["proxies"] = proxy_names

        with open(self.test, "w", encoding="utf-8") as f:
            yaml.safe_dump(base_config, f, allow_unicode=True)

    def start(self):
        exe = "linux-compatible" if os.name != "nt" else "windows-compatible.exe"
        exe_path = os.path.join(BIN_PATH, exe)

        self.proc = subprocess.Popen(
            [exe_path, "-f", self.test],
            stdout=open("clash.log", "w"),
            stderr=subprocess.STDOUT,
        )
        time.sleep(5)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=5)

    def switch_proxy(self, proxy_name=None):
        r = requests.put(
            f"{API}/proxies/TEST",
            json={"name": proxy_name},
            headers=HEADERS,
            timeout=3,
        )
        r.raise_for_status()
        time.sleep(6)

    def list_proxies(self):
        url = "http://127.0.0.1:9090/proxies"
        headers = {"Authorization": "Bearer my-secret"}
        return requests.get(url, headers=headers).json()

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
