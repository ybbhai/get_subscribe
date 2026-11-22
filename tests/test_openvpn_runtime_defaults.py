import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from main import _write_bootstrap_config
from utils.clash_manager import ClashMetaManager
from utils.proxy_chain import (
    DEPENDENCIES_KEY,
    apply_runtime_defaults,
    bind_dialer,
    materialize_proxies,
)


def openvpn(name="vpn", **settings):
    return {
        "name": name, "type": "openvpn", "server": "192.0.2.1", "port": 443,
        "proto": "tcp", "username": "vpn", "password": "fixture-password",
        "cipher": "AES-128-CBC", "auth": "SHA1", "udp": False,
        "ca": "fixture-ca", "cert": "fixture-cert", "key": "fixture-key",
        "handshake-timeout": 30, **settings,
    }


def worker(name="front"):
    return {
        "name": name, "type": "vless", "server": "104.16.0.1", "port": 443,
        "uuid": "11111111-1111-4111-8111-111111111111", "tls": True,
        "network": "ws", "servername": "worker.example",
        "ws-opts": {"path": "/?ed=2560", "headers": {"Host": "worker.example"}},
    }


class OpenVpnRuntimeDefaultsTests(unittest.TestCase):
    def test_defaults_preserve_transport_credentials_and_input(self):
        node = openvpn()
        original = copy.deepcopy(node)

        configured = apply_runtime_defaults(node)

        self.assertEqual(configured, {
            **original, "remote-dns-resolve": True, "dns": ["1.1.1.1", "8.8.8.8"],
        })
        self.assertEqual(node, original)
        self.assertEqual(apply_runtime_defaults(configured), configured)
        configured["dns"].append("9.9.9.9")
        self.assertEqual(apply_runtime_defaults(node)["dns"], ["1.1.1.1", "8.8.8.8"])

    def test_explicit_remote_resolution_and_dns_settings_are_preserved(self):
        cases = [
            ({"remote-dns-resolve": False}, {"remote-dns-resolve": False}),
            ({"remote-dns-resolve": False, "dns": []},
             {"remote-dns-resolve": False, "dns": []}),
            ({"dns": ["9.9.9.9"]},
             {"remote-dns-resolve": True, "dns": ["9.9.9.9"]}),
            ({"remote-dns-resolve": False, "dns": ["9.9.9.9"]},
             {"remote-dns-resolve": False, "dns": ["9.9.9.9"]}),
            ({"remote-dns-resolve": True, "dns": []},
             {"remote-dns-resolve": True, "dns": ["1.1.1.1", "8.8.8.8"]}),
            ({"dns": []},
             {"remote-dns-resolve": True, "dns": ["1.1.1.1", "8.8.8.8"]}),
            ({"remote-dns-resolve": True, "dns": None},
             {"remote-dns-resolve": True, "dns": None}),
        ]
        for supplied, expected in cases:
            with self.subTest(supplied=supplied):
                node = openvpn(**supplied)
                original = copy.deepcopy(node)
                self.assertEqual(apply_runtime_defaults(node), {**openvpn(), **expected})
                self.assertEqual(node, original)

    def test_ordinary_protocols_are_unchanged_and_deep_copied(self):
        for protocol in ("vless", "vmess", "trojan", "ss", "socks5", "wireguard"):
            with self.subTest(protocol=protocol):
                node = {**worker(), "type": protocol}
                configured = apply_runtime_defaults(node)
                self.assertEqual(configured, node)
                configured["ws-opts"]["headers"]["Host"] = "changed.example"
                self.assertEqual(node["ws-opts"]["headers"]["Host"], "worker.example")

    def test_dependencies_receive_defaults_without_losing_references(self):
        dependency = openvpn("shared-dialer")
        first = {**worker("first"), "dialer-proxy": dependency["name"],
                 DEPENDENCIES_KEY: [dependency]}
        second = {**worker("second"), "dialer-proxy": dependency["name"],
                  DEPENDENCIES_KEY: [apply_runtime_defaults(dependency)]}
        collision = worker("shared-dialer")
        nodes = [first, second, collision]
        original = copy.deepcopy(nodes)

        configured = materialize_proxies(nodes)

        self.assertEqual(nodes, original)
        self.assertEqual(len(configured), 4)
        self.assertEqual(len({node["name"] for node in configured}), 4)
        exported_dependency = next(node for node in configured if node["type"] == "openvpn")
        self.assertTrue(exported_dependency["remote-dns-resolve"])
        self.assertEqual(exported_dependency["dns"], ["1.1.1.1", "8.8.8.8"])
        for name in ("first", "second"):
            node = next(node for node in configured if node["name"] == name)
            self.assertEqual(node["dialer-proxy"], exported_dependency["name"])
            self.assertNotIn(DEPENDENCIES_KEY, node)
        self.assertNotEqual(exported_dependency["name"], collision["name"])

    def test_vpngate_generic_and_chained_nodes_match_test_export_and_bootstrap(self):
        nodes = [
            openvpn("vpngate", _source="vpngate"),
            openvpn("generic", **{"remote-dns-resolve": False}),
            openvpn("custom-dns", dns=["9.9.9.9"]),
            bind_dialer(openvpn("cfnew"), worker()),
        ]
        for node in nodes:
            node.update(_categories={"google"}, _latency=150,
                        _speed_kbps=8000, _download_passed=True)
        original = copy.deepcopy(nodes)
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            test_path = directory / "test.yaml"
            export_path = directory / "export.yaml"
            bootstrap_path = directory / "bootstrap.yaml"
            manager = ClashMetaManager("base_template.yaml", "test_config.yaml")
            manager.write_config(nodes, output_path=str(test_path))
            with patch("utils.clash_manager.GENERATED_PROXY_CONFIG", str(export_path)):
                manager.save_config(nodes, str(export_path))
            _write_bootstrap_config(export_path, bootstrap_path)
            configs = [yaml.safe_load(path.read_text(encoding="utf-8"))
                       for path in (test_path, export_path, bootstrap_path)]

        self.assertEqual(nodes, original)
        by_name = [{node["name"]: node for node in config["proxies"]} for config in configs]
        self.assertEqual(by_name[0], by_name[1])
        self.assertEqual(by_name[1], by_name[2])
        self.assertEqual(set(by_name[0]), {node["name"] for node in nodes}
                         | {nodes[-1]["dialer-proxy"]})
        self.assertEqual(by_name[0]["vpngate"]["dns"], ["1.1.1.1", "8.8.8.8"])
        self.assertFalse(by_name[0]["generic"]["remote-dns-resolve"])
        self.assertNotIn("dns", by_name[0]["generic"])
        self.assertEqual(by_name[0]["custom-dns"]["dns"], ["9.9.9.9"])
        self.assertEqual(by_name[0]["cfnew"]["dns"], ["1.1.1.1", "8.8.8.8"])
        self.assertNotIn("dns", by_name[0][nodes[-1]["dialer-proxy"]])

    def test_bootstrap_upgrades_old_flattened_config_and_preserves_dependencies(self):
        nodes = [
            openvpn("dialer"),
            {**worker("exit"), "dialer-proxy": "dialer"},
            openvpn("explicit", **{"remote-dns-resolve": False, "dns": []}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "old.yaml"
            output = Path(directory) / "bootstrap.yaml"
            source_text = yaml.safe_dump({"proxies": nodes})
            source.write_text(source_text, encoding="utf-8")

            _write_bootstrap_config(source, output)

            configured = yaml.safe_load(output.read_text(encoding="utf-8"))["proxies"]
            self.assertEqual(source.read_text(encoding="utf-8"), source_text)
        self.assertEqual(configured, [apply_runtime_defaults(node) for node in nodes])
        self.assertEqual(configured[0]["dns"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(configured[1]["dialer-proxy"], configured[0]["name"])
        self.assertEqual(configured[2], nodes[2])


if __name__ == "__main__":
    unittest.main()
