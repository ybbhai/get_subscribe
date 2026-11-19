import os
import tempfile
import unittest

import yaml

from main import _config_has_proxy_nodes, _filter_bootstrap_nodes, _write_bootstrap_config


class BootstrapProxyTests(unittest.TestCase):
    def test_filter_rejects_loopback_and_keeps_remote_nodes(self):
        nodes = [
            {"name": "loopback-ip", "server": "127.0.0.1", "port": 10000},
            {"name": "loopback-name", "server": "localhost", "port": 10000},
            {"name": "remote", "server": "proxy.example.com", "port": 443},
        ]

        self.assertEqual(_filter_bootstrap_nodes(nodes), [nodes[-1]])

    def test_bootstrap_config_contains_only_filtered_nodes(self):
        nodes = [
            {"name": "local", "type": "ss", "server": "127.0.0.1", "port": 10000},
            {"name": "remote", "type": "ss", "server": "proxy.example.com", "port": 443},
        ]
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.yaml")
            output_path = os.path.join(directory, "bootstrap.yaml")
            with open(source_path, "w", encoding="utf-8") as source:
                yaml.safe_dump({"proxies": nodes}, source)

            _write_bootstrap_config(source_path, output_path)

            with open(output_path, encoding="utf-8") as output:
                config = yaml.safe_load(output)

        self.assertEqual([node["name"] for node in config["proxies"]], ["remote"])
        self.assertEqual(config["proxy-groups"][0]["proxies"], ["remote"])

    def test_empty_fallback_is_not_a_proxy_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "proxy.yaml")
            with open(path, "w", encoding="utf-8") as config_file:
                yaml.safe_dump({"proxies": [], "rules": ["MATCH,DIRECT"]}, config_file)

            self.assertFalse(_config_has_proxy_nodes(path))


if __name__ == "__main__":
    unittest.main()