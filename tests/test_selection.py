import asyncio
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import yaml

from utils.clash_manager import ClashMetaManager
from utils.utils import _test_node_metrics_async, sort_proxies_by_performance, test_link_async, test_nodes, test_proxy_telnet_async


class SelectionTests(unittest.TestCase):
    def make_nodes(self, count):
        return [
            {"name": f"node-{index}", "type": "ss", "server": "127.0.0.1",
             "port": 10000 + index, "cipher": "aes-128-gcm", "password": "test",
             "_latency": index + 1, "_speed_kbps": 100,
             "_categories": ({"google", "youtube", "chatgpt"} if index % 3 == 2
                             else {"google"} if index % 2 == 0 else {"youtube", "chatgpt"})}
            for index in range(count)
        ]

    def test_export_limits_and_measured_groups(self):
        ranked = sort_proxies_by_performance(self.make_nodes(60))
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "clash.yaml")
            manager = ClashMetaManager("base_template.yaml", "test_config.yaml")
            with open(manager.base, encoding="utf-8") as stream:
                template = yaml.safe_load(stream)
            with patch("utils.clash_manager.GENERATED_PROXY_CONFIG", output):
                manager.save_config(ranked, output)
            with open(output, encoding="utf-8") as stream:
                config = yaml.safe_load(stream)
        self.assertEqual(len(config["proxies"]), 50)
        self.assertTrue(all(not key.startswith("_") for node in config["proxies"] for key in node))
        groups = {group["name"]: group for group in config["proxy-groups"]}
        selection = next(name for name in groups if "节点选择" in name)
        automatic = next(name for name in groups if "自动选择" in name)
        names = [node["name"] for node in ranked[:50]]
        expected_order = [group["name"] for group in template["proxy-groups"]]
        if "GLOBAL" not in expected_order:
            expected_order.append("GLOBAL")
        self.assertEqual([group["name"] for group in config["proxy-groups"]], expected_order)
        self.assertEqual(groups[selection]["proxies"][0], automatic)
        global_names = [node["name"] for node in ranked[:50]
                if {"google", "youtube", "chatgpt"}.issubset(node["_categories"])]
        expected_global = [selection, automatic] + global_names
        self.assertEqual(groups["GLOBAL"]["proxies"], expected_global)
        self.assertEqual(groups[automatic]["proxies"], global_names)
        self.assertEqual(groups[selection]["proxies"], [automatic] + global_names)
        self.assertEqual(groups["GLOBAL"]["type"], "select")
        self.assertFalse(groups["GLOBAL"]["include-all"])
        self.assertTrue(config["profile"]["store-selected"])
        for name, group in groups.items():
            if any(label in name for label in ("漏网之鱼", "电报信息", "微软服务", "国内媒体")):
                self.assertIn(automatic, group["proxies"])
                self.assertTrue(set(global_names).issubset(group["proxies"]))
                self.assertFalse((set(names) - set(global_names)) & set(group["proxies"]))
        for service in ("google", "youtube", "chatgpt"):
            group = next(group for name, group in groups.items() if service in name.lower())
            members = [node["name"] for node in ranked[:50]
                       if service in node["_categories"]]
            self.assertEqual(group["proxies"], members)
            self.assertEqual(group["type"], "url-test")
            self.assertEqual(group["expected-status"], 204 if service == "google" else 200)
            self.assertFalse(group["lazy"])
            self.assertEqual(group["interval"], 120)
        self.assertEqual(groups[automatic]["url"], "https://www.gstatic.com/generate_204")
        self.assertEqual(groups[automatic]["expected-status"], 204)
        self.assertFalse(groups[automatic]["lazy"])

    def test_empty_service_rejects_unverified_nodes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "clash.yaml")
            with patch("utils.clash_manager.GENERATED_PROXY_CONFIG", output):
                ClashMetaManager("base_template.yaml", "test_config.yaml").save_config(self.make_nodes(1), output)
            with open(output, encoding="utf-8") as stream:
                config = yaml.safe_load(stream)
        group = next(group for group in config["proxy-groups"] if "chatgpt" in group["name"].lower())
        self.assertEqual(group["proxies"], ["REJECT"])
        self.assertEqual(group["type"], "select")
        self.assertNotIn("url", group)
        automatic = next(item for item in config["proxy-groups"] if "自动选择" in item["name"])
        self.assertEqual(automatic["proxies"], ["REJECT"])
        global_group = next(item for item in config["proxy-groups"] if item["name"] == "GLOBAL")
        self.assertNotIn("node-0", global_group["proxies"])

    def test_hbo_max_rule_covers_max_domain_before_match(self):
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "clash.yaml")
            with patch("utils.clash_manager.GENERATED_PROXY_CONFIG", output):
                ClashMetaManager("base_template.yaml", "test_config.yaml").save_config(
                    self.make_nodes(1), output
                )
            with open(output, encoding="utf-8") as stream:
                config = yaml.safe_load(stream)

        rules = config["rules"]
        max_rule = next(rule for rule in rules if rule.startswith("DOMAIN-SUFFIX,max.com,"))
        match_index = next(index for index, rule in enumerate(rules) if rule.startswith("MATCH,"))
        self.assertEqual(max_rule, "DOMAIN-SUFFIX,max.com,🌍 国外媒体")
        self.assertLess(rules.index(max_rule), match_index)

    def test_pipeline_keeps_best_fifty(self):
        with patch("utils.utils._test_batch_nodes", side_effect=lambda batch, *args: batch):
            result = test_nodes(list(reversed(self.make_nodes(60))), "dev", "/unused")
        self.assertEqual(len(result), 50)
        self.assertEqual(result[0]["name"], "node-0")
        self.assertEqual(result[-1]["name"], "node-49")

    def test_service_mapping_and_uniform_speed(self):
        responses = [
            [("https://www.youtube.com", True, 0.2, 100),
             ("https://chatgpt.com/api/auth/providers", False, 0.1, 0),
             ("https://github.com", True, 0.4, 100)],
            [("https://www.gstatic.com/generate_204", True, 0.1, 0)],
            [("https://speed.cloudflare.com/__down?bytes=1048576", True, 2, 1048576)],
        ]
        with patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=responses)):
            metrics = asyncio.run(_test_node_metrics_async({"name": "google-us"}, 7890))
        self.assertIsNone(metrics["google_latency"])
        self.assertIsNone(metrics["chatgpt_latency"])
        self.assertEqual(metrics["youtube_latency"], 200)
        self.assertEqual(metrics["avg_speed_kbps"], 4194.3)
        self.assertTrue(metrics["is_available"])

    def test_limit_preserves_only_global_and_service_candidates(self):
        for categories in ({"google", "youtube", "chatgpt"}, {"youtube"}, {"chatgpt"}):
            with self.subTest(categories=categories):
                nodes = self.make_nodes(51)
                for node in nodes:
                    node["_categories"] = {"google"}
                nodes[-1]["_categories"] = categories
                with patch("utils.utils._test_batch_nodes", side_effect=lambda batch, *args: batch):
                    selected = test_nodes(nodes, "dev", "/unused")
                self.assertEqual(len(selected), 50)
                self.assertIn("node-50", [node["name"] for node in selected])
                with tempfile.TemporaryDirectory() as directory:
                    output = os.path.join(directory, "clash.yaml")
                    with patch("utils.clash_manager.GENERATED_PROXY_CONFIG", output):
                        ClashMetaManager("base_template.yaml", "test_config.yaml").save_config(nodes, output)
                    with open(output, encoding="utf-8") as stream:
                        config = yaml.safe_load(stream)
                self.assertEqual(len(config["proxies"]), 50)
                self.assertIn("node-50", [node["name"] for node in config["proxies"]])

    def test_no_successful_service_rejects_node(self):
        with patch("utils.utils.test_links_concurrent", new=AsyncMock(return_value=[
                ("https://www.google.com/generate_204", False, 0.1, 0),
                ("https://github.com", True, 0.1, 100)])) as probe:
            metrics = asyncio.run(_test_node_metrics_async({"name": "node"}, 7890))
        self.assertFalse(metrics["is_available"])
        self.assertEqual(probe.await_count, 1)

    def test_chatgpt_auth_survives_failed_download(self):
        responses = [
            [("https://chatgpt.com/api/auth/providers", True, 0.3, 100)],
            [("https://www.gstatic.com/generate_204", True, 0.1, 0)],
            [("https://speed.cloudflare.com/__down?bytes=1048576", False, 1, 0)],
        ]
        with patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=responses)) as probe:
            metrics = asyncio.run(_test_node_metrics_async({"name": "node"}, 7890, timeout=2))
        self.assertEqual(metrics["chatgpt_latency"], 300)
        self.assertTrue(metrics["is_available"])
        self.assertFalse(metrics["download_passed"])
        self.assertTrue(all(call.kwargs["timeout"] >= 6 for call in probe.call_args_list))

    def test_failed_health_check_keeps_service_node(self):
        responses = [
            [("https://www.youtube.com", True, 0.2, 100)],
            [("https://www.gstatic.com/generate_204", False, 6, 0)],
            [("https://speed.cloudflare.com/__down?bytes=1048576", False, 6, 0)],
        ]
        with patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=responses)) as probe:
            metrics = asyncio.run(_test_node_metrics_async({"name": "node"}, 7890))
        self.assertTrue(metrics["is_available"])
        self.assertEqual(probe.await_count, 3)

    def test_partial_download_keeps_service_node_without_speed(self):
        responses = [
            [("https://www.youtube.com", True, 0.2, 100)],
            [("https://www.gstatic.com/generate_204", True, 0.1, 0)],
            [("https://speed.cloudflare.com/__down?bytes=1048576", True, 0.1, 1024)],
        ]
        with patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=responses)):
            metrics = asyncio.run(_test_node_metrics_async({"name": "node"}, 7890))
        self.assertTrue(metrics["is_available"])
        self.assertEqual(metrics["avg_speed_kbps"], 0)

    def test_chatgpt_auth_requires_provider_json(self):
        for status, body, expected in (
            (200, b'{"openai":{"id":"openai"}}', True),
            (200, b'<html>Challenge</html>', False),
            (403, b'{"error":"unsupported_country"}', False),
            (429, b'{"error":"rate_limit"}', False),
            (200, b'{}', False),
        ):
            with self.subTest(status=status, body=body):
                async def chunks(size):
                    yield body

                response = SimpleNamespace(status=status, url=SimpleNamespace(host="chatgpt.com"),
                                           content=SimpleNamespace(iter_chunked=chunks))
                context = AsyncMock()
                context.__aenter__.return_value = response
                session = MagicMock()
                session.get.return_value = context
                result = asyncio.run(test_link_async(session, "https://chatgpt.com/api/auth/providers"))
                self.assertEqual(result[1], expected)

    def test_ipv6_tcp_probe_uses_bare_address(self):
        for server in ("2001:db8::1", "[2001:db8::1]"):
            with self.subTest(server=server):
                writer = MagicMock()
                writer.wait_closed = AsyncMock()
                node = {"server": server, "port": 443}
                with patch("utils.utils.asyncio.open_connection", new=AsyncMock(
                        return_value=(None, writer))) as connect:
                    result = asyncio.run(test_proxy_telnet_async(node))
                self.assertIs(result, node)
                connect.assert_awaited_once_with("2001:db8::1", 443)
                writer.close.assert_called_once()

    def test_quic_nodes_skip_tcp_prefilter(self):
        for protocol in ("hysteria", "hysteria2", "tuic"):
            with self.subTest(protocol=protocol):
                node = {"type": protocol, "server": "example.com", "port": 443}
                with patch("utils.utils.asyncio.open_connection", new=AsyncMock()) as connect:
                    self.assertIs(asyncio.run(test_proxy_telnet_async(node)), node)
                connect.assert_not_awaited()

    def test_health_status_and_download_body_validation(self):
        for link, status, size, expected in (
            ("https://www.google.com/generate_204", 200, 0, False),
            ("https://www.google.com/generate_204", 204, 0, True),
            ("https://www.gstatic.com/generate_204", 200, 0, False),
            ("https://www.gstatic.com/generate_204", 204, 0, True),
            ("https://speed.cloudflare.com/__down?bytes=1048576", 200, 1024, False),
            ("https://speed.cloudflare.com/__down?bytes=1048576", 200, 1048576, True),
            ("https://speed.cloudflare.com/__down?bytes=1048576", 403, 1048576, False),
        ):
            with self.subTest(link=link, status=status, size=size):
                async def chunks(chunk_size):
                    yield b"x" * size

                host = ("www.google.com" if "google.com" in link else
                    "www.gstatic.com" if "gstatic" in link else "speed.cloudflare.com")
                response = SimpleNamespace(status=status, url=SimpleNamespace(host=host),
                                           content=SimpleNamespace(iter_chunked=chunks))
                context = AsyncMock()
                context.__aenter__.return_value = response
                session = MagicMock()
                session.get.return_value = context
                result = asyncio.run(test_link_async(session, link))
                self.assertEqual(result[1], expected)


if __name__ == "__main__":
    unittest.main()