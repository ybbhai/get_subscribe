import asyncio
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import yaml

from utils.clash_manager import ClashMetaManager
from utils.utils import _test_node_metrics_async, sort_proxies_by_performance, test_link_async, test_nodes


class SelectionTests(unittest.TestCase):
    def make_nodes(self, count):
        return [
            {"name": f"node-{index}", "type": "ss", "server": "127.0.0.1",
             "port": 10000 + index, "cipher": "aes-128-gcm", "password": "test",
             "_latency": index + 1, "_speed_kbps": 100,
             "_categories": {"google"} if index % 2 == 0 else {"youtube", "chatgpt"}}
            for index in range(count)
        ]

    def test_export_limits_and_measured_groups(self):
        ranked = sort_proxies_by_performance(self.make_nodes(60))
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "clash.yaml")
            manager = ClashMetaManager("base_template.yaml", "test_config.yaml")
            with open(manager.base, encoding="utf-8") as stream:
                template = yaml.safe_load(stream)
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
        self.assertEqual(groups["GLOBAL"]["proxies"], [selection, automatic] + names)
        self.assertEqual(groups["GLOBAL"]["type"], "select")
        self.assertFalse(groups["GLOBAL"]["include-all"])
        self.assertTrue(config["profile"]["store-selected"])
        for name, group in groups.items():
            if any(label in name for label in ("漏网之鱼", "电报信息", "微软服务", "国内媒体")):
                self.assertIn(automatic, group["proxies"])
                self.assertTrue(set(names).issubset(group["proxies"]))
        for service in ("google", "youtube", "chatgpt"):
            group = next(group for name, group in groups.items() if service in name.lower())
            # service 分组应包含匹配的节点 + fallback + 所有节点作为后备
            expected_names = [node["name"] for node in ranked[:50]
                              if service in node["_categories"]] + [selection, automatic]
            # 所有节点都应可用，以确保 service 分组有实际可选的节点
            self.assertTrue(set(names).issubset(set(group["proxies"])))
            self.assertIn(selection, group["proxies"])
            self.assertIn(automatic, group["proxies"])
            self.assertEqual(group["type"], "select")

    def test_empty_service_falls_back_to_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "clash.yaml")
            ClashMetaManager("base_template.yaml", "test_config.yaml").save_config(self.make_nodes(1), output)
            with open(output, encoding="utf-8") as stream:
                config = yaml.safe_load(stream)
        group = next(group for group in config["proxy-groups"] if "chatgpt" in group["name"].lower())
        # service 分组应包含所有节点作为后备选项
        selection = config["proxy-groups"][0]["name"]
        automatic = next(item["name"] for item in config["proxy-groups"] if "自动选择" in item["name"])
        self.assertIn(selection, group["proxies"])
        self.assertIn(automatic, group["proxies"])
        self.assertIn("node-0", group["proxies"])
        self.assertEqual(group["type"], "select")

    def test_pipeline_keeps_best_fifty(self):
        with patch("utils.utils._test_batch_nodes", side_effect=lambda batch, *args: batch):
            result = test_nodes(list(reversed(self.make_nodes(60))), "dev", "/unused")
        self.assertEqual(len(result), 50)
        self.assertEqual(result[0]["name"], "node-0")
        self.assertEqual(result[-1]["name"], "node-49")

    def test_service_mapping_and_uniform_speed(self):
        responses = [
            [("https://www.youtube.com", True, 0.2, 100),
             ("https://chatgpt.com", False, 0.1, 0),
             ("https://github.com", True, 0.4, 100)],
            [("https://chatgpt.com/api/auth/providers", False, 0.1, 0)],
            [("https://speed.cloudflare.com/__down?bytes=1048576", True, 2, 1000000)],
        ]
        with patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=responses)):
            metrics = asyncio.run(_test_node_metrics_async({"name": "google-us"}, 7890))
        self.assertIsNone(metrics["google_latency"])
        self.assertIsNone(metrics["chatgpt_latency"])
        self.assertEqual(metrics["youtube_latency"], 200)
        self.assertEqual(metrics["avg_speed_kbps"], 4000)

    def test_chatgpt_auth_fallback_and_web_timeout(self):
        responses = [
            [("https://chatgpt.com", False, 0.1, 0)],
            [("https://chatgpt.com/api/auth/providers", True, 0.3, 100)],
            [("https://speed.cloudflare.com/__down?bytes=1048576", False, 1, 0)],
        ]
        with patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=responses)) as probe:
            metrics = asyncio.run(_test_node_metrics_async({"name": "node"}, 7890, timeout=2))
        self.assertEqual(metrics["chatgpt_latency"], 300)
        self.assertTrue(metrics["is_available"])
        self.assertTrue(all(call.kwargs["timeout"] >= 6 for call in probe.call_args_list))

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


if __name__ == "__main__":
    unittest.main()