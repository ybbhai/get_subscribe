import asyncio
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import yaml

from utils.clash_manager import ClashMetaManager
from utils.utils import _test_node_metrics_async, sort_proxies_by_performance, test_nodes


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
            manager.save_config(ranked, output)
            with open(output, encoding="utf-8") as stream:
                config = yaml.safe_load(stream)
        self.assertEqual(len(config["proxies"]), 50)
        self.assertTrue(all(not key.startswith("_") for node in config["proxies"] for key in node))
        groups = {group["name"]: group for group in config["proxy-groups"]}
        self.assertEqual(groups["GLOBAL"]["proxies"], [node["name"] for node in ranked[:10]])
        self.assertFalse(groups["GLOBAL"]["include-all"])
        for service in ("google", "youtube", "chatgpt"):
            group = next(group for name, group in groups.items() if service in name.lower())
            self.assertEqual(group["proxies"], [node["name"] for node in ranked[:50]
                                               if service in node["_categories"]])

    def test_empty_service_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "clash.yaml")
            ClashMetaManager("base_template.yaml", "test_config.yaml").save_config(self.make_nodes(1), output)
            with open(output, encoding="utf-8") as stream:
                config = yaml.safe_load(stream)
        group = next(group for group in config["proxy-groups"] if "chatgpt" in group["name"].lower())
        self.assertEqual(group["proxies"], ["REJECT"])
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
            [("https://speed.cloudflare.com/__down?bytes=1048576", True, 2, 1000000)],
        ]
        with patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=responses)):
            metrics = asyncio.run(_test_node_metrics_async({"name": "google-us"}, 7890))
        self.assertIsNone(metrics["google_latency"])
        self.assertIsNone(metrics["chatgpt_latency"])
        self.assertEqual(metrics["youtube_latency"], 200)
        self.assertEqual(metrics["avg_speed_kbps"], 4000)


if __name__ == "__main__":
    unittest.main()