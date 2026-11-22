import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

import yaml

from utils.node_policy import NodePolicy
from utils.utils import _test_batch_nodes, _test_node_metrics_async, _ProbeAudit, test_nodes


def node(name, speed=10000, source=None):
    result = {"name": name, "type": "ss", "server": "192.0.2.1", "port": 443,
              "cipher": "aes-128-gcm", "password": name, "_categories": {"google"},
              "_latency": 200, "_speed_kbps": speed, "_download_passed": True}
    if source:
        result["_source"] = source
    return result


def metrics(speed=10000, latency=200, available=True):
    return {"is_available": available, "avg_latency": latency, "avg_speed_kbps": speed,
            "download_passed": True, "google_latency": 200,
            "youtube_latency": None, "chatgpt_latency": None}


class ProductionPipelineTests(unittest.TestCase):
    def test_budget_is_allocated_after_all_measurements_and_failed_recheck_is_rejected(self):
        nodes = [node("slow", 1000), node("unstable", 16000), node("best", 12000)]
        events = []

        def probe(batch, directory, timeout, worker_id, inspector, mode, policy, audit):
            events.append((mode, [p["name"] for p in batch]))
            if mode == "measure":
                return [dict(p) for p in batch]
            self.assertEqual(mode, "verify")
            self.assertEqual({p["name"] for p in batch}, {"best", "unstable"})
            result = []
            for proxy in batch:
                proxy = dict(proxy)
                if proxy["name"] == "unstable":
                    proxy.update(_speed_kbps=500, _verification="failed")
                else:
                    proxy.update(_verification="passed", _exit_quality={"status": "clean"})
                result.append(proxy)
            return result

        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.utils.load_node_policy", return_value=NodePolicy(
                    min_speed_kbps=5000, max_latency_ms=1500, max_lookups_per_round=2)), \
                patch("utils.utils._test_batch_nodes", side_effect=probe), \
                patch("utils.clash_manager.GENERATED_PROXY_CONFIG", str(Path(directory) / "cache.yaml")):
            selected = test_nodes(nodes, "prod", directory)
            report = json.loads((Path(directory) / "node_selection_report.json").read_text(encoding="utf-8"))
            exported = yaml.safe_load((Path(directory) / "clash.yaml").read_text(encoding="utf-8"))
        self.assertEqual([p["name"] for p in selected], ["best"])
        self.assertEqual([p["name"] for p in exported["proxies"]], ["best"])
        self.assertEqual([event[0] for event in events], ["measure", "verify"])
        self.assertEqual(report["diagnostics"]["stage_counts"]["performance_passed"]["total"], 2)
        self.assertEqual(report["diagnostics"]["stage_counts"]["verification_passed"]["total"], 1)
        rejected = next(p for p in report["nodes"] if p["name"] == "unstable")
        self.assertEqual(rejected["speed_kbps"], 500)
        self.assertFalse(rejected["selected"])

    def test_failed_verification_does_not_overwrite_previous_output(self):
        def probe(batch, *args):
            return [dict(p) for p in batch] if args[4] == "measure" else []

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "clash.yaml"
            output.write_text("previous output", encoding="utf-8")
            with patch("utils.utils._test_batch_nodes", side_effect=probe):
                selected = test_nodes([node("unstable")], "prod", directory)
            report = json.loads((Path(directory) / "node_selection_report.json").read_text(encoding="utf-8"))
            self.assertEqual(output.read_text(encoding="utf-8"), "previous output")
        self.assertEqual(selected, [])
        self.assertEqual(report["selected_count"], 0)
        self.assertEqual(report["nodes"][0]["verification"], "failed")

    def test_measurement_never_inspects_and_verify_skips_slow_node(self):
        inspector = Mock()
        policy = NodePolicy(min_speed_kbps=5000, max_latency_ms=1500)
        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.utils.ClashMetaManager") as manager, \
                patch("utils.utils.test_node_metrics", return_value=metrics(speed=1000)):
            manager.return_value.switch_proxy.return_value = True
            measured = _test_batch_nodes([node("slow")], directory, 6, 0, inspector, "measure", policy)
            verified = _test_batch_nodes(measured, directory, 6, 0, inspector, "verify", policy)
        inspector.inspect.assert_not_called()
        self.assertEqual(verified[0]["_verification"], "failed")
        self.assertEqual(verified[0]["_exit_quality"]["reason"], "performance_floor")

    def test_failed_recheck_uses_remaining_budget_for_next_candidate(self):
        first, fallback = node("first", 20000), node("fallback", 10000)
        seen = []
        def probe(batch, directory, timeout, worker_id, inspector, mode, policy, audit):
            if mode == "measure":
                return [dict(p) for p in batch]
            seen.extend(p["name"] for p in batch)
            return [dict(p, _verification="passed", _exit_quality={"status": "clean"})
                    for p in batch if p["name"] == "fallback"]
        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.utils.load_node_policy", return_value=NodePolicy(
                    min_speed_kbps=5000, max_latency_ms=1500, max_lookups_per_round=1)), \
                patch("utils.utils._test_batch_nodes", side_effect=probe), \
                patch("utils.clash_manager.GENERATED_PROXY_CONFIG", str(Path(directory) / "cache.yaml")):
            selected = test_nodes([first, fallback], "prod", directory)
        self.assertEqual(seen, ["first", "fallback"])
        self.assertEqual([p["name"] for p in selected], ["fallback"])

    def test_invalid_collected_entries_are_filtered_before_testing(self):
        import main
        def collect(proxies, *args, **kwargs):
            proxies.extend([None, "bad", node("valid")])
        with patch("main.start_proxies", return_value=(None, None)), \
                patch("main._collect_proxies", side_effect=collect), \
                patch("main.test_proxies_async", new=AsyncMock(return_value=[])) as tcp, \
                patch("main.test_nodes", return_value=[]) as run:
            main.main("prod", "unused", {"automatic_enabled": False})
        self.assertEqual(len(tcp.call_args.args[0]), 1)
        self.assertEqual(run.call_args.args[4]["stage_counts"]["collected"]["total"], 3)

    def test_latency_uses_empty_body_probe_not_full_page_time(self):
        samples = [
            [("https://www.google.com/generate_204", True, 0.3, 0),
             ("https://www.youtube.com", True, 5, 900000)],
            [("https://www.gstatic.com/generate_204", True, 0.1, 0)],
            [("https://speed.cloudflare.com/__down?bytes=1048576", True, 0.5, 1048576)],
        ]
        with patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=samples)):
            result = asyncio.run(_test_node_metrics_async(node("one"), 18001))
        self.assertEqual(result["avg_latency"], 100)
        self.assertEqual(result["service_avg_latency"], 2650)
        self.assertTrue(result["download_passed"])

    def test_missing_latency_does_not_reuse_incoming_metric(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.utils.ClashMetaManager"), \
                patch("utils.utils.test_node_metrics", return_value=metrics(latency=None)):
            result = _test_batch_nodes([node("stale")], directory, 6, 0, Mock(), "measure")
        self.assertIsNone(result[0]["_latency"])

    def test_invalid_batch_is_split_to_keep_valid_neighbors(self):
        active = []
        audit = _ProbeAudit()
        def write(batch, output_path):
            active[:] = batch
        def start(config_path):
            if any(p["name"] == "bad" for p in active):
                raise RuntimeError("invalid proxy")
        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.utils.ClashMetaManager") as create, \
                patch("utils.utils.test_node_metrics", return_value=metrics()):
            create.return_value.write_config.side_effect = write
            create.return_value.start.side_effect = start
            result = _test_batch_nodes([node("good"), node("bad", source="cloudflare_auto")],
                                       directory, 6, 0, Mock(), "measure", audit=audit)
        self.assertEqual([p["name"] for p in result], ["good"])
        self.assertTrue(any(x["source"] == "cloudflare_auto" and x["reason"] == "batch_start_failed"
                            for x in audit.snapshot()))


if __name__ == "__main__":
    unittest.main()
