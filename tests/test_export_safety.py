"""Regression coverage for reserved names and failure-safe config replacement."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from utils.clash_manager import ClashMetaManager, _normalize_proxies, _reserved_proxy_names
from utils.proxy_chain import materialize_proxies
from utils.utils import test_nodes


def node(name="node", port=443):
    return {"name": name, "type": "ss", "server": "192.0.2.1", "port": port,
            "cipher": "aes-128-gcm", "password": "test-password",
            "_categories": {"google", "youtube", "chatgpt"}, "_latency": 100,
            "_speed_kbps": 10000, "_download_passed": True}


class ReservedNameTests(unittest.TestCase):
    def test_all_template_and_builtin_names_are_renamed_before_measurement(self):
        inputs = [node(name, 10000 + index) for index, name in enumerate(sorted(_reserved_proxy_names()))]
        original = copy.deepcopy(inputs)
        normalized = _normalize_proxies(inputs)
        names = {p["name"] for p in normalized}
        self.assertFalse(names & _reserved_proxy_names())
        self.assertEqual(len(names), len(inputs))
        self.assertEqual(_normalize_proxies(normalized), normalized)
        self.assertEqual(inputs, original)

    def test_custom_template_reservation_preserves_cf_suffix_and_dependency(self):
        proxy = dict(node("custom"), _source="cloudflare_auto", **{
            "dialer-proxy": "custom-cf", "_dialer_proxies": [node("custom-cf", 8443)]})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / "base.yaml"
            template.write_text(yaml.safe_dump({"proxy-groups": [
                {"name": "custom-cf", "type": "select", "proxies": ["DIRECT"]}]}), encoding="utf-8")
            manager = ClashMetaManager(str(template), str(root / "test.yaml"))
            normalized = manager.write_config([proxy])
            output = root / "export.yaml"
            with patch("utils.clash_manager.GENERATED_PROXY_CONFIG", str(output)):
                manager.save_config(normalized, str(output))
            for path in (root / "test.yaml", output):
                config = yaml.safe_load(path.read_text(encoding="utf-8"))
                exit_node = config["proxies"][-1]
                self.assertEqual(exit_node["name"], "custom-1-cf")
                self.assertNotEqual(exit_node["dialer-proxy"], "custom-cf")
                self.assertEqual(exit_node["dialer-proxy"], config["proxies"][0]["name"])
                self.assertEqual(len({p["name"] for p in config["proxies"] + config["proxy-groups"]}),
                                 len(config["proxies"] + config["proxy-groups"]))

    def test_dependency_cannot_reuse_builtin_name(self):
        proxy = dict(node(), **{"dialer-proxy": "DIRECT", "_dialer_proxies": [node("DIRECT", 8443)]})
        nodes = materialize_proxies([proxy])
        self.assertEqual(nodes[-1]["dialer-proxy"], nodes[0]["name"])
        self.assertNotEqual(nodes[0]["name"], "DIRECT")

    def test_pipeline_switches_reports_and_exports_same_names(self):
        inputs = [node(name, 10000 + i) for i, name in enumerate(("GLOBAL", "TEST", "DIRECT", "♻️ 自动选择"))]
        runtime_names, switched = [], []

        def start(config_path=None):
            config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
            runtime_names.extend(config["proxy-groups"][0]["proxies"])

        def switch(name):
            self.assertIn(name, runtime_names)
            switched.append(name)
            return True

        metrics = {"is_available": True, "avg_latency": 100, "avg_speed_kbps": 10000,
                   "download_passed": True, "google_latency": 100, "youtube_latency": 100, "chatgpt_latency": 100}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(ClashMetaManager, "start", side_effect=start), \
                patch.object(ClashMetaManager, "stop"), \
                patch.object(ClashMetaManager, "switch_proxy", side_effect=switch), \
                patch("utils.utils.test_node_metrics", return_value=metrics), \
                patch("utils.exit_quality.ExitInspector.inspect", return_value={"status": "clean"}), \
                patch("utils.clash_manager.GENERATED_PROXY_CONFIG", str(Path(directory) / "cache.yaml")):
            selected = test_nodes(inputs, "prod", directory)
            config = yaml.safe_load((Path(directory) / "clash.yaml").read_text(encoding="utf-8"))
            report = json.loads((Path(directory) / "node_selection_report.json").read_text(encoding="utf-8"))
        names = {p["name"] for p in selected}
        self.assertEqual(len(names), len(inputs))
        self.assertFalse(names & _reserved_proxy_names())
        self.assertEqual(set(switched), names)
        self.assertEqual({p["name"] for p in config["proxies"]}, names)
        self.assertEqual({p["name"] for p in report["nodes"] if p["selected"]}, names)


class AtomicExportTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.output, self.mirror = self.root / "production.yaml", self.root / "cache.yaml"
        self.previous = b"previous complete configuration\n"
        self.output.write_bytes(self.previous)
        self.mirror.write_bytes(self.previous)
        patcher = patch("utils.clash_manager.GENERATED_PROXY_CONFIG", str(self.mirror))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.manager = ClashMetaManager("base_template.yaml", "test_config.yaml")

    @staticmethod
    def fail_dump(config, stream, **kwargs):
        stream.write("partial:")
        raise OSError("injected disk failure")

    def assert_no_temporaries(self):
        self.assertEqual(list(self.root.glob(".clash-*.yaml")), [])

    def test_partial_serialization_keeps_both_previous_files(self):
        with patch("utils.clash_manager.yaml.safe_dump", side_effect=self.fail_dump):
            with self.assertRaises(OSError):
                self.manager.save_config([node()], str(self.output))
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertEqual(self.mirror.read_bytes(), self.previous)
        self.assert_no_temporaries()

    def test_replace_failure_keeps_previous_files_and_cleans_temp(self):
        with patch("utils.clash_manager.os.replace", side_effect=PermissionError("injected lock")):
            with self.assertRaises(PermissionError):
                self.manager.save_config([node()], str(self.output))
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertEqual(self.mirror.read_bytes(), self.previous)
        self.assert_no_temporaries()

    def test_mirror_failure_preserves_old_cache_and_successful_production(self):
        dump = yaml.safe_dump
        calls = []

        def fail_second(config, stream, **kwargs):
            calls.append(stream.name)
            return dump(config, stream, **kwargs) if len(calls) == 1 else self.fail_dump(config, stream)

        with patch("utils.clash_manager.yaml.safe_dump", side_effect=fail_second):
            self.manager.save_config([node()], str(self.output))
        self.assertEqual(yaml.safe_load(self.output.read_text(encoding="utf-8"))["proxies"][0]["name"], "node")
        self.assertEqual(self.mirror.read_bytes(), self.previous)
        self.assert_no_temporaries()

    def test_mirror_only_failure_does_not_touch_production(self):
        with patch("utils.clash_manager.yaml.safe_dump", side_effect=self.fail_dump):
            self.manager.save_config([node()], str(self.output), mirror_only=True)
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertEqual(self.mirror.read_bytes(), self.previous)
        self.assert_no_temporaries()

    def test_invalid_reference_graph_cannot_replace_previous_config(self):
        for reference in ("missing", "node"):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                self.manager.save_config([dict(node(), **{"dialer-proxy": reference})], str(self.output))
            self.assertEqual(self.output.read_bytes(), self.previous)
            self.assertEqual(self.mirror.read_bytes(), self.previous)
        self.assert_no_temporaries()

    def test_successfully_replaces_both_files_with_identical_complete_yaml(self):
        self.manager.save_config([node()], str(self.output))
        self.assertEqual(self.output.read_bytes(), self.mirror.read_bytes())
        self.assertEqual(yaml.safe_load(self.output.read_text(encoding="utf-8"))["proxies"][0]["name"], "node")
        self.assert_no_temporaries()
