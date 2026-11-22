import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

import requests
import yaml
import aiohttp

from main import _collect_proxies, _merge_cloudflare_source, main, parse_command_args
from utils.cloudflare_source import expand_cloudflare_proxies
from utils.cloudflare_config import load_cloudflare_config
from utils.clash_manager import ClashMetaManager
from utils.source_tracking import stage_counts, tag_source
from utils.utils import filter_proxies


def worker(name="worker", server="104.16.0.1", path="/edge"):
    return {
        "name": name, "type": "vless", "server": server, "port": 443,
        "uuid": "11111111-1111-4111-8111-111111111111", "tls": True,
        "network": "ws", "servername": "worker.example",
        "ws-opts": {"path": path, "headers": {"Host": "worker.example"},
                    "max-early-data": 2048, "early-data-header-name": "Sec-WebSocket-Protocol"},
    }


def write_subscription(directory, name, nodes):
    path = Path(directory) / f"{name}.yaml"
    path.write_text(yaml.safe_dump({"proxies": nodes}), encoding="utf-8")
    return {"id": name, "subscription_file": str(path)}


class MultiSourceCollectionTests(unittest.TestCase):
    def setUp(self):
        self.sessions = []

        def session(*args, **kwargs):
            result = Mock()
            result.get.side_effect = requests.ConnectionError("private URL token should not be logged")
            self.sessions.append(result)
            return result

        self.rss = self.mock("main.get_subscribe_proxies", return_value=[])
        self.clash = self.mock("main.get_clash_proxies", return_value=[])
        self.session = self.mock("main._subscription_session", side_effect=session)
        self.gate = self.mock("main.get_vpngate_proxies", return_value=[])
        self.mock("requests.sessions.Session.request", side_effect=AssertionError("unexpected real network"))
        self.mock("utils.cloudflare_source._fetch_subscription", new=AsyncMock(
            side_effect=aiohttp.ClientConnectionError("private URL token should not be logged")))

    def mock(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def test_failure_and_disabled_source_do_not_discard_other_final_subscription(self):
        with tempfile.TemporaryDirectory() as directory:
            valid = write_subscription(directory, "healthy", [worker(path="/private-ws-path")])
            config = {"sources": [
                {"id": "broken", "subscription_url": "https://private.example/token"},
                {"id": "disabled", "enabled": False, "subscription_file": "not-opened.yaml"},
                valid,
            ]}
            proxies, diagnostics = [], {}
            with self.assertLogs("main", level="INFO") as logs:
                _collect_proxies(proxies, False, None, config, diagnostics=diagnostics)

        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0]["_source_ids"], ["healthy"])
        self.assertEqual(proxies[0]["ws-opts"]["path"], "/private-ws-path")
        self.assertEqual(self.session.call_count, 2)
        for session in self.sessions:
            session.close.assert_called_once_with()
        summaries = {summary["id"]: summary for summary in diagnostics["sources"]}
        self.assertEqual(summaries["broken"]["status"], "failed")
        self.assertEqual(summaries["disabled"]["status"], "disabled")
        self.assertEqual(summaries["healthy"]["accepted_count"], 1)
        safe_output = json.dumps(diagnostics) + "\n".join(logs.output)
        for secret in ("private.example", "/token", "private-ws-path", worker()["uuid"]):
            self.assertNotIn(secret, safe_output)

    def test_loaded_missing_files_do_not_abort_healthy_sources_or_vpngate(self):
        self.rss.return_value = [worker("rss", path="/rss")]
        self.clash.return_value = [worker("clash", path="/clash")]
        self.gate.return_value = [worker("gate", path="/gate")]
        with tempfile.TemporaryDirectory() as directory:
            valid = write_subscription(directory, "healthy", [worker("healthy")])
            config = Path(directory) / "cloudflare.yaml"
            config.write_text(yaml.safe_dump({
                "subscription_file": "missing-legacy.yaml",
                "sources": [
                    {"id": "missing", "subscription_file": "missing.yaml"},
                    {"id": "missing-addresses", "subscription_file": valid["subscription_file"],
                     "addresses_file": "missing-addresses.txt"}, valid],
                "vpngate": {"enabled": True},
            }), encoding="utf-8")
            loaded = load_cloudflare_config(config)
            proxies, diagnostics = [], {}
            _collect_proxies(proxies, False, None, loaded, diagnostics=diagnostics)
        self.assertEqual({source for proxy in proxies for source in proxy["_source_ids"]},
                         {"rss", "clash_subscriptions", "healthy", "vpngate"})
        self.gate.assert_called_once()
        statuses = {source["id"]: source["status"] for source in diagnostics["sources"]}
        for source in ("cloudflare_legacy", "missing", "missing-addresses"):
            self.assertEqual(statuses[source], "failed")

    def test_prod_defaults_to_vpngate_and_explicit_flag_overrides_environment(self):
        for profile, config, expected in (
            ("prod", None, True), ("dev", None, False),
            ("prod", {"vpngate": {}}, True), ("dev", {"vpngate": {}}, False),
            ("prod", {"vpngate": {"enabled": False}}, False),
            ("dev", {"vpngate": {"enabled": True}}, True),
        ):
            with self.subTest(profile=profile, config=config):
                self.gate.reset_mock()
                self.session.reset_mock()
                diagnostics = {}
                _collect_proxies([], False, None, config, profile=profile, diagnostics=diagnostics)
                self.assertEqual(self.gate.call_count, int(expected))
                self.assertEqual(self.session.call_count, int(expected))
                gate_summary = next(s for s in diagnostics["sources"] if s["id"] == "vpngate")
                self.assertEqual(gate_summary["status"], "empty" if expected else "disabled")

    def test_vpngate_custom_urls_budget_and_diagnostics_reach_adapter(self):
        def collect(session, **kwargs):
            kwargs["diagnostics"].update(status="ok", parsed_count=1)
            return [dict(worker(), type="openvpn")]

        self.gate.side_effect = collect
        gate_config = {"enabled": True, "api_url": "http://vpn.example/api/", "max_candidates": 12,
                       "mirror_urls": ["https://mirror.example/api/"]}
        proxies, diagnostics = [], {}
        _collect_proxies(proxies, True, 18001, {"vpngate": gate_config}, diagnostics=diagnostics)

        self.assertEqual(self.gate.call_args.kwargs["api_url"], gate_config["api_url"])
        self.assertEqual(self.gate.call_args.kwargs["mirror_urls"], gate_config["mirror_urls"])
        self.assertEqual(self.gate.call_args.kwargs["max_candidates"], 12)
        self.session.assert_called_once_with(True, 18001)
        self.sessions[0].close.assert_called_once_with()
        self.assertEqual(proxies[0]["_source_ids"], ["vpngate"])
        self.assertEqual(proxies[0]["_source"], "vpngate")
        self.assertEqual(diagnostics["sources"][-1]["collection"], {"status": "ok", "parsed_count": 1})

    def test_additional_budget_is_fair_deduplicates_and_preserves_all_source_memberships(self):
        rss = worker("rss", path="/rss")
        self.rss.return_value = [rss]
        shared = worker("shared", path="/shared")
        with tempfile.TemporaryDirectory() as directory:
            source_a = write_subscription(directory, "source-a", [
                shared, dict(shared, name="duplicate-in-a"), worker("a1", path="/a1"), worker("a2", path="/a2"),
            ])
            source_b = write_subscription(directory, "source-b", [dict(shared, name="mirror-name"), worker("b1", path="/b1")])
            source_c = write_subscription(directory, "source-c", [worker("c1", path="/c1"), worker("c2", path="/c2")])
            proxies, diagnostics = [], {}
            _collect_proxies(proxies, False, None, {
                "sources": [source_a, source_b, source_c], "max_total_candidates": 3,
            }, diagnostics=diagnostics)

        self.assertEqual([node["name"] for node in proxies], ["rss", "shared-cf", "c1-cf", "a1-cf"])
        self.assertEqual(proxies[1]["_source_ids"], ["source-a", "source-b"])
        self.assertEqual(proxies[0]["_source_ids"], ["rss"])
        self.assertEqual(diagnostics["additional_sources"], {
            "parsed_count": 8, "unique_candidate_count": 6, "accepted_count": 3, "limit": 3,
        })
        source_a_summary = next(s for s in diagnostics["sources"] if s["id"] == "source-a")
        self.assertEqual(source_a_summary["parsed_count"], 4)
        self.assertEqual(source_a_summary["duplicate_count"], 1)
        source_counts = stage_counts(proxies)["by_source"]
        self.assertEqual(source_counts, {"rss": 1, "source-a": 2, "source-b": 1, "source-c": 1})
        self.assertEqual(filter_proxies(proxies), proxies)
        self.assertNotIn("_source", shared)
        self.assertNotIn("_source", rss)

    def test_legacy_and_multiple_sources_are_collected_together(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = write_subscription(directory, "legacy", [worker("legacy", path="/legacy")])
            extra = write_subscription(directory, "extra", [worker("extra", path="/extra")])
            proxies = []
            _collect_proxies(proxies, False, None, {
                "subscription_file": legacy["subscription_file"], "sources": [extra],
            })
        self.assertEqual([node["_source_ids"] for node in proxies], [["cloudflare_legacy"], ["extra"]])

    def test_vpngate_cli_overrides_only_flag_and_preserves_multiple_sources(self):
        original = {"sources": [{"id": "edge", "subscription_url": "https://example.test/sub"}],
                    "vpngate": {"api_url": "http://vpn.example/api", "max_candidates": 15},
                    "max_total_candidates": 20, "addresses_format": "addresses", "template_index": 1}
        snapshot = copy.deepcopy(original)
        for flag, expected in (("--no-vpngate", False), ("--vpngate", True)):
            with self.subTest(flag=flag), patch("sys.argv", ["main.py", flag]):
                cli = parse_command_args()["cloudflare_source"]
            merged = _merge_cloudflare_source(original, cli)
            self.assertIs(merged["vpngate"]["enabled"], expected)
            self.assertEqual(merged["vpngate"]["api_url"], original["vpngate"]["api_url"])
            self.assertEqual(merged["sources"], original["sources"])
            self.assertEqual(merged["max_total_candidates"], 20)
        self.assertEqual(original, snapshot)

    def test_automatic_variant_retains_original_channel_after_deduplication(self):
        original = tag_source(worker(), "custom-worker", "cloudflare_subscription")
        optimized = expand_cloudflare_proxies([original], [original["server"]])
        merged = filter_proxies([original, *optimized])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["_source"], "cloudflare_auto")
        self.assertEqual(merged[0]["_source_ids"], ["cloudflare_auto", "custom-worker"])
        self.assertEqual(stage_counts(merged), {"total": 1, "cloudflare_auto": 1,
                                               "by_source": {"cloudflare_auto": 1, "custom-worker": 1}})
        self.assertEqual(original["_source_ids"], ["custom-worker"])

    def test_local_final_subscriptions_pass_filter_measurement_and_export_without_internal_metadata(self):
        metric = {"is_available": True, "avg_latency": 100, "avg_speed_kbps": 10000,
                  "download_passed": True, "google_latency": 100, "youtube_latency": 120,
                  "chatgpt_latency": 130}
        with tempfile.TemporaryDirectory() as directory:
            sources = [write_subscription(directory, "first", [worker("first", path="/first")]),
                       write_subscription(directory, "second", [worker("second", path="/second")])]
            output = Path(directory) / "clash.yaml"
            with patch("main.start_proxies", return_value=(None, None)), \
                    patch("main.test_proxies_async", new=AsyncMock(side_effect=lambda nodes, **kw: nodes)), \
                    patch("main.ensure_openvpn_runtime") as ensure, \
                    patch.object(ClashMetaManager, "start"), \
                    patch.object(ClashMetaManager, "stop"), \
                    patch.object(ClashMetaManager, "switch_proxy", return_value=True), \
                    patch("utils.utils.test_node_metrics", return_value=metric), \
                    patch("utils.exit_quality.ExitInspector.inspect", return_value={"status": "clean", "residential": False}), \
                    patch("utils.clash_manager.GENERATED_PROXY_CONFIG", str(output)):
                selected = main("prod", directory, {
                    "sources": sources, "automatic_enabled": False, "vpngate": {"enabled": False},
                })
            report = json.loads((Path(directory) / "node_selection_report.json").read_text(encoding="utf-8"))
            exported = yaml.safe_load(output.read_text(encoding="utf-8"))

        ensure.assert_not_called()
        self.assertEqual(len(selected), 2)
        self.assertEqual({node["name"] for node in exported["proxies"]}, {"first-cf", "second-cf"})
        self.assertEqual({node["name"] for node in selected}, {"first-cf", "second-cf"})
        self.assertEqual({node["name"] for node in report["nodes"]}, {"first-cf", "second-cf"})
        self.assertTrue(all(not key.startswith("_") for node in exported["proxies"] for key in node))
        self.assertEqual({node["ws-opts"]["path"] for node in exported["proxies"]}, {"/first", "/second"})
        self.assertTrue(all(node["ws-opts"]["max-early-data"] == 2048 for node in exported["proxies"]))
        self.assertEqual(report["diagnostics"]["stage_counts"]["selected"]["by_source"], {"first": 1, "second": 1})
        self.assertEqual(report["export_eligible_count"], 2)
        self.assertTrue(all(node["verification"] == "passed" for node in report["nodes"]))

    def test_main_prepares_openvpn_runtime_for_vpngate_candidates(self):
        self.gate.return_value = [{"name": "vpn", "type": "openvpn", "server": "192.0.2.1", "port": 443}]
        with patch("main.start_proxies", return_value=(None, None)), \
                patch("main.ensure_openvpn_runtime") as ensure, \
                patch("main.test_proxies_async", new=AsyncMock(return_value=[])), \
                patch("main.test_nodes", return_value=[]) as test:
            main("prod", "unused", {"automatic_enabled": False})
        ensure.assert_called_once_with(session=self.sessions[-1])
        self.sessions[-1].close.assert_called_once_with()
        self.assertEqual(test.call_args.args[4]["openvpn_runtime"], {"status": "ready"})
        self.assertEqual(test.call_args.args[4]["stage_counts"]["collected"]["by_source"], {"vpngate": 1})

    def test_automatic_optimizer_receives_all_sources_and_report_keeps_parent_channels(self):
        rss = worker("rss-template", server="104.16.0.1", path="/rss")
        clash = worker("clash-template", server="104.16.0.2", path="/clash")
        self.rss.return_value = [rss]
        self.clash.return_value = [clash]
        optimized_inputs = []

        def optimize(nodes, **kwargs):
            optimized_inputs.extend(nodes)
            return expand_cloudflare_proxies(nodes, ["104.16.0.3"])

        with tempfile.TemporaryDirectory() as directory:
            extra = write_subscription(directory, "extra", [worker("extra", path="/extra")])
            with patch("main.start_proxies", return_value=(None, None)), \
                    patch("main.get_optimized_cloudflare_proxies", side_effect=optimize), \
                    patch("main.test_proxies_async", new=AsyncMock(side_effect=lambda nodes, **kw: nodes)), \
                    patch("main.test_nodes", side_effect=lambda nodes, *args: nodes) as test:
                selected = main("prod", directory, {"sources": [extra], "vpngate": {"enabled": False}})

        self.assertEqual([node["_source_ids"] for node in optimized_inputs],
                         [["rss"], ["clash_subscriptions"], ["extra"]])
        self.assertEqual(len(selected), 6)
        self.assertEqual([node["_source_ids"] for node in selected[3:]], [
            ["cloudflare_auto", "rss"], ["clash_subscriptions", "cloudflare_auto"],
            ["cloudflare_auto", "extra"],
        ])
        diagnostics = test.call_args.args[4]
        self.assertEqual(diagnostics["stage_counts"]["tcp_passed"]["cloudflare_auto"], 3)
        self.assertEqual(diagnostics["stage_counts"]["tcp_passed"]["by_source"],
                         {"rss": 2, "clash_subscriptions": 2, "extra": 2, "cloudflare_auto": 3})
        self.assertEqual(diagnostics["sources"][-1]["id"], "cloudflare_auto")
        self.assertEqual(diagnostics["sources"][-1]["accepted_count"], 3)

    def test_automatic_optimizer_runs_after_collection_proxy_stops(self):
        self.rss.return_value = [worker("rss-template")]
        stopped = {"value": False}
        process = Mock()

        def optimize(nodes, **kwargs):
            self.assertTrue(stopped["value"])
            self.assertIsNone(kwargs["bootstrap_proxy_url"])
            self.assertTrue(kwargs["bootstrap_trust_env"])
            return []

        def stop(_process):
            stopped["value"] = True

        with tempfile.TemporaryDirectory() as directory, \
                patch("main.start_proxies", return_value=(process, 17500)), \
                patch("main.stop_proxies", side_effect=stop), \
                patch("main._detect_fallback_proxy", return_value=None), \
                patch("main.get_optimized_cloudflare_proxies", side_effect=optimize), \
                patch("main.test_proxies_async", new=AsyncMock(side_effect=lambda nodes, **kw: nodes)), \
                patch("main.test_nodes", side_effect=lambda nodes, *args: nodes):
            main("prod", directory, {"vpngate": {"enabled": False}})

        self.assertTrue(stopped["value"])

    def test_automatic_optimizer_reuses_detected_fallback_proxy(self):
        self.rss.return_value = [worker("rss-template")]
        proxy_url = "http://127.0.0.1:7890"
        optimizer_calls = []

        def optimize(nodes, **kwargs):
            optimizer_calls.append(kwargs)
            return []

        with tempfile.TemporaryDirectory() as directory, \
                patch("main.start_proxies", return_value=(None, None)), \
                patch("main._detect_fallback_proxy", return_value=proxy_url) as detect, \
                patch("main.get_optimized_cloudflare_proxies", side_effect=optimize), \
                patch("main.test_proxies_async", new=AsyncMock(side_effect=lambda nodes, **kw: nodes)), \
                patch("main.test_nodes", side_effect=lambda nodes, *args: nodes):
            main("prod", directory, {"vpngate": {"enabled": False}})

        detect.assert_called_once_with()
        self.assertEqual(optimizer_calls[0]["bootstrap_proxy_url"], proxy_url)
        self.assertFalse(optimizer_calls[0]["bootstrap_trust_env"])

    def test_vpngate_failure_is_reported_and_existing_subscription_survives(self):
        self.gate.side_effect = requests.Timeout("https://private.example/token")
        self.rss.return_value = [worker("rss")]
        proxies, diagnostics = [], {}
        with self.assertLogs("main", level="WARNING") as logs:
            _collect_proxies(proxies, False, None, profile="prod", diagnostics=diagnostics)

        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0]["_source_ids"], ["rss"])
        self.sessions[0].close.assert_called_once_with()
        self.assertEqual(diagnostics["sources"][-1]["status"], "failed")
        self.assertEqual(diagnostics["sources"][-1]["reason"], "Timeout")
        self.assertNotIn("private.example", json.dumps(diagnostics) + "\n".join(logs.output))

    def test_invalid_rss_items_do_not_discard_valid_neighbor(self):
        self.rss.return_value = [None, worker("valid")]
        proxies, diagnostics = [], {}
        _collect_proxies(proxies, False, None, diagnostics=diagnostics)

        self.assertEqual([node["name"] for node in proxies], ["valid"])
        self.assertEqual(proxies[0]["_source_ids"], ["rss"])
        rss = next(source for source in diagnostics["sources"] if source["id"] == "rss")
        self.assertEqual(rss["status"], "ok")
        self.assertEqual(rss["parsed_count"], 2)
        self.assertEqual(rss["accepted_count"], 1)

    def test_subscription_cannot_supply_local_provenance_or_quality_evidence(self):
        node = worker("valid")
        node.update(_source="cloudflare_auto", _source_ids=["https://private.example/token"],
                    _exit_quality={"status": "clean", "residential": True}, _speed_kbps=100000)
        self.rss.return_value = [node]
        proxies, diagnostics = [], {}
        _collect_proxies(proxies, False, None, diagnostics=diagnostics)
        self.assertEqual(proxies[0]["_source_ids"], ["rss"])
        self.assertEqual(proxies[0]["_source"], "subscription")
        self.assertNotIn("_exit_quality", proxies[0])
        self.assertNotIn("_speed_kbps", proxies[0])
        self.assertNotIn("private.example", json.dumps(diagnostics))

    def test_skipped_openvpn_is_not_reported_as_tcp_success(self):
        self.gate.return_value = [{"name": "vpn", "type": "openvpn", "server": "192.0.2.1", "port": 443}]
        self.rss.return_value = [worker("edge")]
        with patch("main.start_proxies", return_value=(None, None)), \
                patch("main.ensure_openvpn_runtime"), \
                patch("main.test_proxies_async", new=AsyncMock(side_effect=lambda nodes, **kw: nodes)), \
                patch("main.test_nodes", return_value=[]) as test:
            main("prod", "unused", {"automatic_enabled": False})
        stages = test.call_args.args[4]["stage_counts"]
        self.assertEqual(stages["tcp_tested"]["total"], 1)
        self.assertEqual(stages["tcp_passed"]["by_source"], {"rss": 1})
        self.assertEqual(stages["tcp_skipped"]["by_source"], {"vpngate": 1})
        self.assertEqual(stages["tcp_retained"]["total"], 2)


if __name__ == "__main__":
    unittest.main()
