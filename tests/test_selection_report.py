import json
from pathlib import Path
import tempfile
import unittest

from utils.node_policy import NodePolicy
from utils.selection_report import write_selection_report


def measured_node(name, **changes):
    node = {
        "name": name, "type": "vless", "server": "104.16.0.1", "port": 443,
        "uuid": "private-uuid", "password": "private-password",
        "servername": "private-host.example",
        "ws-opts": {"path": "/private-ws-path", "headers": {"Host": "private-host.example"}},
        "_categories": ["google", "youtube"],
        "_speed_kbps": 10000, "_latency": 300, "_download_passed": True,
        "_exit_quality": {"status": "clean", "residential": False},
        "_service_latency_ms": {"google": 200, "youtube": 400, "chatgpt": None},
        "_verification": "passed",
    }
    node.update(changes)
    return node


class SelectionReportTests(unittest.TestCase):
    def test_zero_service_success_does_not_mean_no_test_input(self):
        with tempfile.TemporaryDirectory() as directory:
            write_selection_report([], [], NodePolicy(), directory, diagnostics={
                "sources": [{"id": "vpngate", "status": "ok"}],
                "stage_counts": {"test_input": {"total": 8, "by_source": {"vpngate": 8}}},
            })
            report = json.loads((Path(directory) / "node_selection_report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["test_input_count"], 8)
        self.assertEqual(report["service_passed_count"], 0)
        self.assertEqual(report["sources"][0]["test_input_count"], 8)
        self.assertEqual(report["sources"][0]["service_passed_count"], 0)

    def test_report_explains_source_performance_and_verification_rejections(self):
        policy = NodePolicy(min_speed_kbps=5000, max_latency_ms=1500)
        selected = measured_node("verified-cf", _source="cloudflare_auto")
        measured = [
            selected,
            measured_node("slow-clean", _speed_kbps=4900, _verification="budget_not_selected"),
            measured_node("high-latency", _latency=1501, _verification="budget_not_selected"),
            measured_node("failed-download", _download_passed=False, _verification="failed"),
            measured_node("not-verified", _verification="budget_not_selected"),
        ]
        diagnostics = {
            "profile": "prod",
            "stage_counts": {"cloudflare_auto": {"generated": 15, "selected": 1}},
            "probe_failures": {"download_failed": 1},
        }
        inspection = {"enabled": True, "attempted": 1, "budget": 200}

        with tempfile.TemporaryDirectory() as directory:
            write_selection_report(
                measured, [selected], policy, directory,
                diagnostics=diagnostics, inspection=inspection,
            )
            raw = (Path(directory) / "node_selection_report.json").read_text(encoding="utf-8")
            report = json.loads(raw)

        self.assertEqual(report["measured_count"], 5)
        self.assertEqual(report["selected_count"], 1)
        self.assertEqual(report["performance_eligible_count"], 2)
        self.assertEqual(report["export_eligible_count"], 1)
        self.assertEqual(report["diagnostics"], diagnostics)
        self.assertEqual(report["inspection"], inspection)
        self.assertEqual(report["policy"]["min_speed_kbps"], 5000)
        self.assertIn("generated_at", report)
        self.assertEqual(report["groups"]["google"]["nodes"], ["verified-cf"])
        self.assertEqual(report["groups"]["google"]["tier"], 2)
        nodes = {node["name"]: node for node in report["nodes"]}
        self.assertEqual(nodes["verified-cf"]["source"], "cloudflare_auto")
        self.assertEqual(nodes["verified-cf"]["service_latency_ms"], selected["_service_latency_ms"])
        self.assertEqual(nodes["verified-cf"]["verification"], "passed")
        self.assertTrue(nodes["verified-cf"]["selected"])
        self.assertTrue(nodes["verified-cf"]["export_eligible"])
        self.assertEqual(nodes["slow-clean"]["source"], "subscription")
        self.assertFalse(nodes["slow-clean"]["performance_eligible"])
        self.assertFalse(nodes["high-latency"]["performance_eligible"])
        self.assertFalse(nodes["failed-download"]["download_passed"])
        self.assertFalse(nodes["failed-download"]["performance_eligible"])
        self.assertEqual(nodes["failed-download"]["verification"], "failed")
        self.assertTrue(nodes["not-verified"]["performance_eligible"])
        self.assertFalse(nodes["not-verified"]["export_eligible"])
        self.assertFalse(nodes["not-verified"]["selected"])
        self.assertEqual(nodes["not-verified"]["verification"], "budget_not_selected")
        self.assertEqual(nodes["verified-cf"]["latency_ms"], 300)
        self.assertEqual(nodes["verified-cf"]["speed_kbps"], 10000)
        self.assertEqual(nodes["verified-cf"]["exit"], selected["_exit_quality"])
        for secret in ("private-uuid", "private-password", "private-host", "private-ws-path"):
            self.assertNotIn(secret, raw)

    def test_empty_report_retains_default_diagnostics_and_legacy_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            write_selection_report([], [], NodePolicy(), directory)
            report = json.loads((Path(directory) / "node_selection_report.json").read_text(encoding="utf-8"))

        self.assertEqual(report["measured_count"], 0)
        self.assertEqual(report["selected_count"], 0)
        self.assertEqual(report["performance_eligible_count"], 0)
        self.assertEqual(report["export_eligible_count"], 0)
        self.assertEqual(report["diagnostics"], {})
        self.assertEqual(report["inspection"], {})
        self.assertEqual(report["nodes"], [])
        self.assertEqual(set(report["groups"]), {"global", "google", "youtube", "chatgpt"})

    def test_export_eligibility_requires_services_but_dev_does_not_require_reverification(self):
        policy = NodePolicy(min_speed_kbps=5000, max_latency_ms=1500)
        nodes = [measured_node("unverified", _verification=None),
                 measured_node("no-service", _categories=[]),
                 measured_node("too-slow", _speed_kbps=100)]
        for diagnostics in (None, {"profile": "dev"}, {"profile": "prod"}):
            with self.subTest(diagnostics=diagnostics), tempfile.TemporaryDirectory() as directory:
                write_selection_report(nodes, [], policy, directory, diagnostics=diagnostics)
                report = json.loads((Path(directory) / "node_selection_report.json").read_text(encoding="utf-8"))

            production = diagnostics is not None and diagnostics["profile"] == "prod"
            self.assertEqual(report["performance_eligible_count"], 2)
            self.assertEqual(report["export_eligible_count"], 0 if production else 1)
            self.assertEqual([node["export_eligible"] for node in report["nodes"]],
                             [not production, False, False])

    def test_report_counts_real_unique_exits_globally_and_per_source(self):
        shared = measured_node("shared", _source="cloudflare_auto", _source_ids=["rss", "cloudflare_auto"],
                               _exit_quality={"status": "clean", "ip": "8.8.8.8"})
        same_exit = measured_node("same-exit", _source_ids=["rss"],
                                  _exit_quality={"status": "unknown", "ip": "8.8.8.8"})
        v6 = measured_node("v6", _source_ids=["paid"],
                           _exit_quality={"status": "clean", "ip": "2606:4700:4700::1111"})
        v6_long = measured_node("v6-long", _source_ids=["paid"],
                                _exit_quality={"status": "clean", "ip": "2606:4700:4700:0:0:0:0:1111"})
        unknown = measured_node("unknown", _source_ids=["rss"], _verification="not_selected")
        slow = measured_node("slow", _source_ids=["paid"], _speed_kbps=100, _verification="failed")
        measured = [shared, same_exit, v6, v6_long, unknown, slow]
        selected = [shared, v6, unknown]
        diagnostics = {"profile": "prod", "sources": [
            {"id": "rss", "type": "rss", "status": "collected", "parsed_count": 100},
            {"id": "empty", "type": "subscription", "status": "failed", "parsed_count": 0},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            write_selection_report(measured, selected, NodePolicy(min_speed_kbps=5000), directory,
                                   diagnostics=diagnostics)
            report = json.loads((Path(directory) / "node_selection_report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["observed_unique_exit_count"], 2)
        self.assertEqual(report["selected_unique_exit_count"], 2)
        self.assertEqual(report["observed_unknown_exit_count"], 2)
        self.assertEqual(report["selected_unknown_exit_count"], 1)
        sources = {source["id"]: source for source in report["sources"]}
        self.assertEqual(sources["rss"]["measured_count"], 3)
        self.assertEqual(sources["rss"]["performance_eligible_count"], 3)
        self.assertEqual(sources["rss"]["verified_count"], 2)
        self.assertEqual(sources["rss"]["selected_count"], 2)
        self.assertEqual(sources["rss"]["observed_unique_exit_count"], 1)
        self.assertEqual(sources["rss"]["selected_unique_exit_count"], 1)
        self.assertEqual(sources["rss"]["observed_unknown_exit_count"], 1)
        self.assertEqual(sources["rss"]["parsed_count"], 100)
        self.assertEqual(sources["paid"]["measured_count"], 3)
        self.assertEqual(sources["paid"]["performance_eligible_count"], 2)
        self.assertEqual(sources["paid"]["observed_unique_exit_count"], 1)
        self.assertEqual(sources["cloudflare_auto"]["selected_count"], 1)
        for key in ("measured_count", "performance_eligible_count", "verified_count", "selected_count",
                    "observed_unique_exit_count", "selected_unique_exit_count", "observed_unknown_exit_count"):
            self.assertEqual(sources["empty"][key], 0)
        self.assertEqual(sources["empty"]["status"], "failed")
        nodes = {item["name"]: item for item in report["nodes"]}
        self.assertEqual(nodes["shared"]["sources"], ["cloudflare_auto", "rss"])

    def test_unknown_and_invalid_exit_values_do_not_count_as_independent_exits(self):
        measured = [measured_node(f"node-{index}", _exit_quality={"status": "unknown", "ip": value})
                    for index, value in enumerate((None, "", "not-ip", True, 134744072, "127.0.0.1", "192.168.1.1"))]
        with tempfile.TemporaryDirectory() as directory:
            write_selection_report(measured, measured, NodePolicy(), directory)
            report = json.loads((Path(directory) / "node_selection_report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["observed_unique_exit_count"], 0)
        self.assertEqual(report["selected_unique_exit_count"], 0)
        self.assertEqual(report["observed_unknown_exit_count"], len(measured))
        self.assertEqual(report["selected_unknown_exit_count"], len(measured))

    def test_empty_collection_still_reports_declared_sources(self):
        diagnostics = {"sources": [{"id": "vpngate", "type": "vpngate", "status": "empty", "parsed_count": 0}]}
        with tempfile.TemporaryDirectory() as directory:
            write_selection_report([], [], NodePolicy(), directory, diagnostics=diagnostics)
            report = json.loads((Path(directory) / "node_selection_report.json").read_text(encoding="utf-8"))
        self.assertEqual(len(report["sources"]), 1)
        self.assertEqual(report["sources"][0]["id"], "vpngate")
        self.assertEqual(report["sources"][0]["measured_count"], 0)
        self.assertEqual(report["observed_unique_exit_count"], 0)


if __name__ == "__main__":
    unittest.main()
