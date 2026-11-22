import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import yaml

from utils.exit_quality import (
    ExitInspector, LookupError, apply_ipapi, parse_ipquery,
)
from utils.node_policy import (
    NodePolicy, load_node_policy, preferred_pool, quality_tier, select_candidates,
)
from utils.clash_manager import ClashMetaManager
from utils.mihomo_runtime import resolve_mihomo_executable
from utils.selection_report import write_selection_report
from utils.utils import _test_batch_nodes


def ipquery(**flags):
    risk = dict(is_mobile=False, is_vpn=False, is_tor=False, is_proxy=False,
                is_datacenter=False, risk_score=0)
    risk.update(flags)
    return {"ip": "8.8.4.4", "risk": risk}


def ipapi(**flags):
    data = dict(ip="8.8.4.4", is_bogon=False, is_mobile=False, is_satellite=False,
                is_anycast=False, is_crawler=False, is_datacenter=False, is_tor=False,
                is_proxy=False, is_vpn=False, is_abuser=False)
    data.update(company={"type": "isp", "abuser_score": "0.0001 (Very Low)"},
                asn={"type": "isp", "abuser_score": "0.0001 (Very Low)"})
    data.update(flags)
    return data


def node(name, status="unknown", residential=None, speed=10000, latency=100, services=None):
    return {"name": name, "type": "ss", "server": "example.com", "port": 443,
            "cipher": "aes-128-gcm", "password": "private-password",
            "_categories": set(services if services is not None else ("google", "youtube", "chatgpt")),
            "_latency": latency, "_speed_kbps": speed, "_download_passed": True,
            "_exit_quality": {"status": status, "residential": residential, "ip": "8.8.4.4"}}


class EvidenceTests(unittest.TestCase):
    def test_low_risk_is_not_automatically_residential(self):
        evidence = parse_ipquery(ipquery(), NodePolicy())
        self.assertEqual(evidence["status"], "clean")
        self.assertIsNone(evidence["residential"])
        self.assertEqual(parse_ipquery(ipquery(is_datacenter=True), NodePolicy())["status"], "clean")

    def test_missing_fields_and_non_boolean_false_are_unknown(self):
        for field in ("is_mobile", "is_vpn", "is_tor", "is_proxy", "is_datacenter", "risk_score"):
            data = ipquery()
            data["risk"].pop(field)
            self.assertEqual(parse_ipquery(data, NodePolicy())["status"], "unknown")
        for value in ("false", 0, None):
            self.assertEqual(parse_ipquery(ipquery(is_proxy=value), NodePolicy())["status"], "unknown")

    def test_nonfinite_risk_and_nonpublic_ips_are_unknown(self):
        for value in (True, -1, 101, float("nan"), float("inf"), "0"):
            self.assertEqual(parse_ipquery(ipquery(risk_score=value), NodePolicy())["status"], "unknown")
        for ip in ("127.0.0.1", "192.168.1.2", "::1", "not-an-ip", None, 134743044, True):
            data = ipquery()
            data["ip"] = ip
            self.assertEqual(parse_ipquery(data, NodePolicy())["status"], "unknown")

    def test_positive_risk_signal_disqualifies_clean(self):
        for changes in ({"is_vpn": True}, {"is_proxy": True}, {"is_tor": True}, {"risk_score": 11}):
            self.assertEqual(parse_ipquery(ipquery(**changes), NodePolicy())["status"], "risk")

    def test_residential_requires_positive_isp_and_negative_special_network_flags(self):
        evidence = parse_ipquery(ipquery(), NodePolicy())
        self.assertTrue(apply_ipapi(evidence, ipapi(), NodePolicy())["residential"])
        for field in ("is_datacenter", "is_mobile", "is_satellite", "is_anycast"):
            for value in (True, None, "false"):
                result = apply_ipapi(evidence, ipapi(**{field: value}), NodePolicy())
                self.assertIsNot(result["residential"], True)
        for field in ("company", "asn"):
            data = ipapi()
            data[field]["type"] = "business"
            self.assertFalse(apply_ipapi(evidence, data, NodePolicy())["residential"])

    def test_reputation_disagreement_missing_fields_and_ip_mismatch(self):
        evidence = parse_ipquery(ipquery(), NodePolicy())
        self.assertEqual(apply_ipapi(evidence, ipapi(is_abuser=True), NodePolicy())["status"], "risk")
        self.assertEqual(apply_ipapi(evidence, ipapi(ip="1.1.1.1"), NodePolicy())["status"], "unknown")
        data = ipapi()
        data.pop("is_proxy")
        self.assertEqual(apply_ipapi(evidence, data, NodePolicy())["status"], "unknown")
        data = ipapi()
        data["asn"].pop("abuser_score")
        self.assertEqual(apply_ipapi(evidence, data, NodePolicy())["status"], "unknown")
        data = ipapi()
        data["company"]["abuser_score"] = "0.2 (High)"
        self.assertEqual(apply_ipapi(evidence, data, NodePolicy())["status"], "risk")

    def test_requests_use_selected_local_proxy_and_never_environment(self):
        with patch.dict(os.environ, {"IPAPI_IS_KEY": "", "HTTPS_PROXY": "http://wrong.example:80"}), \
                patch("utils.exit_quality._request_json", return_value=ipquery()) as request:
            result = ExitInspector().inspect(18010)
        self.assertEqual(result["status"], "clean")
        self.assertEqual(request.call_args.args[0], "http://127.0.0.1:18010")
        self.assertEqual(request.call_args.kwargs["params"], {"format": "json"})

    def test_keyed_lookup_cached_by_exit_but_egress_is_rechecked_per_node(self):
        calls = []

        def request(proxy_url, method, url, timeout, **kwargs):
            calls.append((method, url, kwargs))
            return ipquery() if method == "GET" else ipapi()

        with patch.dict(os.environ, {"IPAPI_IS_KEY": "test-private-key"}), \
                patch("utils.exit_quality._request_json", side_effect=request):
            inspector = ExitInspector()
            first = inspector.inspect(18010)
            second = inspector.inspect(18020)
        self.assertTrue(first["residential"])
        self.assertTrue(second["residential"])
        self.assertEqual([c[0] for c in calls], ["GET", "POST", "GET"])
        self.assertNotIn("test-private-key", json.dumps(second))
        self.assertEqual(calls[1][2]["json"]["q"], first["ip"])

    def test_query_failure_does_not_fall_back_to_direct(self):
        with patch.dict(os.environ, {"IPAPI_IS_KEY": ""}), \
                patch("utils.exit_quality._request_json", side_effect=LookupError("private-token")) as request:
            result = ExitInspector().inspect(18010)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(request.call_count, 1)
        self.assertNotIn("private-token", json.dumps(result))

    def test_round_budget_prevents_excess_requests(self):
        with patch.dict(os.environ, {"IPAPI_IS_KEY": ""}), \
                patch("utils.exit_quality._request_json", return_value=ipquery()) as request:
            inspector = ExitInspector(NodePolicy(max_lookups_per_round=1))
            inspector.inspect(18010)
            result = inspector.inspect(18020)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(result["reason"], "round_lookup_budget")

    def test_ipquery_rejection_does_not_block_another_exit(self):
        for status in (403, 429):
            with self.subTest(status=status), \
                    patch.dict(os.environ, {"IPAPI_IS_KEY": ""}), \
                    patch("utils.exit_quality._request_json", side_effect=[
                        LookupError("limited", status), ipquery()]) as request:
                inspector = ExitInspector()
                first = inspector.inspect(18010)
                second = inspector.inspect(18020)
            self.assertEqual(first["reason"], "provider_rate_limited")
            self.assertEqual(second["status"], "clean")
            self.assertEqual(request.call_count, 2)
            self.assertEqual(
                [call.args[0] for call in request.call_args_list],
                ["http://127.0.0.1:18010", "http://127.0.0.1:18020"],
            )

    def test_keyed_reputation_rate_limit_still_blocks_later_keyed_requests(self):
        other_exit = ipquery()
        other_exit["ip"] = "1.1.1.1"
        for status in (403, 429):
            with self.subTest(status=status), \
                    patch.dict(os.environ, {"IPAPI_IS_KEY": "test-key"}), \
                    patch("utils.exit_quality._request_json", side_effect=[
                        ipquery(), LookupError("limited", status), other_exit]) as request:
                inspector = ExitInspector()
                first = inspector.inspect(18010)
                second = inspector.inspect(18020)
            for result in (first, second):
                self.assertEqual(result["status"], "clean")
                self.assertEqual(result["reason"], "low_risk_signals")
                self.assertIsNone(result["residential"])
                self.assertEqual(result["reputation_reason"], "reputation_rate_limited")
            self.assertEqual(second["ip"], "1.1.1.1")
            self.assertEqual([call.args[1] for call in request.call_args_list], ["GET", "POST", "GET"])

    def test_failed_enrichment_preserves_clean_but_leaves_residential_unknown(self):
        with patch.dict(os.environ, {"IPAPI_IS_KEY": "test-key"}), \
                patch("utils.exit_quality._request_json", side_effect=[ipquery(), LookupError("lookup_timeout")]):
            result = ExitInspector().inspect(18010)
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["reason"], "low_risk_signals")
        self.assertIsNone(result["residential"])
        self.assertEqual(result["reputation_reason"], "reputation_timeout")


class PriorityTests(unittest.TestCase):
    def test_three_level_fallback(self):
        home = node("home", "clean", True, speed=6000, latency=700)
        clean = node("clean", "clean", False, speed=90000, latency=50)
        fast = node("fast", speed=100000, latency=10)
        for candidates, expected in (([fast, clean, home], "home"), ([fast, clean], "clean"), ([fast], "fast")):
            self.assertEqual([p["name"] for p in select_candidates(candidates)], [expected])

    def test_slow_or_incomplete_residential_measurement_joins_clean_tier(self):
        for changes in ({"_speed_kbps": 4999}, {"_latency": 1001}, {"_download_passed": False},
                        {"_speed_kbps": float("nan")}, {"_latency": None}):
            home = node("home", "clean", True)
            home.update(changes)
            self.assertEqual(quality_tier(home), 2)
        self.assertEqual(quality_tier(node("pure home", "unknown", True)), 3)
        self.assertEqual(quality_tier(node("bad home", "risk", True)), 3)

    def test_service_specific_fallback_and_global_eligibility(self):
        home = node("home", "clean", True, services=["google"])
        clean = node("clean", "clean", False, services=["youtube"])
        fast = node("fast", services=["chatgpt"])
        nodes = select_candidates([fast, clean, home])
        self.assertEqual(preferred_pool(nodes, ["google"]), [home])
        self.assertEqual(preferred_pool(nodes, ["youtube"]), [clean])
        self.assertEqual(preferred_pool(nodes, ["chatgpt"]), [fast])
        self.assertEqual(preferred_pool(nodes, ["google", "youtube", "chatgpt"]), [])

    def test_limit_keeps_only_fast_candidate_for_another_service(self):
        homes = [node(f"home-{i}", "clean", True, services=["google"]) for i in range(60)]
        fast = node("youtube-only", services=["youtube"])
        result = select_candidates([*homes, fast])
        self.assertEqual(len(result), 50)
        self.assertIn(fast, result)

    def test_fast_low_latency_tie_breaks_within_fallback(self):
        slow = node("slow", speed=100, latency=900)
        fast = node("fast", speed=10000, latency=20)
        self.assertEqual(select_candidates([slow, fast], limit=1), [fast])

    def test_export_groups_enforce_priority_not_merely_name_order(self):
        home = node("home", "clean", True, services=["google"])
        clean = node("clean", "clean", False, services=["google", "youtube"])
        fast = node("fast")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "clash.yaml"
            with patch("utils.clash_manager.GENERATED_PROXY_CONFIG", str(output)):
                ClashMetaManager("base_template.yaml", "test_config.yaml").save_config([fast, clean, home], str(output))
            config = yaml.safe_load(output.read_text(encoding="utf-8"))
        for service, expected in (("google", ["home"]), ("youtube", ["clean"]), ("chatgpt", ["fast"])):
            group = next(g for g in config["proxy-groups"] if service in g["name"].lower())
            self.assertEqual(group["proxies"], expected)
        auto = next(g for g in config["proxy-groups"] if "自动选择" in g["name"])
        self.assertEqual(auto["proxies"], ["fast"])
        self.assertTrue(all(not key.startswith("_") for p in config["proxies"] for key in p))

    def test_quality_probe_occurs_after_switch_before_next_node(self):
        manager = MagicMock()
        inspector = Mock()
        events = []
        manager.switch_proxy.side_effect = lambda name: events.append(name) or True
        inspector.inspect.side_effect = lambda port: events.append(port) or {"status": "clean", "residential": False}
        metrics = {"is_available": True, "avg_latency": 100, "avg_speed_kbps": 10000,
                   "download_passed": True, "google_latency": 100, "youtube_latency": None, "chatgpt_latency": None}
        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.utils.ClashMetaManager", return_value=manager), \
                patch("utils.utils.find_free_port_block", side_effect=[(18000, 18001), (18010, 18010)]), \
                patch("utils.utils.test_node_metrics", return_value=metrics):
            results = _test_batch_nodes([node("one"), node("two")], directory, 6, 0, inspector)
        self.assertEqual(events, ["one", 18000, "two", 18000])
        self.assertEqual([quality_tier(p) for p in results], [2, 2])

    def test_report_contains_reason_without_proxy_credentials(self):
        measured = [node("home", "clean", True), node("fast")]
        with tempfile.TemporaryDirectory() as directory:
            write_selection_report(measured, select_candidates(measured), NodePolicy(), directory)
            raw = (Path(directory) / "node_selection_report.json").read_text(encoding="utf-8")
        self.assertNotIn("private-password", raw)
        report = json.loads(raw)
        self.assertEqual(report["groups"]["google"]["tier"], 1)
        self.assertEqual(report["selected_count"], 1)
        self.assertEqual(len(report["nodes"]), 2)


class PlatformAndPolicyTests(unittest.TestCase):
    def test_native_core_resolution_and_architecture_override(self):
        with patch.dict(os.environ, {"MIHOMO_BINARY": ""}), \
                patch("utils.mihomo_runtime._cached_runtime", return_value=None):
            self.assertTrue(resolve_mihomo_executable("Windows", "AMD64").endswith("windows-compatible.exe"))
            self.assertTrue(resolve_mihomo_executable("Linux", "x86_64").endswith("linux-compatible"))
            with self.assertRaisesRegex(ValueError, "架构"):
                resolve_mihomo_executable("Linux", "aarch64")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "my core"
            path.write_text("fixture")
            with patch.dict(os.environ, {"MIHOMO_BINARY": str(path)}):
                self.assertEqual(resolve_mihomo_executable("Linux", "aarch64"), str(path.resolve()))

    def test_policy_thresholds_and_invalid_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.yaml"
            path.write_text("residential_min_speed_kbps: 20000\n", encoding="utf-8")
            policy = load_node_policy(path)
            self.assertEqual(quality_tier(node("home", "clean", True), policy), 2)
            for data in ({"max_risk_score": float("nan")}, {"max_risk_score": True},
                         {"max_lookups_per_round": 1.5}, {"unknown": True}, {"lookup_timeout_seconds": 0}):
                path.write_text(yaml.safe_dump(data), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_node_policy(path)
            with self.assertRaisesRegex(ValueError, "不存在"):
                load_node_policy(Path(directory) / "missing.yaml")


if __name__ == "__main__":
    unittest.main()
