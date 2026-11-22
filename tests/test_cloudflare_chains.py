import asyncio
import base64
import copy
import ipaddress
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import yaml

from main import main, parse_command_args, _merge_cloudflare_source
from utils.cloudflare_config import load_cloudflare_config, save_cloudflare_config
from utils.cloudflare_source import (
    CloudflareSourceError, _parse_addresses, expand_cloudflare_proxies,
    get_cloudflare_proxies, get_cloudflare_templates,
)
from utils.cloudflare_speedtest import (
    CFST_DOWNLOAD_SECONDS, _parse_speedtest_results, get_optimized_cloudflare_proxies,
    run_cloudflare_speedtest,
)
from utils.clash_manager import ClashMetaManager, supports_openvpn
from utils.proxy_chain import DEPENDENCIES_KEY, materialize_proxies
from utils.utils import filter_proxies, test_nodes, test_proxy_telnet_async, _test_node_metrics_async


def worker(name="front", server="104.16.0.1"):
    return {
        "name": name, "type": "vless", "server": server, "port": 443,
        "uuid": "11111111-1111-4111-8111-111111111111", "tls": True,
        "network": "ws", "servername": "worker.example",
        "ws-opts": {"path": "/?proxyip=exit.example:443&ed=2560",
                    "headers": {"host": "worker.example"}, "max-early-data": 2560,
                    "early-data-header-name": "Sec-WebSocket-Protocol"},
    }


def subscription(exit_count=2):
    front = worker()
    alternate = worker("alternate", "104.16.0.2")
    nodes = [front, alternate]
    for index in range(exit_count):
        nodes.append({
            "name": f"home-{index}", "type": "openvpn", "server": f"192.0.2.{index + 1}",
            "port": 443, "proto": "tcp", "username": "vpn", "password": "vpn",
            "cipher": "AES-128-CBC", "auth": "SHA1", "udp": False,
            "ca": "fixture-ca", "cert": "fixture-cert", "key": "fixture-key",
            "handshake-timeout": 30, "dialer-proxy": "front-group",
        })
    return {"proxies": nodes, "proxy-groups": [
        {"name": "front-group", "type": "url-test", "proxies": ["front", "alternate"]}],
        "rules": ["MATCH,DIRECT"], "external-controller": "0.0.0.0:9090"}


def parse_document(document, **kwargs):
    text = yaml.safe_dump(document, allow_unicode=True)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "subscription.yaml"
        path.write_text(text, encoding="utf-8")
        return get_cloudflare_proxies(Mock(), subscription_file=path, **kwargs)


class CloudflareChainTests(unittest.TestCase):
    def test_yaml_chain_covers_exits_before_alternate_ingresses(self):
        document = subscription()
        original = copy.deepcopy(document)
        nodes = parse_document(document, max_candidates=3)
        self.assertEqual([node["server"] for node in nodes], ["192.0.2.1", "192.0.2.2", "192.0.2.1"])
        self.assertEqual([node[DEPENDENCIES_KEY][0]["server"] for node in nodes],
                         ["104.16.0.1", "104.16.0.1", "104.16.0.2"])
        self.assertEqual(document, original)
        self.assertEqual(nodes[0]["ca"], "fixture-ca")
        self.assertEqual(nodes[0][DEPENDENCIES_KEY][0]["ws-opts"]["max-early-data"], 2560)
        self.assertEqual(nodes[0][DEPENDENCIES_KEY][0]["ws-opts"]["headers"], {"Host": "worker.example"})

    def test_base64_yaml_and_yaml_anchors_are_supported(self):
        document = subscription()
        text = yaml.safe_dump(document).replace("ca: fixture-ca", "ca: &shared fixture-ca", 1)
        text = text.replace("ca: fixture-ca", "ca: *shared")
        for raw in (text, base64.b64encode(text.encode()).decode()):
            with patch("utils.cloudflare_source._fetch_subscription", new=AsyncMock(return_value=raw.encode())):
                nodes = get_cloudflare_proxies(Mock(), subscription_url="https://worker.example/id/sub?target=vg")
            self.assertEqual(len(nodes), 4)
            self.assertTrue(all(node["ca"] == "fixture-ca" for node in nodes))

    def test_group_cycle_missing_reference_and_direct_do_not_fall_back_to_ingress(self):
        for members in (["front-group"], ["missing"], ["DIRECT"], ["REJECT"]):
            document = subscription()
            document["proxy-groups"][0]["proxies"] = members
            with self.subTest(members=members), self.assertRaisesRegex(CloudflareSourceError, "没有可解析"):
                parse_document(document)

    def test_duplicate_names_are_rejected(self):
        document = subscription()
        document["proxies"][1]["name"] = "front"
        with self.assertRaisesRegex(CloudflareSourceError, "重名"):
            parse_document(document)

    def test_missing_certificate_and_direct_openvpn_are_rejected(self):
        for key in ("ca", "cert", "key", "dialer-proxy"):
            document = subscription(1)
            document["proxies"][-1].pop(key)
            with self.subTest(key=key), self.assertRaises(CloudflareSourceError):
                parse_document(document)

    def test_trojan_yaml_ingress_is_retained(self):
        document = subscription(1)
        document["proxies"][0].update(type="trojan", password="test-password")
        document["proxies"][0].pop("uuid")
        document["proxies"][0].pop("tls")
        nodes = parse_document(document, max_candidates=1)
        self.assertEqual(nodes[0][DEPENDENCIES_KEY][0]["type"], "trojan")

    def test_address_override_cannot_replace_openvpn_exit(self):
        with self.assertRaisesRegex(CloudflareSourceError, "不能用地址文件替换出口"):
            parse_document(subscription(), addresses_file="unused.txt")

    def test_gate_exit_list_is_not_silently_treated_as_ip_list(self):
        for suffix in ("sstp://vpn:vpn@exit.example:443", "socks5://user:secret@exit.example:1080"):
            with self.assertRaisesRegex(CloudflareSourceError, "nodes.txt") as error:
                _parse_addresses("104.16.0.1:443#JP$" + suffix, "addresses")
            self.assertNotIn("secret", str(error.exception))

    def test_standalone_yaml_preserves_worker_path_and_early_data(self):
        node = parse_document({"proxies": [worker()]})[0]
        self.assertEqual(node["ws-opts"]["path"], worker()["ws-opts"]["path"])
        self.assertEqual(node["ws-opts"]["max-early-data"], 2560)

    def test_chain_is_not_dialed_directly_during_tcp_prefilter(self):
        node = parse_document(subscription(), max_candidates=1)[0]
        with patch("utils.utils.asyncio.open_connection", new=AsyncMock()) as dial:
            self.assertEqual(asyncio.run(test_proxy_telnet_async(node)), node)
        dial.assert_not_called()

    def test_chain_probe_allows_openvpn_handshake(self):
        node = parse_document(subscription(), max_candidates=1)[0]
        samples = [
            [("https://www.google.com/generate_204", True, 0.1, 0)],
            [("https://www.gstatic.com/generate_204", True, 0.1, 0)],
            [("https://speed.cloudflare.com/__down?bytes=1048576", False, 0.1, 0)],
        ]
        with patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=samples)) as probe:
            asyncio.run(_test_node_metrics_async(node, 12345, timeout=2))
        self.assertGreater(probe.call_args_list[0].kwargs["timeout"], 34)
        self.assertLessEqual(probe.call_args_list[0].kwargs["timeout"], 35)
        self.assertEqual(probe.await_count, 3)

    def test_dedup_rename_and_batches_retain_dependencies(self):
        nodes = parse_document(subscription(21), max_candidates=21)
        for node in nodes:
            node["name"] = "same"
        nodes = filter_proxies(nodes)
        self.assertEqual(len({node["name"] for node in nodes}), 21)
        for batch in (nodes[:20], nodes[20:]):
            materialized = materialize_proxies(batch)
            names = {node["name"] for node in materialized}
            self.assertTrue(all(node["dialer-proxy"] in names for node in materialized if "dialer-proxy" in node))
            self.assertEqual(len(materialized), len(batch) + 1)

    def test_output_preserves_dependencies_without_granting_service_qualification(self):
        nodes = parse_document(subscription(), max_candidates=2)
        for node in nodes:
            node["_categories"] = {"google"}
            node.update(_latency=150, _speed_kbps=8000, _download_passed=True)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "clash.yaml"
            manager = ClashMetaManager("base_template.yaml", "test_config.yaml")
            with patch("utils.clash_manager.GENERATED_PROXY_CONFIG", str(output)):
                manager.save_config(nodes, str(output))
            config = yaml.safe_load(output.read_text(encoding="utf-8"))
            manager.write_config(nodes[:1], output_path=str(output))
            test_config = yaml.safe_load(output.read_text(encoding="utf-8"))
        dependencies = {node["name"] for node in config["proxies"] if node["type"] == "vless"}
        self.assertEqual(len(dependencies), 1)
        self.assertEqual(len(config["proxies"]), 3)
        for group in config["proxy-groups"]:
            self.assertFalse(dependencies.intersection(group.get("proxies", [])))
        google = next(g for g in config["proxy-groups"] if "google" in g["name"].lower())
        self.assertEqual(google["timeout"], 35000)
        global_group = next(g for g in config["proxy-groups"] if g["name"] == "GLOBAL")
        self.assertFalse(set(n["name"] for n in nodes).intersection(global_group["proxies"]))
        self.assertEqual(test_config["proxy-groups"][0]["proxies"], [nodes[0]["name"]])
        self.assertEqual(len(test_config["proxies"]), 2)
        self.assertTrue(all(not key.startswith("_") for n in config["proxies"] for key in n))

    def test_dependency_names_cannot_collide_with_selected_nodes(self):
        node = parse_document(subscription(), max_candidates=1)[0]
        node["name"] = node["dialer-proxy"]
        output = materialize_proxies([node])
        self.assertEqual(len({p["name"] for p in output}), 2)
        self.assertNotEqual(output[-1]["name"], output[-1]["dialer-proxy"])
        self.assertEqual(output[-1]["dialer-proxy"], output[0]["name"])

    def test_old_core_skips_openvpn_without_testing_broken_batch(self):
        nodes = parse_document(subscription(), max_candidates=1)
        with patch("utils.utils.supports_openvpn", return_value=False), \
                patch("utils.utils._test_batch_nodes") as batch:
            self.assertEqual(test_nodes(nodes, "dev", "unused"), [])
        batch.assert_not_called()

    def test_core_version_check(self):
        for version, expected in (("v1.19.18", False), ("v1.19.25", False),
                                  ("v1.19.26", False), ("v1.19.27", False),
                                  ("v1.19.28", False), ("v1.19.29", False),
                                  ("v1.19.30", True), ("v1.20.0", True), ("unknown", False)):
            with patch("utils.clash_manager.subprocess.run", return_value=subprocess.CompletedProcess([], 0, f"Mihomo Meta {version}", "")):
                self.assertEqual(supports_openvpn(), expected)

    def test_full_collection_filter_batch_and_export_keeps_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "cfnew.yaml"
            output = Path(directory) / "clash.yaml"
            source.write_text(yaml.safe_dump(subscription(1)), encoding="utf-8")
            runtime_configs = []

            def start(config_path=None):
                runtime_configs.append(yaml.safe_load(Path(config_path).read_text(encoding="utf-8")))

            metrics = {"is_available": True, "avg_latency": 150, "avg_speed_kbps": 8000,
                       "download_passed": True,
                       "google_latency": 150, "youtube_latency": None, "chatgpt_latency": None}
            with patch("main.start_proxies", return_value=(None, None)), \
                    patch("main.get_subscribe_proxies", return_value=[]), \
                    patch("main.get_clash_proxies", return_value=[]), \
                    patch("main._subscription_session", return_value=Mock()), \
                    patch("main.ensure_openvpn_runtime"), \
                    patch("utils.utils.supports_openvpn", return_value=True), \
                    patch.object(ClashMetaManager, "start", side_effect=start), \
                    patch.object(ClashMetaManager, "stop"), \
                    patch.object(ClashMetaManager, "switch_proxy", return_value=True), \
                    patch("utils.utils.test_node_metrics", return_value=metrics), \
                    patch("utils.exit_quality.ExitInspector.inspect", return_value={"status": "unknown"}), \
                    patch("utils.clash_manager.GENERATED_PROXY_CONFIG", str(output)):
                result = main("prod", directory, {"subscription_file": str(source),
                                                  "max_candidates": 1, "automatic_enabled": False,
                                                  "vpngate": {"enabled": False}})
            exported = yaml.safe_load(output.read_text(encoding="utf-8"))
        self.assertEqual(len(result), 1)
        for config in [runtime_configs[0], exported]:
            nodes = {node["name"]: node for node in config["proxies"]}
            exit_node = next(node for node in nodes.values() if node["type"] == "openvpn")
            self.assertTrue(exit_node["name"].endswith("-cf"))
            self.assertIn(exit_node["name"], config["proxy-groups"][0]["proxies"]
                          if config is runtime_configs[0] else
                          next(group for group in config["proxy-groups"]
                               if "google" in group["name"].lower())["proxies"])
            self.assertEqual(nodes[exit_node["dialer-proxy"]]["server"], "104.16.0.1")
            self.assertEqual(exit_node["server"], "192.0.2.1")


class CloudflareOptimizationRegressionTests(unittest.TestCase):
    def test_non_cf_nodes_cannot_exhaust_template_budget(self):
        nodes = []
        for index in range(3):
            node = worker(server=f"192.0.2.{index + 1}")
            node["ws-opts"]["path"] = f"/non-cf-{index}"
            nodes.append(node)
        nodes.append(worker())
        with patch("utils.cloudflare_speedtest.fetch_cloudflare_ipv4_networks", return_value=[ipaddress.ip_network("104.16.0.0/13")]), \
                patch("utils.cloudflare_speedtest.run_cloudflare_speedtest", return_value=[{"ip": "104.16.0.2"}]):
            result = get_optimized_cloudflare_proxies(nodes)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ws-opts"]["path"], worker()["ws-opts"]["path"])

    def test_template_identity_includes_early_data_options(self):
        other = worker()
        other["ws-opts"]["max-early-data"] = 2048
        self.assertEqual(len(get_cloudflare_templates([worker(), other])), 2)

    def test_candidate_budget_round_robins_templates(self):
        other = worker()
        other["ws-opts"]["path"] = "/other"
        result = expand_cloudflare_proxies([worker(), other], ["104.16.0.2", "104.16.0.3"], max_candidates=3)
        self.assertEqual([p["server"] for p in result], ["104.16.0.2", "104.16.0.2", "104.16.0.3"])
        self.assertEqual(result[1]["ws-opts"]["path"], "/other")

    def test_csv_sorted_before_limit_and_invalid_values_rejected(self):
        raw = ("IP Address,Download Speed(MB/s)\n104.16.0.1,1\n104.16.0.2,10\n"
               "104.16.0.3,bad99\n104.16.0.2,2\n104.16.0.4,inf\n").encode()
        self.assertEqual(_parse_speedtest_results(raw, 1), [{"ip": "104.16.0.2", "download_speed": 10}])

    def test_runner_budget_covers_sequential_downloads_and_bounds_work(self):
        def run(command, **kwargs):
            Path(command[command.index("-o") + 1]).write_text("IP Address,Download Speed(MB/s)\n104.16.0.1,1\n")
            return subprocess.CompletedProcess(command, 0, "", "")
        with patch("utils.cloudflare_speedtest._get_cloudflare_speedtest_binary", return_value=Path("cfst.exe")), \
                patch("utils.cloudflare_speedtest.subprocess.run", side_effect=run) as execute:
            run_cloudflare_speedtest([ipaddress.ip_network("104.16.0.0/24")], max_candidates=500)
        command = execute.call_args.args[0]
        count = int(command[command.index("-dn") + 1])
        self.assertLessEqual(count, 40)
        self.assertGreater(execute.call_args.kwargs["timeout"], count * CFST_DOWNLOAD_SECONDS)

    def test_limits_reject_boolean_float_zero_and_excess(self):
        for limit in (True, 0, -1, 1.5, 501):
            with self.subTest(limit=limit), self.assertRaises(CloudflareSourceError):
                get_cloudflare_proxies(Mock(), subscription_file="unused", max_candidates=limit)

    def test_opt_out_skips_automatic_scan(self):
        with patch("main.start_proxies", return_value=(None, None)), \
                patch("main._collect_proxies"), patch("main.test_nodes", return_value=[]), \
                patch("main.get_optimized_cloudflare_proxies") as scan:
            main("dev", "unused", {"automatic_enabled": False})
        scan.assert_not_called()
        with patch("sys.argv", ["main.py", "--no-cloudflare-optimize"]):
            config = parse_command_args()["cloudflare_source"]
        self.assertFalse(_merge_cloudflare_source(None, config)["automatic_enabled"])

    def test_opt_out_persists_with_worker_subscription(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "cloudflare.yaml"
            save_cloudflare_config({"subscription_url": "https://worker.example/id/sub?target=vg", "automatic_enabled": False}, config)
            self.assertFalse(load_cloudflare_config(config)["automatic_enabled"])


if __name__ == "__main__":
    unittest.main()
