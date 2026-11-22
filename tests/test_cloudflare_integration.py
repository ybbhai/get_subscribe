import tempfile
import ipaddress
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import requests
import aiohttp

from main import _collect_proxies, _merge_cloudflare_source, main, parse_command_args
from utils.cloudflare_source import (
    CloudflareSourceError,
    MAX_AUTOMATIC_TEMPLATES,
    expand_cloudflare_proxies,
    get_cloudflare_proxies,
    get_cloudflare_templates,
)


UUID_ONE = "11111111-1111-4111-8111-111111111111"
UUID_TWO = "22222222-2222-4222-8222-222222222222"


def vless_link(user_id, server, name):
    return (
        f"vless://{user_id}@{server}:443?encryption=none&security=tls"
        f"&sni=cdn.example&type=ws&host=cdn.example&path=%2Fedge#{name}"
    )


class CloudflareSourceTests(unittest.TestCase):
    def test_selects_only_compatible_templates_in_official_ipv4_ranges(self):
        compatible = {
            "name": "template", "type": "vless", "server": "104.16.0.1",
            "port": 443, "uuid": UUID_ONE, "network": "ws", "tls": True,
            "servername": "cdn.example", "alpn": ["http/1.1"],
            "ws-opts": {"path": "/edge", "headers": {"Host": "cdn.example"}},
        }
        wrong_port = dict(compatible, port=8443)
        wrong_alpn = dict(compatible, alpn=["h2"])
        wrong_network = dict(compatible, server="203.0.113.8")

        templates = get_cloudflare_templates(
            [compatible, wrong_port, wrong_alpn, wrong_network, None],
            [ipaddress.ip_network("104.16.0.0/13")],
        )

        self.assertEqual(len(templates), 1)
        self.assertEqual(templates[0]["server"], "104.16.0.1")
        self.assertEqual(templates[0]["uuid"], UUID_ONE)
        self.assertEqual(templates[0]["servername"], "cdn.example")
        self.assertEqual(templates[0]["ws-opts"]["headers"]["Host"], "cdn.example")
        self.assertEqual(templates[0]["ws-opts"]["path"], "/edge")
        self.assertEqual(compatible["server"], "104.16.0.1")

    def test_automatic_templates_cover_distinct_hosts_before_same_host_variants(self):
        def template(host, path):
            return {
                "name": host, "type": "vless", "server": "104.16.0.1",
                "port": 443, "uuid": UUID_ONE, "network": "ws", "tls": True,
                "servername": host,
                "ws-opts": {"path": path, "headers": {"Host": host}},
            }

        proxies = [template("first.example", f"/variant-{index}") for index in range(12)]
        proxies += [template("FIRST.EXAMPLE.", "/case-variant")]
        proxies += [template(f"worker-{index}.example", "/edge") for index in range(11)]

        selected = get_cloudflare_templates(proxies)

        self.assertEqual(len(selected), 10)
        self.assertEqual(
            [proxy["ws-opts"]["headers"]["Host"] for proxy in selected],
            ["first.example"] + [f"worker-{index}.example" for index in range(9)],
        )
        selected = get_cloudflare_templates(proxies[:13] + proxies[13:14], limit=4)
        self.assertEqual(
            [proxy["ws-opts"]["path"] for proxy in selected],
            ["/variant-0", "/edge", "/variant-1", "/variant-2"],
        )
        # Worker route diversity must not enlarge CFnew OpenVPN chain expansion.
        self.assertEqual(MAX_AUTOMATIC_TEMPLATES, 3)

    def test_more_automatic_templates_still_respect_default_candidate_budget(self):
        templates = [
            {"name": f"template-{index}", "uuid": UUID_ONE}
            for index in range(10)
        ]
        candidates = expand_cloudflare_proxies(
            templates, [f"104.16.0.{index}" for index in range(1, 7)],
        )

        self.assertEqual(len(candidates), 40)
        self.assertEqual(len({proxy["server"] for proxy in candidates}), 4)
        self.assertTrue(all(proxy["_source"] == "cloudflare_auto" for proxy in candidates))
        self.assertTrue(all("_source" not in proxy for proxy in templates))

    def test_expands_ranked_addresses_and_preserves_template_configuration(self):
        templates = [{
            "name": "template", "type": "vless", "server": "104.16.0.1",
            "port": 443, "uuid": UUID_ONE, "network": "ws", "tls": True,
            "servername": "cdn.example", "client-fingerprint": "chrome",
            "ws-opts": {"path": "/edge", "headers": {"Host": "cdn.example"}},
        }]

        expanded = expand_cloudflare_proxies(
            templates,
            [{"ip": "104.16.0.2"}, {"ip": "203.0.113.4"}],
            max_candidates=2,
            networks=[ipaddress.ip_network("104.16.0.0/13")],
        )

        self.assertEqual(len(expanded), 1)
        self.assertEqual(expanded[0]["server"], "104.16.0.2")
        self.assertEqual(expanded[0]["port"], 443)
        self.assertEqual(expanded[0]["uuid"], UUID_ONE)
        self.assertEqual(expanded[0]["servername"], "cdn.example")
        self.assertEqual(expanded[0]["client-fingerprint"], "chrome")
        self.assertEqual(expanded[0]["ws-opts"], templates[0]["ws-opts"])
        self.assertEqual(expanded[0]["_source"], "cloudflare_auto")
        self.assertEqual(templates[0]["server"], "104.16.0.1")

    def test_reads_edge_tunnel_subscription_file(self):
        with tempfile.TemporaryDirectory() as directory:
            subscription = Path(directory) / "subscription.txt"
            subscription.write_text(vless_link(UUID_ONE, "edge.example", "edge"))

            proxies = get_cloudflare_proxies(
                Mock(), subscription_file=subscription
            )

        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0]["type"], "vless")
        self.assertEqual(proxies[0]["uuid"], UUID_ONE)
        self.assertEqual(proxies[0]["network"], "ws")
        self.assertTrue(proxies[0]["tls"])
        self.assertEqual(proxies[0]["servername"], "cdn.example")
        self.assertEqual(proxies[0]["ws-opts"]["path"], "/edge")

    def test_expands_cloudflare_speedtest_csv_with_selected_template(self):
        with tempfile.TemporaryDirectory() as directory:
            subscription = Path(directory) / "subscription.txt"
            subscription.write_text("\n".join((
                vless_link(UUID_ONE, "first.example", "first"),
                vless_link(UUID_TWO, "second.example", "second"),
            )))
            addresses = Path(directory) / "results.csv"
            addresses.write_text(
                "IP Address,Sent,Received\n104.16.0.1,10,10\n104.16.0.2,10,10\n"
            )

            proxies = get_cloudflare_proxies(
                Mock(),
                subscription_file=subscription,
                addresses_file=addresses,
                addresses_format="cloudflare-speedtest-csv",
                template_index=2,
            )

        self.assertEqual([proxy["server"] for proxy in proxies], [
            "104.16.0.1", "104.16.0.2",
        ])
        self.assertTrue(all(proxy["uuid"] == UUID_TWO for proxy in proxies))
        self.assertTrue(all(proxy["servername"] == "cdn.example" for proxy in proxies))
        self.assertEqual(proxies[0]["name"], "CF-001-104.16.0.1")

    def test_cloudflare_candidate_limit_matches_root_default(self):
        with tempfile.TemporaryDirectory() as directory:
            subscription = Path(directory) / "subscription.txt"
            subscription.write_text("\n".join(
                vless_link(UUID_ONE, f"edge-{index}.example", f"edge-{index}")
                for index in range(3)
            ))
            addresses = Path(directory) / "addresses.txt"
            addresses.write_text("104.16.0.1\n104.16.0.2\n")

            proxies = get_cloudflare_proxies(
                Mock(),
                subscription_file=subscription,
                addresses_file=addresses,
                max_candidates=1,
            )

        self.assertEqual(len(proxies), 1)

    def test_fetches_https_subscription_through_supplied_session(self):
        session = Mock()
        with patch("utils.cloudflare_source._fetch_subscription", new=AsyncMock(return_value=
                   vless_link(UUID_ONE, "edge.example", "edge").encode())) as fetch:
            proxies = get_cloudflare_proxies(
                session, subscription_url="https://edge.example/private/token"
            )

        self.assertEqual(len(proxies), 1)
        fetch.assert_awaited_once_with(session, "https://edge.example/private/token", (5, 10, 15))

    def test_subscription_request_error_does_not_expose_url_token(self):
        secret_url = "https://edge.example/private/token?key=secret"
        session = Mock()
        with patch("utils.cloudflare_source._fetch_subscription", new=AsyncMock(
                side_effect=aiohttp.ClientConnectionError(f"request failed: {secret_url}"))), \
                self.assertRaises(CloudflareSourceError) as raised:
            get_cloudflare_proxies(session, subscription_url=secret_url)

        self.assertNotIn("private/token", str(raised.exception))
        self.assertNotIn("secret", str(raised.exception))

    def test_cloudflare_candidates_join_existing_collectors(self):
        session = Mock()
        source = {
            "subscription_file": "subscription.txt",
            "subscription_url": None,
            "addresses_file": None,
            "addresses_format": "addresses",
            "template_index": 1,
        }
        rss_proxy = {"name": "rss", "type": "ss", "server": "1.1.1.1", "port": 443}
        clash_proxy = {"name": "clash", "type": "ss", "server": "1.1.1.2", "port": 443}
        cloudflare_proxy = {
            "name": "edge", "type": "vless", "server": "1.1.1.3", "port": 443,
        }
        proxies = []

        with patch("main.get_subscribe_proxies", return_value=[rss_proxy]), \
                patch("main.get_clash_proxies", return_value=[clash_proxy]), \
                patch("main._subscription_session", return_value=session), \
                patch("main.get_cloudflare_proxies", return_value=[cloudflare_proxy]):
            _collect_proxies(proxies, False, None, source)

        self.assertEqual([{k: v for k, v in proxy.items() if not k.startswith("_")}
                          for proxy in proxies], [rss_proxy, clash_proxy, dict(cloudflare_proxy, name="edge-cf")])
        self.assertEqual([proxy["_source_ids"] for proxy in proxies],
                         [["rss"], ["clash_subscriptions"], ["cloudflare_legacy"]])
        session.close.assert_called_once_with()

    def test_cloudflare_nodes_reach_the_shared_availability_filter(self):
        source = {"subscription_file": "subscription.txt", "vpngate": {"enabled": False}}
        cloudflare_proxy = {
            "name": "edge", "type": "vless", "server": "edge.example", "port": 443,
            "uuid": UUID_ONE, "network": "ws", "tls": True,
            "servername": "cdn.example",
            "ws-opts": {"path": "/edge", "headers": {"Host": "cdn.example"}},
        }

        with patch("main.start_proxies", return_value=(None, None)), \
                patch("main.get_subscribe_proxies", return_value=[]), \
                patch("main.get_clash_proxies", return_value=[]), \
                patch("main._subscription_session", return_value=Mock()), \
                patch("main.get_cloudflare_proxies", return_value=[cloudflare_proxy]), \
                patch("main.test_proxies_async",
                      new=AsyncMock(return_value=[cloudflare_proxy])), \
                patch("main.test_nodes", return_value=[cloudflare_proxy]) as test_nodes:
            result = main("prod", "unused", source)

        self.assertEqual(result, [cloudflare_proxy])
        self.assertEqual(test_nodes.call_count, 1)
        self.assertEqual(test_nodes.call_args.args[:4], ([cloudflare_proxy], "prod", "unused", 5))
        self.assertEqual(test_nodes.call_args.args[4]["stage_counts"]["tcp_passed"]["total"], 1)

    def test_cli_exposes_cloudflare_inputs(self):
        with patch("sys.argv", [
            "main.py", "-p", "prod", "--cloudflare-subscription-file", "edge.txt",
            "--cloudflare-addresses-file", "results.csv",
            "--cloudflare-addresses-format", "cloudflare-speedtest-csv",
            "--cloudflare-template-index", "2", "--cloudflare-max-candidates", "25",
        ]):
            args = parse_command_args()

        self.assertEqual(args["cloudflare_source"]["subscription_file"], "edge.txt")
        self.assertEqual(args["cloudflare_source"]["addresses_file"], "results.csv")
        self.assertEqual(
            args["cloudflare_source"]["addresses_format"], "cloudflare-speedtest-csv"
        )
        self.assertEqual(args["cloudflare_source"]["template_index"], 2)
        self.assertEqual(args["cloudflare_source"]["max_candidates"], 25)

    def test_cli_overrides_only_explicit_saved_source_fields(self):
        saved = {
            "subscription_file": "/data/edge.txt",
            "subscription_url": None,
            "addresses_file": "/data/results.csv",
            "addresses_format": "cloudflare-speedtest-csv",
            "template_index": 3,
            "max_candidates": 40,
        }
        overrides = {"max_candidates": 25}

        resolved = _merge_cloudflare_source(saved, overrides)

        self.assertEqual(resolved["subscription_file"], "/data/edge.txt")
        self.assertEqual(resolved["addresses_file"], "/data/results.csv")
        self.assertEqual(resolved["addresses_format"], "cloudflare-speedtest-csv")
        self.assertEqual(resolved["template_index"], 3)
        self.assertEqual(resolved["max_candidates"], 25)

        with patch("sys.argv", [
            "main.py", "--cloudflare-max-candidates", "25",
        ]):
            args = parse_command_args()
        self.assertEqual(args["cloudflare_source"], {"max_candidates": 25})

    def test_cli_subscription_override_keeps_saved_address_settings(self):
        saved = {
            "subscription_file": "/data/edge.txt",
            "subscription_url": None,
            "addresses_file": "/data/results.csv",
            "addresses_format": "cloudflare-speedtest-csv",
            "template_index": 3,
            "max_candidates": 40,
        }

        resolved = _merge_cloudflare_source(
            saved, {"subscription_url": "https://edge.example/private/token"}
        )

        self.assertIsNone(resolved["subscription_file"])
        self.assertEqual(resolved["subscription_url"],
                         "https://edge.example/private/token")
        self.assertEqual(resolved["addresses_file"], "/data/results.csv")
        self.assertEqual(resolved["template_index"], 3)
        self.assertEqual(resolved["max_candidates"], 40)

    def test_candidate_limit_can_configure_automatic_source_without_subscription(self):
        resolved = _merge_cloudflare_source(None, {"max_candidates": 25})
        self.assertEqual(resolved["max_candidates"], 25)
        self.assertEqual(resolved["automatic_max_candidates"], 25)

        with self.assertRaisesRegex(ValueError, "需要订阅文件/URL"):
            _merge_cloudflare_source(None, {"addresses_file": "results.csv"})

    def test_saved_subscription_limit_does_not_change_automatic_default(self):
        saved = {
            "subscription_file": "/data/edge.txt",
            "subscription_url": None,
            "addresses_file": None,
            "addresses_format": "addresses",
            "template_index": 1,
            "max_candidates": 100,
        }

        resolved = _merge_cloudflare_source(saved, None)

        self.assertNotIn("automatic_max_candidates", resolved)

    def test_automatic_candidates_join_shared_filter_and_keep_default_limit(self):
        rss_proxy = {"name": "rss", "type": "ss", "server": "1.1.1.1", "port": 443}
        cloudflare_proxy = {
            "name": "CF-01-001-104.16.0.1", "type": "vless", "server": "104.16.0.1",
            "port": 443, "uuid": UUID_ONE, "network": "ws", "tls": True,
            "servername": "cdn.example",
            "ws-opts": {"path": "/edge", "headers": {"Host": "cdn.example"}},
        }

        optimized_inputs = []
        optimized_limits = []

        def fake_optimize(nodes, max_candidates, diagnostics_dir=None):
            optimized_inputs.append(list(nodes))
            optimized_limits.append(max_candidates)
            return [cloudflare_proxy]

        with patch("main.start_proxies", return_value=(None, None)), \
                patch("main.get_subscribe_proxies", return_value=[rss_proxy]), \
                patch("main.get_clash_proxies", return_value=[]), \
                patch("main.get_optimized_cloudflare_proxies",
                      side_effect=fake_optimize), \
                patch("main.test_proxies_async",
                      new=AsyncMock(return_value=[rss_proxy, cloudflare_proxy])), \
                patch("main.test_nodes",
                      side_effect=lambda nodes, *args: nodes):
            result = main("prod", "unused", {"max_candidates": 100, "vpngate": {"enabled": False}})

        self.assertEqual(result, [rss_proxy, cloudflare_proxy])
        self.assertEqual([{k: v for k, v in proxy.items() if not k.startswith("_")}
                          for proxy in optimized_inputs[0]], [rss_proxy])
        self.assertEqual(optimized_inputs[0][0]["_source_ids"], ["rss"])
        self.assertEqual(optimized_limits, [40])


if __name__ == "__main__":
    unittest.main()
