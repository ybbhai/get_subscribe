import os
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

import yaml
import requests

from main import (
    BOOTSTRAP_MAX_PROBE_NODES,
    BOOTSTRAP_NODE_BUDGET_SECONDS,
    GENERATED_PROXY_CONFIG,
    acquire_instance_lock,
    _check_bootstrap_proxy,
    _filter_bootstrap_nodes,
    _probe_subscription_via_proxy,
    _write_bootstrap_config,
    main,
    start_proxies,
)


class BootstrapProxyTests(unittest.TestCase):
    def _openvpn_bootstrap(self, probe_outcome, *, max_wait_seconds=None, node_type="openvpn"):
        clock = {"now": 100.0, "sleeps": [], "timeouts": []}
        process = Mock()
        process.poll.return_value = None
        api_session = MagicMock()
        api_session.__enter__.return_value = api_session
        api_session.get.return_value.json.return_value = {"now": "vpn"}

        def probe(port, urls, timeout):
            self.assertEqual(port, 17000)
            self.assertEqual(urls, ["https://rss.example"])
            clock["timeouts"].append(timeout)
            return probe_outcome(clock, timeout)

        def sleep(seconds):
            clock["sleeps"].append(seconds)
            clock["now"] += seconds

        with patch("main.requests.Session", return_value=api_session), \
                patch("main._probe_targets", return_value=["https://rss.example"]), \
                patch("main.time.monotonic", side_effect=lambda: clock["now"]), \
                patch("main.time.sleep", side_effect=sleep), \
                patch("main._probe_subscription_via_proxy", side_effect=probe):
            ready = _check_bootstrap_proxy(process, 17000, "SUBSCRIPTION", ["vpn"],
                                           max_wait_seconds=max_wait_seconds,
                                           node_types={"vpn": node_type})
        return ready, clock, api_session

    def test_openvpn_bootstrap_retries_same_node_until_handshake_is_ready(self):
        def probe(clock, timeout):
            clock["now"] += min(5, timeout)
            return clock["now"] >= 130, "subscription verdict"

        ready, clock, api = self._openvpn_bootstrap(probe)

        self.assertTrue(ready)
        self.assertGreater(clock["now"], 124)
        self.assertLessEqual(clock["now"], 135)
        self.assertEqual(len(clock["timeouts"]), 6)
        self.assertEqual(api.put.call_count, 1)
        self.assertEqual(api.put.call_args.kwargs["json"], {"name": "vpn"})
        self.assertTrue(all(0 < timeout <= 24 for timeout in clock["timeouts"]))

    def test_openvpn_bootstrap_stops_at_shared_budget(self):
        def probe(clock, timeout):
            clock["now"] += min(5, timeout)
            return False, "dial failed"

        ready, clock, api = self._openvpn_bootstrap(probe)

        self.assertFalse(ready)
        self.assertEqual(clock["now"], 135)
        self.assertEqual(len(clock["timeouts"]), 7)
        self.assertEqual(clock["timeouts"][-1], 3.5)
        self.assertEqual(api.put.call_count, 1)

    def test_openvpn_bootstrap_global_deadline_caps_node_budget(self):
        def probe(clock, timeout):
            clock["now"] += min(5, timeout)
            return False, "dial failed"

        ready, clock, _ = self._openvpn_bootstrap(probe, max_wait_seconds=10)

        self.assertFalse(ready)
        self.assertEqual(clock["now"], 110)
        self.assertEqual(clock["timeouts"], [10, 4.75])

    def test_openvpn_bootstrap_immediate_errors_back_off(self):
        ready, clock, _ = self._openvpn_bootstrap(lambda clock, timeout: (False, "HTTP 502"))

        self.assertFalse(ready)
        self.assertEqual(clock["now"], 135)
        self.assertEqual(len(clock["timeouts"]), 140)
        self.assertTrue(all(0 < delay <= 0.25 for delay in clock["sleeps"]))

    def test_ordinary_bootstrap_keeps_one_probe_without_retry(self):
        ready, clock, _ = self._openvpn_bootstrap(lambda clock, timeout: (False, "HTTP 502"),
                                                 node_type="vless")
        self.assertFalse(ready)
        self.assertEqual(clock["timeouts"], [BOOTSTRAP_NODE_BUDGET_SECONDS])
        self.assertEqual(clock["sleeps"], [])

    def test_start_proxies_passes_types_from_prepared_runtime_config(self):
        with tempfile.TemporaryDirectory() as directory:
            clash_dir = os.path.join(directory, "clash")
            os.mkdir(clash_dir)
            executable = os.path.join(clash_dir, "test-core")
            with open(executable, "w", encoding="utf-8") as stream:
                stream.write("unused mocked core")
            with open(os.path.join(clash_dir, GENERATED_PROXY_CONFIG), "w", encoding="utf-8") as stream:
                yaml.safe_dump({"proxies": [
                    {"name": "vpn", "type": "openvpn", "server": "vpn.example", "port": 1194},
                    {"name": "edge", "type": "vless", "server": "edge.example", "port": 443},
                ]}, stream)
            process = Mock()
            with patch("main.__file__", os.path.join(directory, "main.py")), \
                    patch("main.resolve_mihomo_executable", return_value=executable), \
                    patch("main.find_free_port_block", side_effect=[(17000, 17000), (17700, 17700)]), \
                    patch("main._launch_clash", return_value=(process, 17000, 17700)), \
                    patch("main._check_bootstrap_proxy", return_value=True) as check:
                result = start_proxies()

        self.assertEqual(result, (process, 17000))
        self.assertEqual(check.call_args.kwargs["node_types"], {"vpn": "openvpn", "edge": "vless"})

    def test_instance_lock_rejects_second_holder_and_releases_on_close(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = os.path.join(directory, "main.lock")
            first = acquire_instance_lock(lock_path)
            self.assertIsNotNone(first)
            try:
                self.assertIsNone(acquire_instance_lock(lock_path))
            finally:
                first.close()

            third = acquire_instance_lock(lock_path)
            self.assertIsNotNone(third)
            third.close()

    def test_bootstrap_check_uses_real_subscription_fetch_as_verdict(self):
        """判定依据必须是真实抓订阅源，而不是 gstatic 204 探针。"""
        process = Mock()
        process.poll.return_value = None
        api_session = MagicMock()
        api_session.__enter__.return_value = api_session
        api_session.put.return_value = Mock(status_code=204)
        nodes = ["node-bad", "node-good"]
        group_url = "http://127.0.0.1:9099/proxies/SUBSCRIPTION"
        api_session.get.side_effect = [
            Mock(**{"json.return_value": {"now": name}}) for name in nodes
        ]
        verdicts = [(False, "HTTP 502"), (True, "HTTP 200 / 4096 字节")]
        probe = Mock(side_effect=verdicts)

        with patch("main.requests.Session", return_value=api_session), \
                patch("main._probe_targets", return_value=["https://rss.example"]), \
                patch("main._probe_subscription_via_proxy", probe):
            ready = _check_bootstrap_proxy(process, 7890, "SUBSCRIPTION", nodes)

        self.assertTrue(ready)
        self.assertEqual(probe.call_count, 2)
        for call in probe.call_args_list:
            self.assertEqual(call.args[0], 7890)
            self.assertEqual(call.args[1], ["https://rss.example"])
        self.assertEqual(api_session.put.call_count, 2)
        self.assertEqual(api_session.put.call_args.kwargs["json"], {"name": "node-good"})
        for call in api_session.put.call_args_list:
            self.assertEqual(call.args[0], group_url)

    def test_bootstrap_check_honors_controller_port(self):
        process = Mock()
        process.poll.return_value = None
        api_session = MagicMock()
        api_session.__enter__.return_value = api_session
        api_session.get.return_value.json.return_value = {"now": "node-ok"}

        with patch("main.requests.Session", return_value=api_session), \
                patch("main._probe_targets", return_value=["https://rss.example"]), \
                patch("main._probe_subscription_via_proxy",
                      return_value=(True, "HTTP 200")):
            ready = _check_bootstrap_proxy(process, 17000, "SUBSCRIPTION",
                                           ["node-ok"], controller_port=17102)

        self.assertTrue(ready)
        self.assertEqual(api_session.put.call_args.args[0],
                         "http://127.0.0.1:17102/proxies/SUBSCRIPTION")

    def test_bootstrap_check_does_not_probe_unconfirmed_switch(self):
        process = Mock()
        process.poll.return_value = None
        api_session = MagicMock()
        api_session.__enter__.return_value = api_session
        api_session.get.return_value.json.return_value = {"now": "other-node"}
        probe = Mock(return_value=(True, "HTTP 200"))

        with patch("main.requests.Session", return_value=api_session), \
                patch("main._probe_targets", return_value=["https://rss.example"]), \
                patch("main._probe_subscription_via_proxy", probe):
            ready = _check_bootstrap_proxy(process, 7890, "SUBSCRIPTION", ["node-bad"])

        self.assertFalse(ready)
        probe.assert_not_called()

    def test_probe_rejects_short_or_error_response(self):
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.return_value = Mock(status_code=204, content=b"\x00" * 8)

        with patch("main.requests.Session", return_value=session):
            ok, detail = _probe_subscription_via_proxy(
                7890, ["https://example.com/sub"])

        self.assertFalse(ok)
        self.assertIn("响应过短", detail)
        self.assertEqual(session.proxies,
                         {"http": "http://127.0.0.1:7890",
                          "https": "http://127.0.0.1:7890"})
        self.assertFalse(session.trust_env)

    def test_probe_shares_node_budget_across_all_targets(self):
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.side_effect = requests.exceptions.ConnectTimeout
        urls = [f"https://source-{index}.example/config" for index in range(4)]

        with patch("main.requests.Session", return_value=session), \
                patch("main.time.monotonic", return_value=100):
            ok, _ = _probe_subscription_via_proxy(7890, urls)

        self.assertFalse(ok)
        self.assertEqual(session.get.call_count, len(urls))
        self.assertEqual([call.kwargs["timeout"] for call in session.get.call_args_list],
                         [BOOTSTRAP_NODE_BUDGET_SECONDS / len(urls)] * len(urls))

    def test_probe_accepts_real_payload(self):
        session = MagicMock()
        session.__enter__.return_value = session
        payload = (
            b"proxies:\n  - name: node\n    type: ss\n    server: proxy.example\n    port: 443\n"
            + b"# padding\n" * 40
        )
        session.get.return_value = Mock(status_code=200, content=payload)

        with patch("main.requests.Session", return_value=session):
            ok, detail = _probe_subscription_via_proxy(
                7890, ["https://example.com/sub"])

        self.assertTrue(ok)
        self.assertIn("200", detail)

    def test_probe_rejects_html_challenge(self):
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.return_value = Mock(
            status_code=200, content=b"<html>verification required</html>" * 20)

        with patch("main.requests.Session", return_value=session):
            ok, detail = _probe_subscription_via_proxy(
                7890, ["https://example.com/sub"])

        self.assertFalse(ok)
        self.assertIn("不是可识别的订阅数据", detail)

    def test_probe_limits_probed_nodes(self):
        process = Mock()
        process.poll.return_value = None
        api_session = MagicMock()
        api_session.__enter__.return_value = api_session
        # 切换后 API 必须回显被切换的节点名，否则会被判成“未切换”而跳过探测
        state = {"now": None}
        api_session.put.side_effect = lambda _url, json=None, **_: (
            state.update({"now": json["name"]}) or Mock(status_code=204))
        api_session.get.side_effect = lambda *args, **kwargs: Mock(
            **{"json.return_value": {"now": state["now"]}})
        probe = Mock(return_value=(False, "HTTP 502"))
        nodes = [f"node-{index}" for index in range(BOOTSTRAP_MAX_PROBE_NODES + 5)]

        with patch("main.requests.Session", return_value=api_session), \
                patch("main._probe_targets", return_value=["https://rss.example"]), \
                patch("main._probe_subscription_via_proxy", probe):
            ready = _check_bootstrap_proxy(process, 7890, "SUBSCRIPTION", nodes)

        self.assertFalse(ready)
        self.assertEqual(probe.call_count, BOOTSTRAP_MAX_PROBE_NODES)

    def test_main_fetches_directly_without_ready_proxy(self):
        with patch("main.start_proxies", return_value=(None, None)), \
                patch("main.get_subscribe_proxies", return_value=[]) as get_rss, \
                patch("main.get_clash_proxies", return_value=[]) as get_clash:
            self.assertEqual(main("dev", "unused"), [])

        get_rss.assert_called_once_with(use_local_proxy=False, proxy_port=None)
        get_clash.assert_called_once_with(use_local_proxy=False, proxy_port=None)

    def test_filter_rejects_loopback_and_keeps_remote_nodes(self):
        nodes = [
            {"name": "loopback-ip", "server": "127.0.0.1", "port": 10000},
            {"name": "loopback-name", "server": "localhost", "port": 10000},
            {"name": "remote", "server": "proxy.example.com", "port": 443},
        ]

        self.assertEqual(_filter_bootstrap_nodes(nodes), [nodes[-1]])

    def test_bootstrap_config_contains_only_filtered_nodes(self):
        nodes = [
            {"name": "local", "type": "ss", "server": "127.0.0.1", "port": 10000},
            {"name": "remote", "type": "ss", "server": "proxy.example.com", "port": 443},
        ]
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.yaml")
            output_path = os.path.join(directory, "bootstrap.yaml")
            with open(source_path, "w", encoding="utf-8") as source:
                yaml.safe_dump({"proxies": nodes}, source)

            _write_bootstrap_config(source_path, output_path)

            with open(output_path, encoding="utf-8") as output:
                config = yaml.safe_load(output)

        self.assertEqual([node["name"] for node in config["proxies"]], ["remote"])
        self.assertEqual(config["proxy-groups"][0]["proxies"], ["remote"])
        self.assertEqual(config["proxy-groups"][0]["type"], "select")

    def test_empty_fallback_is_not_a_proxy_config(self):
        """proxy.yaml 里没有节点时，不能拿它启动采集代理。"""
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "proxy.yaml")
            with open(path, "w", encoding="utf-8") as config_file:
                yaml.safe_dump({"proxies": [], "rules": ["MATCH,DIRECT"]}, config_file)

            self.assertEqual(_filter_bootstrap_nodes([]), [])
            with self.assertRaises(ValueError):
                _write_bootstrap_config(path, os.path.join(directory, "out.yaml"))


if __name__ == "__main__":
    unittest.main()
