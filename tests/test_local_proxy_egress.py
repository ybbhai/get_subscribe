"""回归测试：本机开着代理客户端时必须仍能采集到数据。

这三条覆盖的都是“端口/代理处理错了就 100% 抓不到数据”的场景：
1. 本机 Clash REST API 请求不能被 HTTP_PROXY 转发（否则内核判定永远失败）；
2. 批量测速的端口不能写死 7890/9090（否则被用户代理占用后全部实例绑定失败）；
3. 直连回退必须找到真实可用出口，而不是“端口开着就算”。
"""
import os
import socket
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import yaml

from utils.clash_manager import ClashMetaManager, find_free_port_block, _local_api_session


def _socket_creation_allowed():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM):
            return True
    except PermissionError:
        return False


class LocalApiSessionTests(unittest.TestCase):
    def test_local_api_session_ignores_proxy_env(self):
        """本机 controller 请求必须绕过 HTTP_PROXY，否则用户开代理时全盘失败。"""
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1",
                                     "HTTPS_PROXY": "http://127.0.0.1:1"}):
            session = _local_api_session()
            try:
                self.assertFalse(session.trust_env)
                self.assertEqual(session.proxies, {})
            finally:
                session.close()

    def test_start_probes_api_without_env_proxy(self):
        manager = ClashMetaManager("base_template.yaml", "test_config.yaml",
                                   controller_port=19090, http_port=19080)
        fake_proc = Mock()
        fake_proc.poll.return_value = None
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.return_value = Mock(status_code=200)

        with patch("utils.clash_manager.subprocess.Popen", return_value=fake_proc), \
                patch("utils.clash_manager.requests.Session", return_value=session), \
                patch("builtins.open", MagicMock()), \
                patch("utils.clash_manager.time.sleep"):
            manager.start(config_path="unused.yaml")

        self.assertFalse(session.trust_env)
        self.assertTrue(session.get.called)


class PortAllocationTests(unittest.TestCase):
    @unittest.skipUnless(_socket_creation_allowed(), "environment forbids socket creation")
    def test_batch_ports_do_not_collide_with_busy_ports(self):
        """7890/9090 被本机代理占用时，必须换到别的端口区间。"""
        blocked = []
        for port in (7890, 7891, 9090):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
                sock.listen(1)
                blocked.append(sock)
            except OSError:
                pass

        try:
            start, end = find_free_port_block(size=2, start=18100, stop=18200)
            self.assertIsNotNone(start)
            self.assertGreaterEqual(start, 18100)
            self.assertLess(end, 18200)
            self.assertNotIn(start, (7890, 7891, 9090))
        finally:
            for sock in blocked:
                sock.close()

    @unittest.skipUnless(_socket_creation_allowed(), "environment forbids socket creation")
    def test_worker_windows_are_disjoint(self):
        """并行 worker 不能抢到同一段端口。"""
        windows = {}
        for worker_id in range(4):
            base = 18300 + worker_id * 20
            start, end = find_free_port_block(size=2, start=base, stop=base + 20)
            self.assertIsNotNone(start)
            windows[worker_id] = (start, end)
        ranges = list(windows.values())
        for index, (start, end) in enumerate(ranges):
            for other_start, other_end in ranges[index + 1:]:
                self.assertTrue(end < other_start or other_end < start)

    def test_batch_nodes_use_allocated_ports(self):
        """_test_batch_nodes 必须把分配到的端口传给 ClashMetaManager。"""
        from utils import utils as utils_module

        manager = MagicMock()
        with patch.object(utils_module, "ClashMetaManager", return_value=manager) as manager_cls, \
                patch.object(utils_module, "find_free_port_block",
                             side_effect=[(18500, 18501), (18510, 18510)]), \
                patch.object(utils_module, "test_node_metrics",
                             return_value={"is_available": False}):
            with tempfile.TemporaryDirectory() as directory:
                result = utils_module._test_batch_nodes(
                    [{"name": "n", "server": "example.com", "port": 443, "type": "ss"}],
                    directory, 5, 0)

        self.assertEqual(result, [])
        kwargs = manager_cls.call_args.kwargs
        self.assertEqual(kwargs["http_port"], 18500)
        self.assertEqual(kwargs["socks_port"], 18501)
        self.assertEqual(kwargs["controller_port"], 18510)


class FallbackProxyTests(unittest.TestCase):
    def setUp(self):
        import main
        main._FALLBACK_PROXY_CACHE = None
        self.main = main

    def tearDown(self):
        self.main._FALLBACK_PROXY_CACHE = None

    def test_reachable_but_broken_proxy_is_rejected(self):
        """端口能连但抓不到数据的候选不能被当成出口。"""
        with patch.object(self.main, "_proxy_reachable", return_value=True), \
                patch.object(self.main, "_proxy_actually_works", return_value=False) as works:
            self.assertIsNone(self.main._detect_fallback_proxy())
        self.assertTrue(works.called)

    def test_proxy_health_rejects_html_instead_of_subscription_data(self):
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.return_value = Mock(
            status_code=200, content=b"<html>verification required</html>" * 20)

        with patch.object(self.main, "_probe_targets", return_value=[self.main.RSS_URL]), \
                patch("main.requests.Session", return_value=session):
            self.assertFalse(self.main._proxy_actually_works("http://proxy.example:8080"))

    def test_proxy_health_accepts_a_real_clash_payload(self):
        session = MagicMock()
        session.__enter__.return_value = session
        payload = (
            b"proxies:\n  - name: node\n    type: ss\n    server: proxy.example\n    port: 443\n"
            + b"# padding\n" * 40
        )
        session.get.return_value = Mock(status_code=200, content=payload)

        with patch.object(self.main, "_probe_targets", return_value=["https://feed.example/config"]), \
                patch("main.requests.Session", return_value=session):
            self.assertTrue(self.main._proxy_actually_works("http://proxy.example:8080"))

    def test_working_proxy_is_selected(self):
        with patch.object(self.main, "_proxy_reachable", return_value=True), \
                patch.object(self.main, "_proxy_actually_works", return_value=True):
            detected = self.main._detect_fallback_proxy()
        self.assertTrue(detected.startswith("http://127.0.0.1:"))

    def test_selected_proxy_credentials_are_redacted_from_logs(self):
        candidate = "http://alice:secret@proxy.example:8080"
        with patch.dict(os.environ, {"HTTPS_PROXY": candidate}, clear=True), \
                patch.object(self.main, "_proxy_reachable", return_value=True), \
                patch.object(self.main, "_proxy_actually_works", return_value=True), \
                self.assertLogs("main", level="INFO") as captured:
            self.assertEqual(self.main._detect_fallback_proxy(), candidate)

        output = "\n".join(captured.output)
        self.assertIn("http://proxy.example:8080", output)
        self.assertNotIn("alice", output)
        self.assertNotIn("secret", output)

    def test_url_redaction_removes_paths_queries_and_userinfo(self):
        self.assertEqual(
            self.main._redact_url("https://alice:secret@feed.example/token/abc?key=def#frag"),
            "https://feed.example",
        )
        self.assertEqual(
            self.main._redact_url("http://alice:secret@[2001:db8::1]:8080/token"),
            "http://[2001:db8::1]:8080",
        )

    def test_malformed_proxy_environment_value_is_skipped(self):
        self.assertFalse(self.main._proxy_reachable("http://[invalid"))

    def test_failed_proxy_credentials_are_redacted_from_debug_logs(self):
        candidate = "http://alice:secret@proxy.example:8080"
        with patch.dict(os.environ, {"HTTPS_PROXY": candidate}, clear=True), \
                patch.object(self.main, "_proxy_reachable", return_value=True), \
                patch.object(self.main, "_proxy_actually_works", return_value=False), \
                self.assertLogs("main", level="DEBUG") as captured:
            self.assertIsNone(self.main._detect_fallback_proxy())

        output = "\n".join(captured.output)
        self.assertNotIn("alice", output)
        self.assertNotIn("secret", output)

    def test_session_uses_detected_proxy(self):
        with patch.object(self.main, "_detect_fallback_proxy",
                          return_value="http://127.0.0.1:7897"):
            session = self.main._subscription_session(False, None)
            try:
                self.assertEqual(session.proxies["https"], "http://127.0.0.1:7897")
                self.assertFalse(session.trust_env)
            finally:
                session.close()

    def test_probe_targets_include_multiple_sources(self):
        """只取 urls.txt 第一条时，源站当天没更新就会假装全部节点不可用。"""
        targets = self.main._probe_targets(limit=3)
        self.assertIn(self.main.RSS_URL, targets)
        self.assertGreaterEqual(len(targets), 2)
        self.assertEqual(len(targets), len(set(targets)))

    def test_probe_targets_spread_across_distinct_hosts(self):
        """相邻配置行常重复同一站点，探测名额应留给独立订阅源。"""
        from urllib.parse import urlsplit

        targets = self.main._probe_targets(limit=3)
        hosts = [urlsplit(url).hostname for url in targets]

        self.assertEqual(len(hosts), len(set(hosts)))
        self.assertIn("raw.githubusercontent.com", hosts)
        self.assertEqual(hosts.count("node.openclash.cc"), 1)


class CollectRoundTests(unittest.TestCase):
    """一轮采集的兜底行为：本地代理抓不到数据时必须退回直连。"""

    def setUp(self):
        import main
        main._FALLBACK_PROXY_CACHE = None
        self.main = main

    def tearDown(self):
        self.main._FALLBACK_PROXY_CACHE = None

    def test_resets_fallback_cache_every_round(self):
        """常驻模式下用户可能中途才开代理，负缓存不能带到下一轮。"""
        self.main._FALLBACK_PROXY_CACHE = ""
        with patch.object(self.main, "start_proxies", return_value=(None, None)), \
                patch.object(self.main, "get_subscribe_proxies", return_value=[]), \
                patch.object(self.main, "get_clash_proxies", return_value=[]), \
                patch.object(self.main, "test_proxies_async",
                             new=AsyncMock(return_value=[])):
            self.main.main("dev", "unused")
        self.assertIsNone(self.main._FALLBACK_PROXY_CACHE)

    def test_retries_directly_when_local_proxy_fetches_nothing(self):
        """经本地代理一个节点都没抓到，必须换直连再试，否则整轮产出为 0。"""
        proc = Mock()
        calls = []

        def fake_rss(use_local_proxy=True, proxy_port=None):
            calls.append(use_local_proxy)
            if use_local_proxy:
                return []
            return [{"name": "direct-node", "type": "ss",
                     "server": "proxy.example.com", "port": 443}]

        with patch.object(self.main, "start_proxies", return_value=(proc, 17500)), \
                patch.object(self.main, "get_subscribe_proxies", side_effect=fake_rss), \
                patch.object(self.main, "get_clash_proxies", return_value=[]), \
                patch.object(self.main, "stop_proxies") as stop, \
                patch.object(self.main, "test_proxies_async",
                             new=AsyncMock(return_value=[{"name": "direct-node"}])), \
                patch.object(self.main, "test_nodes", side_effect=lambda nodes, *a: nodes):
            results = self.main.main("dev", "unused")

        self.assertEqual([p["name"] for p in results], ["direct-node"])
        self.assertEqual(calls, [True, False])
        self.assertGreaterEqual(stop.call_count, 1)

    def test_does_not_retry_when_local_proxy_succeeds(self):
        proc = Mock()
        calls = []

        def fake_rss(use_local_proxy=True, proxy_port=None):
            calls.append(use_local_proxy)
            return [{"name": "via-proxy", "type": "ss",
                     "server": "proxy.example.com", "port": 443}]

        with patch.object(self.main, "start_proxies", return_value=(proc, 17500)), \
                patch.object(self.main, "get_subscribe_proxies", side_effect=fake_rss), \
                patch.object(self.main, "get_clash_proxies", return_value=[]), \
                patch.object(self.main, "stop_proxies"), \
                patch.object(self.main, "test_proxies_async",
                             new=AsyncMock(return_value=[{"name": "via-proxy"}])), \
                patch.object(self.main, "test_nodes", side_effect=lambda nodes, *a: nodes):
            results = self.main.main("dev", "unused")

        self.assertEqual([p["name"] for p in results], ["via-proxy"])
        self.assertEqual(calls, [True])


if __name__ == "__main__":
    unittest.main()
