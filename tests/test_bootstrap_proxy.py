import os
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

import yaml

from main import (
    acquire_instance_lock,
    _check_bootstrap_proxy,
    _config_has_proxy_nodes,
    _filter_bootstrap_nodes,
    _write_bootstrap_config,
    main,
)


class BootstrapProxyTests(unittest.TestCase):
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

    def test_bootstrap_check_skips_bad_node_and_switches_to_available_node(self):
        process = Mock()
        process.poll.return_value = None
        api_session = MagicMock()
        api_session.__enter__.return_value = api_session
        bad_delay = Mock(status_code=503)
        good_delay = Mock(status_code=200)
        good_delay.json.return_value = {"delay": 145}
        selected_group = Mock(status_code=200)
        selected_group.json.return_value = {"now": "node-good"}
        api_session.get.side_effect = [bad_delay, good_delay, selected_group]
        api_session.put.return_value = Mock(status_code=204)
        proxy_session = MagicMock()
        proxy_session.__enter__.return_value = proxy_session
        proxy_response = Mock(status_code=204)
        proxy_session.get.return_value.__enter__ = Mock(return_value=proxy_response)
        proxy_session.get.return_value.__exit__ = Mock(return_value=False)

        with patch("main.requests.Session", return_value=api_session), \
                patch("main._subscription_session", return_value=proxy_session):
            ready = _check_bootstrap_proxy(
                process, 7890, "SUBSCRIPTION", ["node-bad", "node-good"])

        self.assertTrue(ready)
        self.assertEqual(api_session.put.call_args.kwargs["json"], {"name": "node-good"})
        self.assertEqual(proxy_session.get.call_count, 1)

    def test_bootstrap_check_rejects_all_nodes_without_outbound_probe(self):
        process = Mock()
        process.poll.return_value = None
        api_session = MagicMock()
        api_session.__enter__.return_value = api_session
        api_session.get.return_value = Mock(status_code=503)
        proxy_session = MagicMock()
        proxy_session.__enter__.return_value = proxy_session

        with patch("main.requests.Session", return_value=api_session), \
                patch("main._subscription_session", return_value=proxy_session):
            ready = _check_bootstrap_proxy(process, 7890, "SUBSCRIPTION", ["node-bad"])

        self.assertFalse(ready)
        proxy_session.get.assert_not_called()

    def test_main_does_not_fetch_subscriptions_without_ready_proxy(self):
        with patch("main.start_proxies", return_value=(None, None)), \
                patch("main.get_subscribe_proxies") as get_rss, \
                patch("main.get_clash_proxies") as get_clash:
            self.assertEqual(main("dev", "unused"), [])

        get_rss.assert_not_called()
        get_clash.assert_not_called()

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
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "proxy.yaml")
            with open(path, "w", encoding="utf-8") as config_file:
                yaml.safe_dump({"proxies": [], "rules": ["MATCH,DIRECT"]}, config_file)

            self.assertFalse(_config_has_proxy_nodes(path))


if __name__ == "__main__":
    unittest.main()