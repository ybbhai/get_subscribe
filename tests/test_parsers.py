"""节点解析、去重与排序的离线回归测试。

这些行为曾经出现过静默降级（节点能生成配置但拨号失败、或字段在去重时被抹掉），
单靠"配置校验通过"发现不了，因此这里用纯离线用例把关键字段固定下来。
"""

import base64
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

from main import RSS_URL, _extract_subscription_urls, _get_rss_proxies, get_clash_proxies
from utils.utils import (
    b64_decode_text,
    decode_hysteria2,
    decode_ss,
    decode_vless,
    decode_vmess,
    filter_proxies,
    sort_proxies_by_performance,
    v2ray_2_clash,
)


def urlsafe_b64(text):
    """生成不带 padding 的 urlsafe base64，模拟真实订阅里的写法。"""
    raw = base64.urlsafe_b64encode(text.encode()).decode()
    return raw.rstrip("=")


class RSSSubscriptionTests(unittest.TestCase):
    def test_extracts_current_clash_and_v2ray_anchor_links(self):
        summary = (
            '<a href="https://nodebuf.example/token/mihomo">Clash 订阅链接</a>'
            '<a href="https://nodebuf.example/token/singbox">Sing-box 订阅链接</a>'
            '<a href="https://nodebuf.example/token/v2ray">V2Ray 订阅链接</a>'
        )
        self.assertEqual(_extract_subscription_urls(summary), {
            "clash": "https://nodebuf.example/token/mihomo",
            "v2ray": "https://nodebuf.example/token/v2ray",
        })

    def test_keeps_legacy_text_summary_links(self):
        summary = (
            "<span>V2Ray/XRay -&gt; https://example.com/v2ray?token=1&amp;x=2</span>"
            "<span>clash -&gt; https://example.com/clash.yaml</span>"
        )
        self.assertEqual(_extract_subscription_urls(summary), {
            "v2ray": "https://example.com/v2ray?token=1&x=2",
            "clash": "https://example.com/clash.yaml",
        })

    def test_current_rss_clash_link_downloads_proxy_yaml(self):
        subscription_url = "https://nodebuf.example/token/mihomo"
        summary = f'<a href="{subscription_url}">Clash 订阅链接</a>'
        rss_response = Mock()
        rss_response.__enter__ = Mock(return_value=rss_response)
        rss_response.__exit__ = Mock(return_value=False)
        rss_response.content = b"<rss>fixture</rss>"
        rss_response.raise_for_status = Mock()

        clash_response = Mock(
            status_code=200,
            content=b"proxies:\n  - name: node-a\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n",
        )
        session = Mock()
        session.get.side_effect = [rss_response, clash_response]

        with patch("main.feedparser.parse", return_value=SimpleNamespace(
                entries=[{"summary": summary}])):
            proxies = _get_rss_proxies(session)

        self.assertEqual(session.get.call_args_list[0].args[0], RSS_URL)
        self.assertEqual(session.get.call_args_list[1].args[0], subscription_url)
        self.assertEqual(proxies, [{
            "name": "node-a", "type": "ss", "server": "1.2.3.4", "port": 8388,
        }])

    def test_reads_content_encoded_links_and_falls_back_to_older_rss_entry(self):
        older_summary = '<a href="https://feed.example/v2ray">V2Ray subscription</a>'
        rss_response = Mock()
        rss_response.__enter__ = Mock(return_value=rss_response)
        rss_response.__exit__ = Mock(return_value=False)
        rss_response.content = b"<rss>fixture</rss>"
        rss_response.raise_for_status = Mock()
        subscription_response = Mock(
            status_code=200,
            text=base64.b64encode(
                b"ss://aes-128-gcm:secret@1.2.3.4:443#node"
            ).decode(),
        )
        session = Mock()
        session.get.side_effect = [rss_response, subscription_response]

        with patch("main.feedparser.parse", return_value=SimpleNamespace(entries=[
                {"summary": ""},
                {"summary": "", "content": [{"value": older_summary}]},
        ])):
            proxies = _get_rss_proxies(session)

        self.assertEqual(session.get.call_args_list[1].args[0], "https://feed.example/v2ray")
        self.assertEqual([proxy["name"] for proxy in proxies], ["node"])

    def test_rss_clash_parser_uses_special_format_fallback(self):
        summary = '<a href="https://feed.example/clash">Clash subscription</a>'
        rss_response = Mock()
        rss_response.__enter__ = Mock(return_value=rss_response)
        rss_response.__exit__ = Mock(return_value=False)
        rss_response.content = b"<rss>fixture</rss>"
        rss_response.raise_for_status = Mock()
        clash_response = Mock(status_code=200, content=b"proxies: [malformed")
        session = Mock()
        session.get.side_effect = [rss_response, clash_response]
        parsed_nodes = [{"name": "recovered", "type": "ss", "server": "1.2.3.4", "port": 443}]

        with patch("main.feedparser.parse", return_value=SimpleNamespace(
                entries=[{"summary": summary}])), \
                patch("main.parse_special_clash", return_value=parsed_nodes):
            proxies = _get_rss_proxies(session)

        self.assertEqual(proxies, parsed_nodes)

    def test_invalid_clash_proxy_list_keeps_v2ray_results(self):
        summary = (
            '<a href="https://nodebuf.example/v2ray">V2Ray 订阅链接</a>'
            '<a href="https://nodebuf.example/clash">Clash 订阅链接</a>'
        )
        rss_response = Mock()
        rss_response.__enter__ = Mock(return_value=rss_response)
        rss_response.__exit__ = Mock(return_value=False)
        rss_response.content = b"<rss>fixture</rss>"
        rss_response.raise_for_status = Mock()
        v2ray_response = Mock(status_code=200, text="fixture")
        clash_response = Mock(status_code=200, content=b"proxies: null\n")
        session = Mock()
        session.get.side_effect = [rss_response, v2ray_response, clash_response]
        v2ray_nodes = [{"name": "v2ray-node", "type": "ss", "server": "1.2.3.4", "port": 443}]

        with patch("main.feedparser.parse", return_value=SimpleNamespace(
                entries=[{"summary": summary}])), \
                patch("main.v2ray_2_clash", return_value=v2ray_nodes):
            proxies = _get_rss_proxies(session)

        self.assertEqual(proxies, v2ray_nodes)


class ClashSubscriptionSourceTests(unittest.TestCase):
    def test_bad_url_template_does_not_skip_later_sources(self):
        response = Mock(
            status_code=200,
            content=b"proxies:\n  - name: node\n    type: ss\n    server: 1.2.3.4\n    port: 443\n",
            headers={},
        )
        session = Mock()
        session.get.return_value = response

        with patch("main.load_urls", return_value=[
                "https://invalid.example/{broken",
                "https://valid.example/{stamp}.yaml",
        ]), patch("main.requests.Session", return_value=session):
            proxies = get_clash_proxies(use_local_proxy=False)

        self.assertEqual([proxy["name"] for proxy in proxies], ["node"])
        self.assertEqual(session.get.call_args.args[0].split("/")[2], "valid.example")

    def test_request_failure_does_not_log_url_path_token(self):
        secret_url = "https://feed.example/private/TOKEN?key=SECRET"
        session = Mock()
        session.get.side_effect = requests.exceptions.ConnectionError(
            f"request failed: {secret_url}")

        with patch("main.load_urls", return_value=[secret_url]), \
                patch("main._subscription_session", return_value=session), \
                self.assertLogs("main", level="WARNING") as captured:
            self.assertEqual(get_clash_proxies(use_local_proxy=False), [])

        output = "\n".join(captured.output)
        self.assertIn("https://feed.example", output)
        self.assertNotIn("TOKEN", output)
        self.assertNotIn("SECRET", output)

    def test_invalid_clash_encoding_keeps_v2ray_results(self):
        summary = (
            '<a href="https://nodebuf.example/v2ray">V2Ray 订阅链接</a>'
            '<a href="https://nodebuf.example/clash">Clash 订阅链接</a>'
        )
        rss_response = Mock()
        rss_response.__enter__ = Mock(return_value=rss_response)
        rss_response.__exit__ = Mock(return_value=False)
        rss_response.content = b"<rss>fixture</rss>"
        rss_response.raise_for_status = Mock()
        session = Mock()
        session.get.side_effect = [
            rss_response,
            Mock(status_code=200, text="fixture"),
            Mock(status_code=200, content=b"proxies: \xff"),
        ]
        v2ray_nodes = [{"name": "v2ray-node", "type": "ss", "server": "1.2.3.4", "port": 443}]

        with patch("main.feedparser.parse", return_value=SimpleNamespace(
                entries=[{"summary": summary}])), \
                patch("main.v2ray_2_clash", return_value=v2ray_nodes):
            proxies = _get_rss_proxies(session)

        self.assertEqual(proxies, v2ray_nodes)

    def test_request_failure_does_not_log_subscription_token(self):
        secret_url = "https://feed.example/private/TOKEN?key=SECRET"
        summary = f'<a href="{secret_url}">V2Ray subscription</a>'
        rss_response = Mock()
        rss_response.__enter__ = Mock(return_value=rss_response)
        rss_response.__exit__ = Mock(return_value=False)
        rss_response.content = b"<rss>fixture</rss>"
        rss_response.raise_for_status = Mock()
        session = Mock()
        session.get.side_effect = [
            rss_response,
            requests.exceptions.ConnectionError(f"request failed: {secret_url}"),
        ]

        with patch("main.feedparser.parse", return_value=SimpleNamespace(
                entries=[{"summary": summary}])), \
                patch("main.write_log"), \
                self.assertLogs("main", level="ERROR") as captured:
            self.assertEqual(_get_rss_proxies(session), [])

        output = "\n".join(captured.output)
        self.assertIn("https://feed.example", output)
        self.assertNotIn("TOKEN", output)
        self.assertNotIn("SECRET", output)


class Base64Tests(unittest.TestCase):
    def test_standard_padding(self):
        self.assertEqual(b64_decode_text("aGVsbG8="), "hello")

    def test_missing_padding(self):
        # "helloworld" 的标准 base64 带 padding，去掉后仍应能解码
        encoded = base64.b64encode(b"helloworld").decode()
        self.assertTrue(encoded.endswith("="))
        self.assertEqual(b64_decode_text(encoded.rstrip("=")), "helloworld")

    def test_urlsafe_alphabet(self):
        payload = "vmess://????>>>>"
        self.assertEqual(b64_decode_text(urlsafe_b64(payload)), payload)

    def test_embedded_newlines(self):
        self.assertEqual(b64_decode_text("aGVs\nbG8=\n"), "hello")

    def test_invalid_input(self):
        self.assertIsNone(b64_decode_text(""))
        self.assertIsNone(b64_decode_text("!!!not-base64!!!"))

    def test_decode_failure_does_not_log_encoded_credentials(self):
        with self.assertLogs("utils.utils", level="DEBUG") as captured:
            self.assertIsNone(b64_decode_text("SECRET_TOKEN!!!"))
        self.assertNotIn("SECRET_TOKEN", "\n".join(captured.output))


class ShadowsocksTests(unittest.TestCase):
    def test_legacy_padded_link(self):
        userinfo = base64.b64encode(b"aes-128-gcm:pass").decode()
        node = decode_ss(f"ss://{userinfo}@1.2.3.4:8388#legacy")
        self.assertEqual(node["cipher"], "aes-128-gcm")
        self.assertEqual(node["password"], "pass")
        self.assertEqual(node["server"], "1.2.3.4")
        self.assertEqual(node["port"], 8388)

    def test_sip002_with_obfs_plugin(self):
        userinfo = urlsafe_b64("aes-256-gcm:secret")
        link = (
            f"ss://{userinfo}@5.6.7.8:8389"
            "?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#sip002"
        )
        node = decode_ss(link)
        self.assertEqual(node["cipher"], "aes-256-gcm")
        self.assertEqual(node["password"], "secret")
        self.assertEqual(node["plugin"], "obfs")
        self.assertEqual(node["plugin-opts"], {"mode": "http", "host": "bing.com"})

    def test_sip002_plain_userinfo(self):
        node = decode_ss("ss://chacha20-ietf-poly1305:pw@9.9.9.9:443#plain")
        self.assertEqual(node["cipher"], "chacha20-ietf-poly1305")
        self.assertEqual(node["password"], "pw")

    def test_ipv6_host_is_unwrapped(self):
        userinfo = urlsafe_b64("aes-128-gcm:pw")
        node = decode_ss(f"ss://{userinfo}@[2001:db8::1]:8388#v6")
        self.assertEqual(node["server"], "2001:db8::1")

    def test_sip002_password_containing_at_sign(self):
        # 真实订阅里存在 password 以 "@@" 结尾的节点。userinfo 解码后若再拼回
        # "@host:port" 并用 split("@", 1) 拆分，server 会变成 "@@1.2.3.4"，
        # 内核拨号时直接失败，表现为"节点不可用"。
        userinfo = urlsafe_b64("aes-256-cfb:qwerREWQ@@")
        node = decode_ss(f"ss://{userinfo}@168.126.234.247:51978#kr")
        self.assertEqual(node["server"], "168.126.234.247")
        self.assertEqual(node["port"], 51978)
        self.assertEqual(node["password"], "qwerREWQ@@")

    def test_legacy_password_containing_at_sign(self):
        userinfo = base64.b64encode(b"aes-256-cfb:qwerREWQ@@@1.2.3.4:8388").decode()
        node = decode_ss(f"ss://{userinfo}#legacy-at")
        self.assertEqual(node["server"], "1.2.3.4")
        self.assertEqual(node["port"], 8388)
        self.assertEqual(node["password"], "qwerREWQ@@")


class VlessTests(unittest.TestCase):
    def test_reality_keeps_utls_fingerprint(self):
        link = (
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
            "?encryption=none&security=reality&sni=www.microsoft.com"
            "&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
            "&sid=1234&flow=xtls-rprx-vision&type=tcp#reality"
        )
        node = decode_vless(link)
        # REALITY 依赖 uTLS：缺 client-fingerprint 时内核能过配置校验但拨号必失败
        self.assertEqual(node["client-fingerprint"], "chrome")
        self.assertTrue(node["tls"])
        self.assertEqual(node["servername"], "www.microsoft.com")
        self.assertEqual(node["flow"], "xtls-rprx-vision")
        self.assertEqual(node["reality-opts"]["short-id"], "1234")
        self.assertIn("public-key", node["reality-opts"])

    def test_ws_tls_keeps_alpn_and_headers(self):
        link = (
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
            "?security=tls&type=ws&host=cdn.example.com&path=%2Fws"
            "&fp=safari&alpn=h2%2Chttp%2F1.1#ws"
        )
        node = decode_vless(link)
        self.assertEqual(node["client-fingerprint"], "safari")
        self.assertEqual(node["alpn"], ["h2", "http/1.1"])
        self.assertEqual(node["ws-opts"]["path"], "/ws")
        self.assertEqual(node["ws-opts"]["headers"]["Host"], "cdn.example.com")

    def test_grpc_service_name(self):
        link = (
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
            "?security=tls&type=grpc&serviceName=gsvc#grpc"
        )
        node = decode_vless(link)
        self.assertEqual(node["grpc-opts"]["grpc-service-name"], "gsvc")

    def test_plaintext_has_no_tls_fields(self):
        link = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:80?type=tcp#plain"
        node = decode_vless(link)
        self.assertFalse(node["tls"])
        self.assertNotIn("client-fingerprint", node)
        self.assertNotIn("flow", node)

    def test_missing_port_returns_none(self):
        self.assertIsNone(decode_vless("vless://uuid@example.com?security=tls"))


class VmessTests(unittest.TestCase):
    def test_grpc_and_servername(self):
        payload = (
            '{"v":"2","ps":"vm","add":"1.2.3.4","port":"443","id":"uuid-1",'
            '"aid":"0","net":"grpc","path":"gsvc","tls":"tls",'
            '"host":"c.com","sni":"","alpn":"h2,http/1.1"}'
        )
        node = decode_vmess("vmess://" + urlsafe_b64(payload))
        self.assertEqual(node["servername"], "c.com")
        self.assertEqual(node["alpn"], ["h2", "http/1.1"])
        self.assertEqual(node["grpc-opts"]["grpc-service-name"], "gsvc")


class V2raySubscriptionTests(unittest.TestCase):
    def test_parses_plain_text_uri_list(self):
        content = (
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls#vless\n"
            "ss://aes-128-gcm:secret@5.6.7.8:8388#ss\n"
        )

        nodes = v2ray_2_clash(content=content)

        self.assertEqual([node["type"] for node in nodes], ["vless", "ss"])

    def test_parses_base64_uri_list(self):
        content = "ss://aes-128-gcm:secret@5.6.7.8:8388#ss\n"

        nodes = v2ray_2_clash(content=base64.b64encode(content.encode()).decode())

        self.assertEqual([node["name"] for node in nodes], ["ss"])

    def test_decodes_percent_encoded_hysteria2_password(self):
        node = decode_hysteria2("hysteria2://password%3Awith%40symbols@example.com:443#hy2")

        self.assertEqual(node["password"], "password:with@symbols")


class FilterTests(unittest.TestCase):
    def test_different_password_not_collapsed(self):
        nodes = [
            {"name": "a", "type": "ss", "server": "1.1.1.1", "port": 443,
             "cipher": "aes-128-gcm", "password": "p1"},
            {"name": "b", "type": "ss", "server": "1.1.1.1", "port": 443,
             "cipher": "aes-128-gcm", "password": "p2"},
        ]
        self.assertEqual(len(filter_proxies(nodes)), 2)

    def test_different_network_not_collapsed(self):
        base = {"type": "vless", "server": "1.1.1.1", "port": 443, "uuid": "u"}
        nodes = [
            dict(base, name="a", network="tcp"),
            dict(base, name="b", network="ws"),
        ]
        self.assertEqual(len(filter_proxies(nodes)), 2)

    def test_exact_duplicates_collapsed(self):
        node = {"name": "a", "type": "ss", "server": "1.1.1.1", "port": 443,
                "cipher": "aes-128-gcm", "password": "p"}
        self.assertEqual(len(filter_proxies([dict(node), dict(node)])), 1)

    def test_missing_required_field_dropped(self):
        nodes = [{"name": "bad", "type": "ss", "port": 443}]
        self.assertEqual(filter_proxies(nodes), [])

    def test_port_is_range_checked_and_numeric_strings_are_normalized(self):
        base = {"name": "node", "type": "ss", "server": "proxy.example",
                "cipher": "aes-128-gcm", "password": "secret"}
        valid = dict(base, port="443")
        invalid = [dict(base, port=0), dict(base, port=65536), dict(base, port=True),
                   dict(base, port="not-a-port"), dict(base, port="9" * 5000)]

        self.assertEqual(filter_proxies([*invalid, valid])[0]["port"], 443)
        self.assertEqual(filter_proxies(invalid), [])

    def test_malformed_entries_do_not_discard_valid_nodes(self):
        valid = {"name": "good", "type": "ss", "server": "1.2.3.4", "port": 443,
                 "cipher": "aes-128-gcm", "password": "secret"}
        self.assertEqual(filter_proxies([None, "invalid", valid]), [valid])

    def test_undialable_server_dropped(self):
        # 真实订阅里出现过 server 为 "@@168.126.234.247" 的脏节点：YAML 校验能过，
        # 但内核拨号时 DNS 解析必然失败，表现为"分组里的节点无法使用"。
        nodes = [
            {"name": "dirty", "type": "ss", "server": "@@168.126.234.247",
             "port": 51978, "cipher": "aes-256-cfb", "password": "p"},
            {"name": "good", "type": "ss", "server": "168.126.234.247",
             "port": 51978, "cipher": "aes-256-cfb", "password": "p"},
        ]
        kept = filter_proxies(nodes)
        self.assertEqual([node["name"] for node in kept], ["good"])

    def test_ipv6_and_domain_servers_kept(self):
        nodes = [
            {"name": "v6", "type": "ss", "server": "2001:db8::1", "port": 1,
             "cipher": "aes-128-gcm", "password": "p"},
            {"name": "domain", "type": "vless", "server": "a.b-c.example.com",
             "port": 443, "uuid": "u", "network": "tcp"},
        ]
        self.assertEqual(len(filter_proxies(nodes)), 2)


class SortTests(unittest.TestCase):
    def test_latency_and_speed_are_comparable(self):
        nodes = [
            {"name": "fast-slow", "type": "ss", "server": "1.1.1.1", "port": 1,
             "_latency": 80, "_speed_kbps": 300},
            {"name": "slow-fast", "type": "ss", "server": "1.1.1.2", "port": 2,
             "_latency": 600, "_speed_kbps": 20000},
        ]
        ranked = sort_proxies_by_performance(nodes)
        # 归一化后 80ms 的低延时优势应大于 600ms+20Mbps 的组合分
        self.assertEqual(ranked[0]["name"], "fast-slow")


if __name__ == "__main__":
    unittest.main()
