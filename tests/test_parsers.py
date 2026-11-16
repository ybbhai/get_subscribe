"""节点解析、去重与排序的离线回归测试。

这些行为曾经出现过静默降级（节点能生成配置但拨号失败、或字段在去重时被抹掉），
单靠"配置校验通过"发现不了，因此这里用纯离线用例把关键字段固定下来。
"""

import base64
import unittest

from utils.utils import (
    b64_decode_text,
    decode_ss,
    decode_vless,
    decode_vmess,
    filter_proxies,
    sort_proxies_by_performance,
)


def urlsafe_b64(text):
    """生成不带 padding 的 urlsafe base64，模拟真实订阅里的写法。"""
    raw = base64.urlsafe_b64encode(text.encode()).decode()
    return raw.rstrip("=")


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
