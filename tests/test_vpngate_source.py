import asyncio
import base64
from contextlib import contextmanager
import csv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import threading
import time
import unittest
from unittest.mock import AsyncMock, patch

import requests

from utils.vpngate_source import (
    CSV_HEADER, MAX_SOURCE_BYTES, VPNGateSourceError, get_vpngate_proxies, parse_openvpn,
)


def pem(label):
    return f"-----BEGIN {label}-----\nZmFrZQ==\n-----END {label}-----"


def profile(remote="remote 8.8.4.4 443", proto="tcp", extra="", auth=False):
    credentials = "auth-user-pass\n" if auth else (
        f"<cert>\n{pem('CERTIFICATE')}\n</cert>\n<key>\n{pem('PRIVATE KEY')}\n</key>\n")
    return (f"client\ndev tun\nproto {proto}\n{remote}\n"
            "cipher AES-128-CBC\ndata-ciphers AES-256-GCM:AES-128-CBC\nauth SHA1\n"
            f"nobind\npersist-key\npersist-tun\nresolv-retry infinite\nverb 3\n{extra}\n"
            f"<ca>\n{pem('CERTIFICATE')}\n</ca>\n{credentials}")


def csv_data(records):
    output = io.StringIO(newline="")
    output.write("*vpn_servers\r\n")
    writer = csv.writer(output)
    writer.writerow(["#HostName", *CSV_HEADER[1:]])
    for config, changes in records:
        row = dict.fromkeys(CSV_HEADER, "0")
        row.update(HostName="vpn-fixture", IP="8.8.4.4", Score="100", Ping="10",
                   CountryShort="JP", OpenVPN_ConfigData_Base64=base64.b64encode(config.encode()).decode())
        row.update(changes)
        writer.writerow([row[key] for key in CSV_HEADER])
    output.write("*\r\n")
    return output.getvalue().encode()


class VPNGateParsingTests(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.session.trust_env = False
        self.addCleanup(self.session.close)

    def fetch(self, raw, **kwargs):
        info = {}
        with patch("utils.vpngate_source._fetch_source", new=AsyncMock(return_value=raw)):
            nodes = get_vpngate_proxies(self.session, diagnostics=info, **kwargs)
        return nodes, info

    def test_tcp_udp_crypto_and_public_auth_are_preserved_without_risk_claim(self):
        nodes, info = self.fetch(csv_data([
            (profile(), {}), (profile(proto="udp", auth=True), {"CountryShort": "US"}),
        ]))
        self.assertEqual((info["fetched"], info["parsed"], info["unique"], info["selected"]), (2, 2, 2, 2))
        self.assertEqual({node["proto"] for node in nodes}, {"tcp", "udp"})
        for node in nodes:
            self.assertEqual(node["cipher"], "AES-128-CBC")
            self.assertEqual(node["data-ciphers"], ["AES-256-GCM", "AES-128-CBC"])
            self.assertEqual(node["auth"], "SHA1")
            self.assertEqual(node["_source_ids"], ["vpngate"])
            self.assertNotIn("_exit_quality", node)
            self.assertNotIn("dialer-proxy", node)
            self.assertNotIn("residential", node)
        udp = next(node for node in nodes if node["proto"] == "udp")
        self.assertEqual((udp["username"], udp["password"], udp["udp"]), ("vpn", "vpn", True))
        self.assertNotIn("PRIVATE KEY", json.dumps(info))

    def test_dedupe_before_source_score_order_and_limit(self):
        low = profile()
        high = profile(remote="remote 1.1.1.1 443")
        nodes, info = self.fetch(csv_data([
            (low, {"Score": "1"}), (high, {"Score": "200"}),
            (low, {"Score": "300"}),
        ]), max_candidates=1)
        self.assertEqual(info["unique"], 2)
        self.assertEqual(info["selected"], 1)
        self.assertEqual(nodes[0]["server"], "8.8.4.4")
        self.assertNotIn("_speed_kbps", nodes[0])
        self.assertNotIn("_latency", nodes[0])

    def test_multiple_remotes_and_alias_pinning(self):
        config = profile(remote="remote vpn-fixture.opengw.net 443 tcp\nremote 1.1.1.1 1194 udp")
        nodes = parse_openvpn(config, advertised_ip="8.8.4.4", hostname="vpn-fixture")
        self.assertEqual([(node["server"], node["proto"]) for node in nodes], [("8.8.4.4", "tcp"), ("1.1.1.1", "udp")])
        with self.assertRaises(VPNGateSourceError):
            parse_openvpn(profile(remote="\n".join("remote 8.8.4.4 443" for _ in range(5))))

    def test_remote_rejects_private_localhost_arbitrary_domains_and_family_mismatch(self):
        for remote in ("127.0.0.1", "192.168.1.5", "169.254.169.254", "::1", "localhost",
                       "example.com", "2130706433", "[fe80::1%eth0]"):
            with self.subTest(remote=remote), self.assertRaises(VPNGateSourceError):
                parse_openvpn(profile(remote=f"remote {remote} 443"), advertised_ip="8.8.4.4", hostname="vpn-fixture")
        with self.assertRaisesRegex(VPNGateSourceError, "family"):
            parse_openvpn(profile(proto="udp6"))

    def test_unsupported_security_script_route_and_file_options_fail_closed(self):
        for option in ("remote-cert-tls server", "verify-x509-name secret-name name", "script-security 2",
                       "up /private/secret", "route 10.0.0.0 255.0.0.0", "ca /private/secret.pem",
                       "auth-user-pass /private/secret", "compress lz4", "tls-version-min 1.3",
                       "reneg-sec 0", "cipher BF-CBC"):
            with self.subTest(option=option), self.assertRaises(VPNGateSourceError) as raised:
                parse_openvpn(profile(extra=option))
            self.assertNotIn("private", str(raised.exception))
            self.assertNotIn("secret", str(raised.exception))

    def test_tls_auth_and_direction_are_retained_and_conflicts_rejected(self):
        block = "-----BEGIN OpenVPN Static key V1-----\n" + "ab" * 256 + "\n-----END OpenVPN Static key V1-----"
        extra = f"tls-auth [inline] 1\n<tls-auth>\n{block}\n</tls-auth>\nkey-direction 1\ncomp-lzo no"
        node = parse_openvpn(profile(extra=extra))[0]
        self.assertEqual(node["key-direction"], "1")
        self.assertEqual(node["comp-lzo"], "no")
        self.assertEqual(node["tls-auth"].strip(), block)
        with self.assertRaises(VPNGateSourceError):
            parse_openvpn(profile(extra=extra.replace("key-direction 1", "key-direction 0")))

    def test_missing_inline_material_and_ambiguous_defaults_are_rejected(self):
        for config in (profile().replace("</ca>", ""), profile().replace("<key>", "<unknown>"),
                       profile().replace("cipher AES-128-CBC\n", "").replace("data-ciphers AES-256-GCM:AES-128-CBC\n", ""),
                       profile().replace("proto tcp", "proto tcp-server")):
            with self.subTest(config=config[:30]), self.assertRaises(VPNGateSourceError):
                parse_openvpn(config)

    def test_bad_csv_header_base64_and_rows_do_not_create_nodes(self):
        for raw in (b"<html>error</html>", csv_data([(profile(), {})]).replace(b"#HostName", b"#Host")):
            nodes, info = self.fetch(raw)
            self.assertEqual(nodes, [])
            self.assertEqual(info["status"], "unavailable")
        nodes, info = self.fetch(csv_data([
            (profile(), {"OpenVPN_ConfigData_Base64": "bad!"}),
            (profile(), {"IP": "127.0.0.1"}),
            (profile(), {}),
        ]))
        self.assertEqual(len(nodes), 1)
        self.assertEqual(info["rejected"], 2)

    def test_mirror_only_follows_failed_source_and_errors_are_sanitized(self):
        info = {}
        with patch("utils.vpngate_source._fetch_source", new=AsyncMock(side_effect=[
            OSError("https://secret-token.invalid/ private-key"), csv_data([(profile(), {})]),
        ])) as fetch:
            nodes = get_vpngate_proxies(self.session, mirror_urls=("https://mirror.invalid/api",), diagnostics=info)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(info["status"], "ok")
        self.assertNotIn("secret", json.dumps(info))
        with patch("utils.vpngate_source._fetch_source", new=AsyncMock(return_value=csv_data([(profile(), {})]))) as fetch:
            get_vpngate_proxies(self.session, mirror_urls=("https://mirror.invalid/api",))
        self.assertEqual(fetch.call_count, 1)

    def test_invalid_limits_and_timeout_are_rejected(self):
        for limit in (0, 501, True, 1.5):
            with self.subTest(limit=limit), self.assertRaises(VPNGateSourceError):
                get_vpngate_proxies(self.session, max_candidates=limit)
        for timeout in ((0, 5), (1, float("inf")), 10):
            with self.subTest(timeout=timeout), self.assertRaises(VPNGateSourceError):
                get_vpngate_proxies(self.session, timeout=timeout)


@contextmanager
def local_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class VPNGateHttpTests(unittest.TestCase):
    def test_real_http_fetch_and_explicit_proxy_preserve_selected_route(self):
        seen = []
        raw = csv_data([(profile(), {})])

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Accept-Encoding")))
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *args):
                pass

        with local_server(Handler) as url, requests.Session() as session:
            session.trust_env = False
            session.proxies = {"http": url.rsplit("/", 1)[0]}
            with patch.dict("os.environ", {"HTTP_PROXY": "http://127.0.0.1:1"}):
                nodes = get_vpngate_proxies(session, api_url="http://source.invalid/api")
        self.assertEqual(len(nodes), 1)
        self.assertEqual(seen, [("http://source.invalid/api", "identity")])

    def test_total_deadline_cancels_trickling_body(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "1000")
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(0.02)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass
            def log_message(self, *args):
                pass

        with local_server(Handler) as url, requests.Session() as session:
            session.trust_env = False
            info = {}
            start = time.monotonic()
            nodes = get_vpngate_proxies(session, api_url=url, timeout=(0.15, 0.15), diagnostics=info)
            elapsed = time.monotonic() - start
        self.assertEqual(nodes, [])
        self.assertEqual(info["error_type"], "source_timeout")
        self.assertLess(elapsed, 0.8)

    def test_redirect_and_oversized_content_are_not_consumed(self):
        requests_seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests_seen.append(self.path)
                redirect = self.path == "/redirect"
                self.send_response(302 if redirect else 200)
                self.send_header("Location", "/private-secret")
                self.send_header("Content-Length", "0" if redirect else str(MAX_SOURCE_BYTES + 1))
                self.end_headers()
            def log_message(self, *args):
                pass

        with local_server(Handler) as url, requests.Session() as session:
            session.trust_env = False
            for endpoint, expected in (("redirect", "source_http_error"), ("large", "source_size_limit")):
                info = {}
                nodes = get_vpngate_proxies(session, api_url=url.rsplit("/", 1)[0] + "/" + endpoint, diagnostics=info)
                self.assertEqual(nodes, [])
                self.assertEqual(info["error_type"], expected)
        self.assertEqual(requests_seen, ["/redirect", "/large"])


if __name__ == "__main__":
    unittest.main()
