"""Real local transport tests: slow headers/body, size bounds and proxy routing."""
import asyncio
import os
import ssl
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, MagicMock, patch

import requests

from utils.cloudflare_source import CloudflareSourceError, _fetch_subscription, _read_subscription


@contextmanager
def local_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass


class CloudflareHttpTests(unittest.TestCase):
    def test_total_timeout_cancels_slow_body_and_closes_connection(self):
        disconnected = threading.Event()

        class Handler(QuietHandler):
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
                    disconnected.set()

        with local_server(Handler) as url, requests.Session() as session:
            session.trust_env = False
            started = time.monotonic()
            with self.assertRaises(asyncio.TimeoutError):
                asyncio.run(_fetch_subscription(session, url, (0.2, 0.2, 0.4)))
            self.assertLess(time.monotonic() - started, 0.9)
            self.assertTrue(disconnected.wait(0.8), "timed out request must release its socket")

    def test_total_timeout_covers_slow_headers(self):
        class Handler(QuietHandler):
            def do_GET(self):
                try:
                    for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n":
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.03)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

        with local_server(Handler) as url, requests.Session() as session:
            session.trust_env = False
            started = time.monotonic()
            with self.assertRaises(asyncio.TimeoutError):
                asyncio.run(_fetch_subscription(session, url, (0.2, 0.2, 0.4)))
            self.assertLess(time.monotonic() - started, 0.9)

    def test_real_transport_uses_selected_proxy_and_headers_despite_environment(self):
        seen = []

        class Handler(QuietHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("X-Subscription")))
                self.send_response(200)
                self.send_header("Content-Length", "4")
                self.end_headers()
                self.wfile.write(b"body")

        with local_server(Handler) as proxy, requests.Session() as session, \
                patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1"}):
            session.trust_env = False
            session.proxies = {"http": proxy}
            session.headers["X-Subscription"] = "custom"
            raw = asyncio.run(_fetch_subscription(session, "http://source.invalid/sub", (1, 1, 2)))
        self.assertEqual(raw, b"body")
        self.assertEqual(seen, [("http://source.invalid/sub", "custom")])

    def test_both_declared_and_streamed_oversized_responses_are_rejected(self):
        class Handler(QuietHandler):
            def do_GET(self):
                self.send_response(200)
                if self.path == "/declared":
                    self.send_header("Content-Length", "65")
                self.end_headers()
                self.wfile.write(b"a" * 65)

        with local_server(Handler) as url, requests.Session() as session, \
                patch("utils.cloudflare_source.MAX_SOURCE_BYTES", 64):
            session.trust_env = False
            for path in ("/declared", "/streamed"):
                with self.subTest(path=path), self.assertRaisesRegex(CloudflareSourceError, "超过"):
                    asyncio.run(_fetch_subscription(session, url + path, (1, 1, 2)))

    def test_https_transport_preserves_ca_proxy_headers_and_total_budget(self):
        response = MagicMock(content_length=2)
        response.content.iter_chunked.return_value.__aiter__.return_value = [b"ok"]
        client = MagicMock()
        client.get.return_value.__aenter__ = AsyncMock(return_value=response)
        context = ssl.create_default_context()
        with requests.Session() as session, \
                patch("utils.cloudflare_source.ssl.create_default_context", return_value=context) as tls, \
                patch("utils.cloudflare_source.aiohttp.ClientSession") as factory:
            session.trust_env = False
            session.verify = "private-ca.pem"
            session.headers["X-Token"] = "private-token"
            session.proxies = {"https": "http://127.0.0.1:17890"}
            factory.return_value.__aenter__ = AsyncMock(return_value=client)
            result = _read_subscription(session, "https://worker.example/sub", None, (0.2, 0.3))
        self.assertEqual(result, "ok")
        tls.assert_called_once_with(cafile="private-ca.pem", capath=None)
        self.assertEqual(factory.call_args.kwargs["headers"]["X-Token"], "private-token")
        self.assertEqual(factory.call_args.kwargs["timeout"].total, 0.5)
        self.assertFalse(factory.call_args.kwargs["trust_env"])
        self.assertEqual(client.get.call_args.kwargs["proxy"], "http://127.0.0.1:17890")
        self.assertIs(client.get.call_args.kwargs["ssl"], context)
        client.get.return_value.__aexit__.assert_awaited_once()
        factory.return_value.__aexit__.assert_awaited_once()

    def test_timeout_errors_are_sanitized_and_scalar_timeout_is_total(self):
        with patch("utils.cloudflare_source._fetch_subscription", new=AsyncMock(
                side_effect=asyncio.TimeoutError("https://worker.example/private-token"))) as fetch:
            with self.assertRaises(CloudflareSourceError) as error:
                _read_subscription(None, "https://worker.example/private-token", None, 0.2)
        self.assertNotIn("private-token", str(error.exception))
        self.assertEqual(fetch.call_args.args[-1], (0.2, 0.2, 0.2))

    def test_invalid_timeout_is_rejected_without_starting_request(self):
        for value in (None, 0, True, -1, float("inf"), (1,), (1, 0), (1, float("nan"))):
            with self.subTest(value=value), patch("utils.cloudflare_source._fetch_subscription") as fetch:
                with self.assertRaises(CloudflareSourceError):
                    _read_subscription(None, "https://worker.example/sub", None, value)
                fetch.assert_not_called()

    def test_plain_http_subscription_still_rejected(self):
        with self.assertRaisesRegex(CloudflareSourceError, "HTTPS"):
            _read_subscription(None, "http://worker.example/sub", None, 1)
