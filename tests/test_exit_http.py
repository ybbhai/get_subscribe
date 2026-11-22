"""Exercise real local sockets so slow streams cannot hide behind HTTP mocks."""

from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import time
import unittest
from unittest.mock import patch

from utils.exit_quality import ExitInspector, LookupError, _request_json
from utils.node_policy import NodePolicy


class LookupHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.reply(self.path)

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.posted.append(data)
        self.reply("/slow-body" if data.get("q") == "8.8.4.4" else "/json")

    def do_CONNECT(self):
        self.server.paths.append("CONNECT " + self.path)
        self.send_error(502)

    def reply(self, path):
        self.server.paths.append(path)
        self.server.started.set()
        status = 302 if path == "/redirect" else 200
        body = {
            "/html": b"<html>challenge</html>",
            "/large": b"x" * 65537,
            "/list": b"[]",
            "/error": b'{"error":"unavailable"}',
        }.get(path, b'{"ok":true,"padding":"' + b"x" * 48 + b'"}')
        if path == "/slow-headers" and self.server.stop_event.wait(2):
            return
        if path == "/headers-then-body" and self.server.stop_event.wait(0.4):
            return
        try:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            if status == 302:
                self.send_header("Location", "/json")
            self.end_headers()
            if path in ("/slow-body", "/headers-then-body"):
                for byte in body:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    if self.server.stop_event.wait(0.04):
                        return
            else:
                self.wfile.write(body)
        except OSError:
            self.server.disconnected.set()


class ExitHttpTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), LookupHandler)
        self.server.stop_event = threading.Event()
        self.server.started = threading.Event()
        self.server.disconnected = threading.Event()
        self.server.paths = []
        self.server.posted = []
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.stop_event.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_total_deadline_cancels_slow_body_and_closes_socket(self):
        started = time.monotonic()
        with self.assertRaisesRegex(LookupError, "lookup_timeout"):
            _request_json(None, "GET", self.url + "/slow-body", 0.4)
        self.assertLess(time.monotonic() - started, 1.3)
        self.assertTrue(self.server.disconnected.wait(1), "timed-out connection stayed open")

    def test_total_deadline_includes_response_headers(self):
        started = time.monotonic()
        with self.assertRaisesRegex(LookupError, "lookup_timeout"):
            _request_json(None, "GET", self.url + "/slow-headers", 0.4)
        self.assertLess(time.monotonic() - started, 1.3)

    def test_headers_and_body_share_one_deadline(self):
        started = time.monotonic()
        with self.assertRaisesRegex(LookupError, "lookup_timeout"):
            _request_json(None, "GET", self.url + "/headers-then-body", 0.6)
        self.assertLess(time.monotonic() - started, 1.2)

    def test_reader_rejects_redirect_html_oversized_and_invalid_records(self):
        for path, reason in (("/redirect", "lookup_http_error"),
                             ("/html", "lookup_invalid_json"),
                             ("/large", "lookup_response_limit"),
                             ("/list", "lookup_invalid_record"),
                             ("/error", "lookup_invalid_record")):
            with self.subTest(path=path), self.assertRaisesRegex(LookupError, reason):
                _request_json(None, "GET", self.url + path, 2)
        self.assertNotIn("/json", self.server.paths, "redirect was followed")

    def test_explicit_proxy_and_no_environment_proxy_or_direct_retry(self):
        environment = {key: "http://127.0.0.1:1" for key in
                       ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                        "http_proxy", "https_proxy", "all_proxy")}
        environment.update(NO_PROXY="", no_proxy="")
        with patch.dict(os.environ, environment):
            self.assertTrue(_request_json(None, "GET", self.url + "/json", 2)["ok"])
            target = "http://unresolvable.invalid/json"
            self.assertTrue(_request_json(self.url, "GET", target, 2)["ok"])
            self.assertEqual(self.server.paths[-1], target)
            count = len(self.server.paths)
            with self.assertRaisesRegex(LookupError, "lookup_(transport_error|timeout)"):
                _request_json("http://127.0.0.1:1", "GET", self.url + "/json", 1)
            self.assertEqual(len(self.server.paths), count, "failed proxy fell back to direct")

    def test_https_uses_explicit_proxy_tunnel(self):
        with self.assertRaisesRegex(LookupError, "lookup_transport_error"):
            _request_json(self.url, "GET", "https://unresolvable.invalid/json", 2)
        self.assertEqual(self.server.paths, ["CONNECT unresolvable.invalid:443"])

    def test_timed_out_keyed_request_releases_lock_for_next_exit(self):
        inspector = ExitInspector(NodePolicy(lookup_timeout_seconds=0.4))
        started = time.monotonic()
        with patch("utils.exit_quality.IPAPI_URL", self.url), ThreadPoolExecutor(2) as pool:
            first = pool.submit(inspector._lookup_ipapi, None, "8.8.4.4")
            self.assertTrue(self.server.started.wait(1))
            second = pool.submit(inspector._lookup_ipapi, None, "1.1.1.1")
            with self.assertRaisesRegex(LookupError, "lookup_timeout"):
                first.result(timeout=2)
            self.assertTrue(second.result(timeout=2)["ok"])
        self.assertLess(time.monotonic() - started, 1.3)
        self.assertEqual([record["q"] for record in self.server.posted], ["8.8.4.4", "1.1.1.1"])


if __name__ == "__main__":
    unittest.main()
