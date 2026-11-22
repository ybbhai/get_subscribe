import hashlib
import ipaddress
import json
import os
import random
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from utils.cloudflare_source import CloudflareSourceError
from utils.cloudflare_speedtest import (
    _download_asset,
    _parse_ipv4_networks,
    _parse_speedtest_results,
    _platform_asset_name,
    fetch_cloudflare_ipv4_networks,
    get_optimized_cloudflare_proxies,
    run_cloudflare_speedtest,
    sample_cloudflare_scan_ranges,
)


UUID_ONE = "11111111-1111-4111-8111-111111111111"


def cloudflare_template():
    return {
        "name": "source-node", "type": "vless", "server": "104.16.0.1",
        "port": 443, "uuid": UUID_ONE, "network": "ws", "tls": True,
        "servername": "cdn.example",
        "ws-opts": {"path": "/edge", "headers": {"Host": "cdn.example"}},
    }


class CloudflareRangeTests(unittest.TestCase):
    def test_parses_only_official_ipv4_network_lines(self):
        networks = _parse_ipv4_networks(
            b"# cloudflare ranges\n104.16.0.0/13\n2606:4700::/32\ninvalid\n"
        )

        self.assertEqual(networks, [ipaddress.ip_network("104.16.0.0/13")])

    def test_invalid_feed_encoding_uses_cached_networks(self):
        response = Mock()
        response.iter_content.return_value = [b"\xff\xfe"]
        session = Mock()
        session.get.return_value = response

        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "ips-v4.txt"
            cache_path.write_text("104.16.0.0/13\n", encoding="ascii")
            with patch("utils.cloudflare_speedtest._direct_session",
                       return_value=session):
                networks = fetch_cloudflare_ipv4_networks(directory)

        self.assertEqual(networks, [ipaddress.ip_network("104.16.0.0/13")])
        response.close.assert_called_once_with()

    def test_samples_bounded_ipv4_subnets(self):
        networks = [
            ipaddress.ip_network("104.16.0.0/16"),
            ipaddress.ip_network("104.17.0.0/24"),
        ]

        sampled = sample_cloudflare_scan_ranges(
            networks, max_ranges=3, samples_per_network=2,
            rng=random.Random(4),
        )

        self.assertEqual(len(sampled), 3)
        self.assertTrue(all(
            any(ipaddress.ip_network(item).subnet_of(network) for network in networks)
            for item in sampled
        ))

    def test_samples_wide_ranges_without_enumerating_every_subnet(self):
        sampled = sample_cloudflare_scan_ranges(
            [ipaddress.ip_network("0.0.0.0/0")],
            max_ranges=4,
            samples_per_network=4,
            rng=random.Random(2),
        )

        self.assertEqual(len(sampled), 4)

    def test_platform_assets_map_supported_windows_and_linux_architectures(self):
        self.assertEqual(
            _platform_asset_name("Windows", "AMD64"), "cfst_windows_amd64.zip"
        )
        self.assertEqual(
            _platform_asset_name("Linux", "aarch64"), "cfst_linux_arm64.tar.gz"
        )
        with self.assertRaises(CloudflareSourceError):
            _platform_asset_name("Darwin", "arm64")

    def test_downloaded_release_asset_must_match_sha256_digest(self):
        payload = b"verified release asset"
        response = Mock()
        response.iter_content.return_value = [payload]
        session = Mock()
        session.get.return_value = response
        digest = hashlib.sha256(payload).hexdigest()

        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.cloudflare_speedtest._direct_session", return_value=session):
            archive = Path(directory) / "cfst.zip"
            downloaded = _download_asset(
                {"browser_download_url": "https://example.test/cfst.zip"},
                archive,
                f"sha256:{digest}",
            )
            self.assertEqual(downloaded.read_bytes(), payload)

            with self.assertRaisesRegex(CloudflareSourceError, "SHA-256 不匹配"):
                _download_asset(
                    {"browser_download_url": "https://example.test/cfst.zip"},
                    archive.with_name("bad.zip"),
                    "sha256:" + "0" * 64,
                )


class CloudflareSpeedTestTests(unittest.TestCase):
    def test_parses_download_speed_csv_and_rejects_nonfinite_values(self):
        results = _parse_speedtest_results(
            "IP Address,Download Speed(MB/s)\n"
            "104.16.0.1,12.5 MB/s\n"
            "104.16.0.2,nan\n"
            "104.16.0.3,0\n".encode(),
            10,
        )

        self.assertEqual(results, [{"ip": "104.16.0.1", "download_speed": 12.5}])

    def test_runner_strips_proxy_environment_and_scans_only_requested_port(self):
        def fake_run(command, **kwargs):
            output_path = Path(command[command.index("-o") + 1])
            output_path.write_text(
                "IP Address,Download Speed(MB/s)\n104.16.0.1,12.5\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.cloudflare_speedtest._get_cloudflare_speedtest_binary",
                      return_value=Path("cfst.exe")), \
                patch("utils.cloudflare_speedtest.subprocess.run", side_effect=fake_run) as run, \
                patch.dict(os.environ, {
                    "HTTP_PROXY": "http://127.0.0.1:7890",
                    "https_proxy": "http://127.0.0.1:7890",
                    "ALL_PROXY": "socks5://127.0.0.1:1080",
                }, clear=True):
            result = run_cloudflare_speedtest(
                [ipaddress.ip_network("104.16.0.0/24")],
                max_candidates=8,
                cache_dir=directory,
            )

        self.assertEqual(result[0]["ip"], "104.16.0.1")
        command = run.call_args.args[0]
        environment = run.call_args.kwargs["env"]
        self.assertEqual(command[command.index("-tp") + 1], "443")
        self.assertEqual(command[command.index("-dn") + 1], "8")
        self.assertNotIn("-allip", command)
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
                    "https_proxy", "all_proxy"):
            self.assertNotIn(key, environment)
        self.assertEqual(environment["NO_PROXY"], "*")

    def test_runner_rejects_non_443_template_port(self):
        with self.assertRaisesRegex(CloudflareSourceError, "只扫描 443"):
            run_cloudflare_speedtest(
                [ipaddress.ip_network("104.16.0.0/24")], port=8443
            )

    def test_runner_preserves_measurements_and_scan_parameters(self):
        csv_data = "IP Address,Download Speed(MB/s)\n104.16.0.1,12.5\n104.16.0.2,0\n"

        def fake_run(command, **kwargs):
            Path(command[command.index("-o") + 1]).write_bytes(csv_data.encode())
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.cloudflare_speedtest._get_cloudflare_speedtest_binary",
                      return_value=Path("cfst.exe")), \
                patch("utils.cloudflare_speedtest.subprocess.run", side_effect=fake_run):
            report_dir = Path(directory) / "run"
            result = run_cloudflare_speedtest(
                [ipaddress.ip_network("104.16.0.0/24")],
                max_candidates=8, cache_dir=directory, diagnostics_dir=report_dir,
            )
            self.assertEqual((report_dir / "cloudflare_speedtest.csv").read_bytes(),
                             csv_data.encode())
            report = json.loads((report_dir / "cloudflare_speedtest_diagnostics.json").read_text())

        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["sampled_range_count"], 1)
        self.assertEqual(report["speedtested_ingress_count"], 1)
        self.assertEqual(report["ingress_results"], result)
        self.assertEqual(report["scan_parameters"]["max_downloads"], 8)
        self.assertEqual(report["scan_parameters"]["port"], 443)
        self.assertEqual(report["scan_parameters"]["timeout_seconds"], 300)

    def test_automatic_diagnostics_explain_count_without_subscription_secrets(self):
        templates = []
        for index in range(3):
            template = cloudflare_template()
            template["ws-opts"]["path"] = f"/private-path-{index}?token=secret"
            template["password"] = "private-password"
            template["_subscription_url"] = "https://secret.example/subscription?token=secret"
            templates.append(template)
        addresses = [{"ip": f"104.16.0.{index}", "download_speed": 20}
                     for index in range(2, 7)]

        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.cloudflare_speedtest.fetch_cloudflare_ipv4_networks",
                      return_value=[ipaddress.ip_network("104.16.0.0/13")]), \
                patch("utils.cloudflare_speedtest.run_cloudflare_speedtest",
                      return_value=addresses) as scan:
            result = get_optimized_cloudflare_proxies(templates, diagnostics_dir=directory)
            raw = (Path(directory) / "cloudflare_diagnostics.json").read_text()
            report = json.loads(raw)

        self.assertEqual(scan.call_args.kwargs["diagnostics_dir"], directory)
        self.assertEqual(report["status"], "generated")
        self.assertEqual(report["template_count"], 3)
        self.assertEqual(report["speedtested_ingress_count"], 5)
        self.assertEqual(report["candidate_count"], 15)
        self.assertEqual(report["max_candidates"], 40)
        self.assertEqual(report["candidates"], [
            {"id": proxy["name"], "ingress_ip": proxy["server"]} for proxy in result
        ])
        for secret in (UUID_ONE, "private-password", "private-path", "cdn.example",
                       "secret.example", "subscription", "token", "servername", "ws-opts"):
            self.assertNotIn(secret, raw)

    def test_automatic_diagnostics_record_no_template_without_network_access(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.cloudflare_speedtest.fetch_cloudflare_ipv4_networks") as fetch:
            self.assertEqual(get_optimized_cloudflare_proxies([], diagnostics_dir=directory), [])
            report = json.loads((Path(directory) / "cloudflare_diagnostics.json").read_text())

        fetch.assert_not_called()
        self.assertEqual(report["status"], "no_reusable_template")
        self.assertEqual(report["template_count"], 0)
        self.assertEqual(report["candidate_count"], 0)

    def test_failed_scan_records_only_safe_error_type(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.cloudflare_speedtest.fetch_cloudflare_ipv4_networks",
                      return_value=[ipaddress.ip_network("104.16.0.0/13")]), \
                patch("utils.cloudflare_speedtest.run_cloudflare_speedtest",
                      side_effect=CloudflareSourceError("private subscription token")):
            with self.assertRaises(CloudflareSourceError):
                get_optimized_cloudflare_proxies([cloudflare_template()], diagnostics_dir=directory)
            raw = (Path(directory) / "cloudflare_diagnostics.json").read_text()
            report = json.loads(raw)

        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["template_count"], 1)
        self.assertEqual(report["error_type"], "CloudflareSourceError")
        self.assertNotIn("private", raw)

    def test_diagnostic_write_failure_does_not_discard_usable_candidates(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("utils.cloudflare_speedtest.fetch_cloudflare_ipv4_networks",
                      return_value=[ipaddress.ip_network("104.16.0.0/13")]), \
                patch("utils.cloudflare_speedtest.run_cloudflare_speedtest",
                      return_value=[{"ip": "104.16.0.2", "download_speed": 20}]):
            blocked_path = Path(directory) / "not-a-directory"
            blocked_path.write_text("existing file")
            result = get_optimized_cloudflare_proxies(
                [cloudflare_template()], diagnostics_dir=blocked_path,
            )

        self.assertEqual(len(result), 1)

    def test_automatic_flow_skips_network_when_no_reusable_template_exists(self):
        with patch("utils.cloudflare_speedtest.fetch_cloudflare_ipv4_networks") as fetch:
            result = get_optimized_cloudflare_proxies([{"type": "ss"}])

        self.assertEqual(result, [])
        fetch.assert_not_called()

    def test_automatic_flow_filters_results_to_official_ranges(self):
        network = ipaddress.ip_network("104.16.0.0/13")
        addresses = [
            {"ip": "104.16.0.2", "download_speed": 20},
            {"ip": "203.0.113.4", "download_speed": 100},
        ]
        with patch("utils.cloudflare_speedtest.fetch_cloudflare_ipv4_networks",
                   return_value=[network]), \
                patch("utils.cloudflare_speedtest.run_cloudflare_speedtest",
                      return_value=addresses) as scan:
            result = get_optimized_cloudflare_proxies(
                [cloudflare_template()], max_candidates=5
            )

        self.assertEqual(scan.call_count, 1)
        self.assertEqual(scan.call_args.args[0], [network])
        self.assertEqual(scan.call_args.kwargs["port"], 443)
        self.assertEqual(scan.call_args.kwargs["max_candidates"], 5)
        self.assertEqual([proxy["server"] for proxy in result], ["104.16.0.2"])
        self.assertEqual(result[0]["port"], 443)
        self.assertEqual(result[0]["uuid"], UUID_ONE)


if __name__ == "__main__":
    unittest.main()
