import asyncio
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import ssl
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
import zipfile

import requests

from utils.mihomo_runtime import (
    MAX_ARCHIVE_BYTES, MihomoRuntimeError, _cached_runtime, _extract_binary, _fetch,
    _release_asset, _tls_context, _version, ensure_openvpn_runtime, resolve_mihomo_executable,
)


def archive_bytes(system="windows", architecture="amd64", payload=b"official-test-binary", member=None):
    if system == "linux":
        return gzip.compress(payload)
    output = io.BytesIO()
    variant = "amd64-compatible" if architecture == "amd64" else "arm64"
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(member or f"mihomo-windows-{variant}.exe", payload)
    return output.getvalue()


def release_for(archive, system="windows", architecture="amd64", version="v1.19.34"):
    variant = "amd64-compatible" if architecture == "amd64" else "arm64"
    name = f"mihomo-{system}-{variant}-{version}." + ("zip" if system == "windows" else "gz")
    return {
        "tag_name": version, "draft": False, "prerelease": False,
        "assets": [{"id": 123, "name": name, "size": len(archive),
                    "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
                    "url": "https://api.github.com/repos/MetaCubeX/mihomo/releases/assets/123",
                    "browser_download_url": f"https://github.com/MetaCubeX/mihomo/releases/download/{version}/" + name}],
    }


def mock_fetch(release, archive):
    def fetch(session, url, deadline, max_bytes, output=None):
        if output is None:
            return json.dumps(release).encode(), "unused"
        output.write(archive)
        return len(archive), hashlib.sha256(archive).hexdigest()
    return fetch


class MihomoRuntimeTests(unittest.TestCase):
    def test_official_platform_assets_cover_windows_linux_and_arm64(self):
        for system in ("windows", "linux"):
            for architecture in ("amd64", "arm64"):
                with self.subTest(system=system, architecture=architecture):
                    archive = archive_bytes(system, architecture)
                    tag, asset = _release_asset(release_for(archive, system, architecture), system, architecture)
                    self.assertEqual(tag, "v1.19.34")
                    self.assertIn(system, asset["name"])
                    self.assertIn(architecture, asset["name"])

    def test_capable_existing_binary_is_reused_without_download(self):
        with tempfile.TemporaryDirectory() as directory:
            bundled = Path(directory) / "windows-compatible.exe"
            bundled.write_bytes(b"existing")
            with patch.dict(os.environ, {"MIHOMO_BINARY": ""}), \
                    patch("utils.mihomo_runtime.BIN_DIR", Path(directory)), \
                    patch("utils.mihomo_runtime._version", return_value=(1, 19, 30)), \
                    patch("utils.mihomo_runtime.requests.Session") as session:
                result = ensure_openvpn_runtime(system="Windows", machine="AMD64", cache_dir=Path(directory) / "cache")
            self.assertEqual(result, str(bundled.resolve()))
            session.assert_not_called()

    def test_explicit_old_missing_or_unreadable_binary_is_never_overridden(self):
        with tempfile.TemporaryDirectory() as directory:
            explicit = Path(directory) / "explicit.exe"
            explicit.write_bytes(b"user-binary")
            for version in (*((1, 19, patch_number) for patch_number in range(25, 30)), None):
                with self.subTest(version=version), patch.dict(os.environ, {"MIHOMO_BINARY": str(explicit)}), \
                        patch("utils.mihomo_runtime._version", return_value=version), \
                        patch("utils.mihomo_runtime.requests.Session") as session:
                    with self.assertRaisesRegex(MihomoRuntimeError, "MIHOMO_BINARY"):
                        ensure_openvpn_runtime(cache_dir=directory)
                    session.assert_not_called()
            explicit.unlink()
            with patch.dict(os.environ, {"MIHOMO_BINARY": str(explicit)}):
                with self.assertRaisesRegex(MihomoRuntimeError, "不存在"):
                    ensure_openvpn_runtime(cache_dir=directory)

    def test_official_release_requires_all_imported_openvpn_fields(self):
        archive = archive_bytes()
        for patch_number in range(26, 30):
            with self.subTest(patch=patch_number), self.assertRaisesRegex(MihomoRuntimeError, "1.19.30"):
                _release_asset(release_for(archive, version=f"v1.19.{patch_number}"), "windows", "amd64")
        tag, _ = _release_asset(release_for(archive, version="v1.19.30"), "windows", "amd64")
        self.assertEqual(tag, "v1.19.30")

    def test_explicit_minimum_version_is_reused_without_download(self):
        with tempfile.TemporaryDirectory() as directory:
            explicit = Path(directory) / "explicit.exe"
            explicit.write_bytes(b"user-binary")
            with patch.dict(os.environ, {"MIHOMO_BINARY": str(explicit)}), \
                    patch("utils.mihomo_runtime._version", return_value=(1, 19, 30)), \
                    patch("utils.mihomo_runtime.requests.Session") as session:
                self.assertEqual(ensure_openvpn_runtime(cache_dir=directory), str(explicit.resolve()))
                session.assert_not_called()

    def test_older_verified_cache_is_not_reused_after_capability_requirement_increases(self):
        payload = b"previously-verified-core"
        with tempfile.TemporaryDirectory() as directory:
            for patch_number in range(26, 31):
                tag = f"v1.19.{patch_number}"
                binary = Path(directory) / f"mihomo-windows-amd64-{tag}.exe"
                binary.write_bytes(payload)
                manifest = {"version": tag, "platform": "windows-amd64", "binary": binary.name,
                            "binary_sha256": hashlib.sha256(payload).hexdigest(),
                            "asset_digest": "sha256:" + "a" * 64}
                (Path(directory) / "verified-runtime-windows-amd64.json").write_text(json.dumps(manifest))
                with self.subTest(patch=patch_number), \
                        patch("utils.mihomo_runtime._version", return_value=(1, 19, patch_number)) as version:
                    self.assertEqual(_cached_runtime(directory, "windows", "amd64"),
                                     binary if patch_number == 30 else None)
                    if patch_number < 30:
                        version.assert_not_called()

    def test_older_bundled_cores_trigger_verified_upgrade(self):
        archive = archive_bytes()
        release = release_for(archive)
        for patch_number in range(26, 30):
            with self.subTest(patch=patch_number), tempfile.TemporaryDirectory() as directory:
                bundled = Path(directory) / "windows-compatible.exe"
                bundled.write_bytes(b"old-bundled-core")

                def version(path):
                    return (1, 19, patch_number) if Path(path) == bundled else (1, 19, 34)

                with patch.dict(os.environ, {"MIHOMO_BINARY": ""}), \
                        patch("utils.mihomo_runtime.BIN_DIR", Path(directory)), \
                        patch("utils.mihomo_runtime._version", side_effect=version), \
                        patch("utils.mihomo_runtime._fetch", side_effect=mock_fetch(release, archive)) as fetch:
                    executable = ensure_openvpn_runtime(system="Windows", machine="amd64",
                                                        cache_dir=Path(directory) / "cache")
                    self.assertNotEqual(Path(executable), bundled)
                    self.assertEqual(Path(executable).read_bytes(), b"official-test-binary")
                    self.assertEqual(fetch.call_count, 2)

    def test_verified_windows_download_creates_cache_and_detects_tampering(self):
        archive = archive_bytes()
        release = release_for(archive)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"MIHOMO_BINARY": ""}), \
                patch("utils.mihomo_runtime.BIN_DIR", Path(directory) / "bundled"), \
                patch("utils.mihomo_runtime._version", return_value=(1, 19, 34)), \
                patch("utils.mihomo_runtime._fetch", side_effect=mock_fetch(release, archive)) as fetch:
            executable = ensure_openvpn_runtime(system="Windows", machine="amd64", cache_dir=directory)
            self.assertEqual(Path(executable).read_bytes(), b"official-test-binary")
            self.assertEqual(resolve_mihomo_executable("Windows", "amd64", cache_dir=directory), executable)
            self.assertEqual(fetch.call_args_list[1].args[1], release["assets"][0]["url"])
            fetch.reset_mock()
            self.assertEqual(ensure_openvpn_runtime(system="Windows", machine="amd64", cache_dir=directory), executable)
            fetch.assert_not_called()
            Path(executable).write_bytes(b"tampered-binary")
            self.assertTrue(resolve_mihomo_executable("Windows", "amd64", cache_dir=directory).endswith("windows-compatible.exe"))
            self.assertFalse(any(path.name.startswith(".mihomo-") for path in Path(directory).iterdir()))

    def test_linux_arm64_gzip_runtime_is_supported_without_bundled_binary(self):
        archive = archive_bytes("linux", "arm64")
        release = release_for(archive, "linux", "arm64")
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"MIHOMO_BINARY": ""}), \
                patch("utils.mihomo_runtime._version", return_value=(1, 19, 34)), \
                patch("utils.mihomo_runtime._fetch", side_effect=mock_fetch(release, archive)):
            executable = ensure_openvpn_runtime(system="Linux", machine="aarch64", cache_dir=directory)
            self.assertEqual(Path(executable).read_bytes(), b"official-test-binary")
            self.assertEqual(resolve_mihomo_executable("Linux", "arm64", cache_dir=directory), executable)

    def test_checksum_mismatch_does_not_create_runtime_or_manifest(self):
        archive = archive_bytes()
        release = release_for(archive)
        release["assets"][0]["digest"] = "sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"MIHOMO_BINARY": ""}), \
                patch("utils.mihomo_runtime.BIN_DIR", Path(directory) / "bundled"), \
                patch("utils.mihomo_runtime._fetch", side_effect=mock_fetch(release, archive)):
            with self.assertRaisesRegex(MihomoRuntimeError, "SHA-256"):
                ensure_openvpn_runtime(system="Windows", machine="amd64", cache_dir=directory)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_missing_digest_untrusted_url_and_unstable_release_are_rejected(self):
        archive = archive_bytes()
        for changes in ({"digest": None}, {"browser_download_url": "https://untrusted.example/binary.zip"},
                        {"size": MAX_ARCHIVE_BYTES + 1}, {"size": True}):
            release = release_for(archive)
            release["assets"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(MihomoRuntimeError):
                _release_asset(release, "windows", "amd64")
        for changes in ({"tag_name": "v1.19.25"}, {"tag_name": "../../evil"}, {"prerelease": True}, {"draft": True}):
            release = release_for(archive)
            release.update(changes)
            with self.subTest(changes=changes), self.assertRaises(MihomoRuntimeError):
                _release_asset(release, "windows", "amd64")

    def test_zip_requires_exact_member_and_does_not_extract_paths(self):
        archive = archive_bytes(member="../../mihomo-windows-amd64-compatible.exe")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.zip"
            path.write_bytes(archive)
            with self.assertRaisesRegex(MihomoRuntimeError, "精确"):
                _extract_binary(path, io.BytesIO(), "windows", "amd64", float("inf"))
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["archive.zip"])

    def test_archive_expansion_limit_and_total_deadline_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.gz"
            path.write_bytes(gzip.compress(b"x" * 100))
            with patch("utils.mihomo_runtime.MAX_BINARY_BYTES", 50), self.assertRaisesRegex(MihomoRuntimeError, "大小"):
                _extract_binary(path, io.BytesIO(), "linux", "amd64", float("inf"))
            with self.assertRaisesRegex(MihomoRuntimeError, "总时间"):
                _extract_binary(path, io.BytesIO(), "linux", "amd64", 0)

    def test_fetch_size_and_version_probe_timeout_are_bounded(self):
        async def chunks(size):
            yield b"x" * 100
        response = MagicMock()
        response.content.iter_chunked.side_effect = chunks
        context = MagicMock()
        context.__aenter__.return_value = response
        client = MagicMock()
        client.get.return_value = context
        manager = MagicMock()
        manager.__aenter__.return_value = client
        with requests.Session() as session, patch("utils.mihomo_runtime.aiohttp.ClientSession", return_value=manager), \
                self.assertRaisesRegex(MihomoRuntimeError, "大小"):
            _fetch(session, "https://api.github.com", time.monotonic() + 5, 50)
        with patch("utils.mihomo_runtime.subprocess.run", side_effect=subprocess.TimeoutExpired("mihomo", 5)) as run:
            self.assertIsNone(_version("fixture"))
        self.assertEqual(run.call_args.kwargs["timeout"], 5)

    def test_slow_drip_download_is_cancelled_by_total_deadline(self):
        async def chunks(size):
            while True:
                await asyncio.sleep(0.01)
                yield b"x"
        response = MagicMock()
        response.content.iter_chunked.side_effect = chunks
        context = MagicMock()
        context.__aenter__.return_value = response
        client = MagicMock()
        client.get.return_value = context
        manager = MagicMock()
        manager.__aenter__.return_value = client
        started = time.monotonic()
        with requests.Session() as session, patch("utils.mihomo_runtime.aiohttp.ClientSession", return_value=manager), \
                self.assertRaisesRegex(MihomoRuntimeError, "时间"):
            session.trust_env = False
            session.proxies = {"https": "http://127.0.0.1:18080"}
            _fetch(session, "https://api.github.com", started + 0.08, 1000)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(client.get.call_args.kwargs["proxy"], "http://127.0.0.1:18080")

    def test_external_download_session_is_not_closed_or_modified(self):
        archive = archive_bytes()
        release = release_for(archive)
        session = requests.Session()
        session.trust_env = False
        session.proxies = {"https": "http://127.0.0.1:18080"}
        original_headers = dict(session.headers)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"MIHOMO_BINARY": ""}), \
                patch("utils.mihomo_runtime.BIN_DIR", Path(directory) / "bundled"), \
                patch("utils.mihomo_runtime._version", return_value=(1, 19, 34)), \
                patch("utils.mihomo_runtime._fetch", side_effect=mock_fetch(release, archive)) as fetch, \
                patch.object(session, "close") as close:
            ensure_openvpn_runtime(system="Windows", machine="amd64", cache_dir=directory, session=session)
            close.assert_not_called()
            self.assertIs(fetch.call_args.args[0], session)
            self.assertEqual(dict(session.headers), original_headers)
        session.close()

    def test_cache_manifest_cannot_escape_its_directory(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"MIHOMO_BINARY": ""}):
            manifest = Path(directory) / "verified-runtime-windows-amd64.json"
            manifest.write_text(json.dumps({"version": "v1.19.34", "platform": "windows-amd64",
                                            "binary": "../escaped.exe", "binary_sha256": "a" * 64,
                                            "asset_digest": "sha256:" + "b" * 64}))
            self.assertTrue(resolve_mihomo_executable("Windows", "amd64", cache_dir=directory).endswith("windows-compatible.exe"))

    def test_download_timeout_must_be_positive_finite_and_bounded(self):
        for value in (None, True, 0, -1, "120", float("nan"), float("inf"), 301, 10 ** 1000):
            with self.subTest(value=value), patch("utils.mihomo_runtime._version") as version, \
                    patch("utils.mihomo_runtime.requests.Session") as session:
                with self.assertRaisesRegex(MihomoRuntimeError, "超时"):
                    ensure_openvpn_runtime(total_timeout=value)
                version.assert_not_called()
                session.assert_not_called()

    def test_tls_verification_cannot_be_disabled(self):
        with requests.Session() as session, patch("utils.mihomo_runtime.aiohttp.ClientSession") as client:
            for value in (False, None, 0, ""):
                with self.subTest(verify=value):
                    session.verify = value
                    with self.assertRaisesRegex(MihomoRuntimeError, "TLS"):
                        _fetch(session, "https://api.github.com", time.monotonic() + 5, 100)
            client.assert_not_called()

    def test_tls_context_preserves_explicit_ca_file_and_directory(self):
        with tempfile.TemporaryDirectory() as directory, requests.Session() as session:
            ca_file = Path(directory) / "custom-ca.pem"
            ca_file.write_text("test-ca")
            for path, option in ((ca_file, "cafile"), (Path(directory), "capath")):
                session.verify = str(path)
                with patch("utils.mihomo_runtime.ssl.create_default_context") as create:
                    self.assertIs(_tls_context(session), create.return_value)
                create.assert_called_once_with(**{option: str(path)})

    def test_tls_defaults_stay_verified_and_honor_environment_ca_when_enabled(self):
        with requests.Session() as session, patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": "corporate.pem"}):
            with patch("utils.mihomo_runtime.ssl.create_default_context") as create:
                _tls_context(session)
            create.assert_called_once_with(cafile="corporate.pem")
            session.trust_env = False
            context = _tls_context(session)
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_unrunnable_or_wrong_version_cache_cannot_override_working_bundle(self):
        archive = archive_bytes()
        release = release_for(archive)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"MIHOMO_BINARY": ""}), \
                patch("utils.mihomo_runtime.BIN_DIR", Path(directory) / "bundled"):
            with patch("utils.mihomo_runtime._version", return_value=(1, 19, 34)), \
                    patch("utils.mihomo_runtime._fetch", side_effect=mock_fetch(release, archive)):
                cached = ensure_openvpn_runtime(system="Windows", machine="amd64", cache_dir=directory)
            bundle = Path(directory) / "bundled" / "windows-compatible.exe"
            bundle.parent.mkdir()
            bundle.write_bytes(b"working-existing-binary")
            for cached_version in (None, (1, 19, 25), (1, 19, 33)):
                def version(path):
                    return cached_version if Path(path) == Path(cached) else (1, 19, 34)
                with self.subTest(cached_version=cached_version), \
                        patch("utils.mihomo_runtime._version", side_effect=version), \
                        patch("utils.mihomo_runtime.requests.Session") as session:
                    self.assertEqual(ensure_openvpn_runtime(system="Windows", machine="amd64", cache_dir=directory), str(bundle.resolve()))
                    self.assertEqual(resolve_mihomo_executable("Windows", "amd64", cache_dir=directory), str(bundle.resolve()))
                    session.assert_not_called()


if __name__ == "__main__":
    unittest.main()
