"""Resolve the same native core for collection, capability checks and node tests."""

import asyncio
from contextlib import nullcontext
import gzip
import hashlib
import json
import math
import os
import platform
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import time
import zipfile

import aiohttp
import requests


BIN_DIR = Path(__file__).resolve().parents[1] / "clash"
DEFAULT_CACHE_DIR = Path(__file__).resolve().parents[1] / ".cache" / "mihomo"
GITHUB_RELEASES_API = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
# 1.19.30 covers the imported handshake-timeout, data-ciphers, tls-auth and
# tran-window fields; accepting CBC support alone silently loses these options.
MIN_OPENVPN_VERSION = (1, 19, 30)
MAX_RELEASE_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_BINARY_BYTES = 200 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 120
MAX_DOWNLOAD_TIMEOUT_SECONDS = 300
VERSION_TIMEOUT_SECONDS = 5


class MihomoRuntimeError(RuntimeError):
    """The requested native runtime could not be safely prepared."""


def _platform(system=None, machine=None):
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    architecture = {"amd64": "amd64", "x86_64": "amd64", "x64": "amd64",
                    "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if system not in ("linux", "windows") or architecture is None:
        raise ValueError("当前支持 Linux/Windows 的 amd64/arm64 架构；其他平台请设置 MIHOMO_BINARY")
    return system, architecture


def _version(path):
    try:
        result = subprocess.run([str(path), "-v"], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=VERSION_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"\bv(\d+)\.(\d+)\.(\d+)\b", result.stdout or "")
    return tuple(map(int, match.groups())) if result.returncode == 0 and match else None


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_path(cache_dir, system, architecture):
    return Path(cache_dir) / f"verified-runtime-{system}-{architecture}.json"


def _cached_runtime(cache_dir, system, architecture):
    try:
        manifest = _manifest_path(cache_dir, system, architecture)
        if manifest.stat().st_size > MAX_RELEASE_BYTES:
            return None
        data = json.loads(manifest.read_text(encoding="utf-8"))
        version = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", data.get("version", ""))
        if (version is None or tuple(map(int, version.groups())) < MIN_OPENVPN_VERSION
                or data.get("platform") != f"{system}-{architecture}"):
            return None
        binary_name = f"mihomo-{system}-{architecture}-{data['version']}" + (".exe" if system == "windows" else "")
        if data.get("binary") != binary_name or not re.fullmatch(r"[0-9a-f]{64}", data.get("binary_sha256", "")):
            return None
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", data.get("asset_digest", "")):
            return None
        binary = Path(cache_dir) / binary_name
        if not 0 < binary.stat().st_size <= MAX_BINARY_BYTES or _sha256(binary) != data["binary_sha256"]:
            return None
        if _version(binary) != tuple(map(int, version.groups())):
            return None
        return binary
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def resolve_mihomo_executable(system=None, machine=None, *, cache_dir=None):
    override = os.environ.get("MIHOMO_BINARY")
    if override:
        path = Path(override).expanduser()
        if not path.is_file():
            raise FileNotFoundError("MIHOMO_BINARY 指向的内核文件不存在")
        return str(path.resolve())
    system, architecture = _platform(system, machine)
    cached = _cached_runtime(cache_dir or DEFAULT_CACHE_DIR, system, architecture)
    if cached is not None:
        return str(cached.resolve())
    if architecture != "amd64":
        raise ValueError("随附 Mihomo 为 x86_64；请通过 MIHOMO_BINARY 指定当前架构内核")
    return str(BIN_DIR / ("windows-compatible.exe" if system == "windows" else "linux-compatible"))


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise MihomoRuntimeError("Mihomo 官方下载超过总时间限制")
    return remaining


def _tls_context(session):
    verify = session.verify
    if verify is True:
        verify = (os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE") or True) \
            if session.trust_env else True
    if verify is True:
        return ssl.create_default_context()
    if isinstance(verify, (str, os.PathLike)) and os.fspath(verify):
        path = Path(verify).expanduser()
        return ssl.create_default_context(capath=str(path)) if path.is_dir() \
            else ssl.create_default_context(cafile=str(path))
    raise MihomoRuntimeError("Mihomo 官方下载必须验证 TLS 证书；拒绝 verify=False 或无效证书配置")


def _fetch(session, url, deadline, max_bytes, output=None):
    remaining = _remaining(deadline)
    tls_context = _tls_context(session)
    proxy = requests.utils.select_proxy(url, session.proxies)
    headers = {"User-Agent": "get-subscribe/1.0",
               "Accept": "application/vnd.github+json" if url == GITHUB_RELEASES_API else "application/octet-stream"}

    async def transfer():
        timeout = aiohttp.ClientTimeout(total=remaining, connect=min(5, remaining), sock_read=min(15, remaining))
        async with aiohttp.ClientSession(timeout=timeout, trust_env=session.trust_env, headers=headers) as client:
            async with client.get(url, proxy=proxy, ssl=tls_context) as response:
                response.raise_for_status()
                total = 0
                chunks = []
                digest = hashlib.sha256()
                async for chunk in response.content.iter_chunked(65536):
                    _remaining(deadline)
                    total += len(chunk)
                    if total > max_bytes:
                        raise MihomoRuntimeError("Mihomo 官方响应超过大小限制")
                    digest.update(chunk)
                    if output is None:
                        chunks.append(chunk)
                    else:
                        output.write(chunk)
                return (b"".join(chunks) if output is None else total), digest.hexdigest()

    async def bounded_transfer():
        return await asyncio.wait_for(transfer(), timeout=remaining)

    try:
        return asyncio.run(bounded_transfer())
    except asyncio.TimeoutError:
        raise MihomoRuntimeError("Mihomo 官方下载超过总时间或读取时间限制") from None


def _release_asset(release, system, architecture):
    tag = release.get("tag_name") if isinstance(release, dict) else None
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", tag or "")
    if (match is None or tuple(map(int, match.groups())) < MIN_OPENVPN_VERSION
            or release.get("prerelease") is not False or release.get("draft") is not False):
        raise MihomoRuntimeError("官方稳定 Mihomo 不满足本项目 OpenVPN >=1.19.30 要求")
    variant = "amd64-compatible" if architecture == "amd64" else "arm64"
    extension = "zip" if system == "windows" else "gz"
    name = f"mihomo-{system}-{variant}-{tag}.{extension}"
    assets = [asset for asset in release.get("assets", []) if isinstance(asset, dict) and asset.get("name") == name]
    if len(assets) != 1:
        raise MihomoRuntimeError("官方稳定版没有当前平台的 Mihomo 安装包")
    asset = assets[0]
    digest = asset.get("digest")
    url = f"https://github.com/MetaCubeX/mihomo/releases/download/{tag}/{name}"
    size = asset.get("size")
    if (not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest) is None
            or asset.get("browser_download_url") != url
            or isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_ARCHIVE_BYTES):
        raise MihomoRuntimeError("官方 Mihomo 安装包 URL、大小或 SHA-256 元数据无效")
    return tag, asset


def _extract_binary(archive, output, system, architecture, deadline):
    variant = "amd64-compatible" if architecture == "amd64" else "arm64"
    archive_handle = None
    try:
        if system == "windows":
            archive_handle = zipfile.ZipFile(archive)
            member = f"mihomo-windows-{variant}.exe"
            matches = [item for item in archive_handle.infolist() if item.filename == member]
            if len(matches) != 1 or matches[0].is_dir() or not 0 < matches[0].file_size <= MAX_BINARY_BYTES:
                raise MihomoRuntimeError("Mihomo ZIP 缺少精确的可执行文件成员或大小无效")
            stream = archive_handle.open(matches[0])
        else:
            stream = gzip.open(archive, "rb")
        total = 0
        with stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                _remaining(deadline)
                total += len(chunk)
                if total > MAX_BINARY_BYTES:
                    raise MihomoRuntimeError("Mihomo 解压后的内核超过大小限制")
                output.write(chunk)
        if total == 0:
            raise MihomoRuntimeError("Mihomo 解压后的内核为空")
    finally:
        if archive_handle is not None:
            archive_handle.close()


def ensure_openvpn_runtime(*, system=None, machine=None, cache_dir=None, total_timeout=DOWNLOAD_TIMEOUT_SECONDS,
                          session=None):
    """Use a capable core or verify/cache an official stable release on demand."""
    if (isinstance(total_timeout, bool) or not isinstance(total_timeout, (int, float))
            or not 0 < total_timeout <= MAX_DOWNLOAD_TIMEOUT_SECONDS or not math.isfinite(total_timeout)):
        raise MihomoRuntimeError(f"Mihomo 下载总超时必须是 0–{MAX_DOWNLOAD_TIMEOUT_SECONDS} 秒之间的有限正数")
    override = os.environ.get("MIHOMO_BINARY")
    if override:
        path = Path(override).expanduser()
        if not path.is_file():
            raise MihomoRuntimeError("MIHOMO_BINARY 指向的内核文件不存在；请修正显式配置")
        version = _version(path)
        if version is None or version < MIN_OPENVPN_VERSION:
            raise MihomoRuntimeError("MIHOMO_BINARY 需要 Mihomo >=1.19.30 才能保留本项目 OpenVPN 配置字段；未覆盖显式配置")
        return str(path.resolve())
    system, architecture = _platform(system, machine)
    cache_dir = Path(cache_dir or DEFAULT_CACHE_DIR)
    cached = _cached_runtime(cache_dir, system, architecture)
    if cached is not None:
        return str(cached.resolve())
    bundled = BIN_DIR / ("windows-compatible.exe" if system == "windows" else "linux-compatible")
    if architecture == "amd64" and bundled.is_file():
        version = _version(bundled)
        if version is not None and version >= MIN_OPENVPN_VERSION:
            return str(bundled.resolve())
    deadline = time.monotonic() + total_timeout
    temporary = []
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        with (nullcontext(session) if session is not None else requests.Session()) as session:
            raw, _ = _fetch(session, GITHUB_RELEASES_API, deadline, MAX_RELEASE_BYTES)
            tag, asset = _release_asset(json.loads(raw), system, architecture)
            archive = cache_dir / asset["name"]
            expected_digest = asset["digest"].split(":", 1)[1].lower()
            if not archive.is_file() or archive.stat().st_size != asset["size"] or _sha256(archive) != expected_digest:
                asset_id = asset.get("id")
                api_url = f"https://api.github.com/repos/MetaCubeX/mihomo/releases/assets/{asset_id}"
                download_url = (api_url if type(asset_id) is int and asset_id > 0 and asset.get("url") == api_url
                                else asset["browser_download_url"])
                with tempfile.NamedTemporaryFile(dir=cache_dir, prefix=".mihomo-", suffix=".archive", delete=False) as stream:
                    temporary.append(Path(stream.name))
                    size, digest = _fetch(session, download_url, deadline, MAX_ARCHIVE_BYTES, stream)
                if size != asset["size"] or digest != expected_digest:
                    raise MihomoRuntimeError("Mihomo 官方安装包 SHA-256 或大小校验失败")
                os.replace(temporary[-1], archive)
            name = f"mihomo-{system}-{architecture}-{tag}" + (".exe" if system == "windows" else "")
            target = cache_dir / name
            with tempfile.NamedTemporaryFile(dir=cache_dir, prefix=".mihomo-", suffix=".exe" if system == "windows" else ".bin", delete=False) as stream:
                temporary.append(Path(stream.name))
                _extract_binary(archive, stream, system, architecture, deadline)
            binary_temp = temporary[-1]
            if system == "linux":
                binary_temp.chmod(0o700)
            version = _version(binary_temp)
            if version is None or version < MIN_OPENVPN_VERSION or version != tuple(map(int, tag[1:].split("."))):
                raise MihomoRuntimeError("下载的 Mihomo 版本探测失败或与官方版本不符")
            metadata = {"version": tag, "platform": f"{system}-{architecture}", "binary": name,
                        "binary_sha256": _sha256(binary_temp), "asset_digest": asset["digest"].lower()}
            os.replace(binary_temp, target)
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=cache_dir, prefix=".mihomo-", suffix=".json", delete=False) as stream:
                temporary.append(Path(stream.name))
                json.dump(metadata, stream)
            os.replace(temporary[-1], _manifest_path(cache_dir, system, architecture))
            return str(target.resolve())
    except MihomoRuntimeError:
        raise
    except (requests.RequestException, aiohttp.ClientError, OSError, ValueError, TypeError, zipfile.BadZipFile, EOFError) as error:
        raise MihomoRuntimeError(f"无法准备官方 Mihomo 内核（{type(error).__name__}）") from None
    finally:
        for path in temporary:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
