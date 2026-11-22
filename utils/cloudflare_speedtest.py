"""Account-free Cloudflare IP discovery and local CloudflareSpeedTest runner."""

import csv
import hashlib
import io
import ipaddress
import json
import logging
import math
import os
import platform
import random
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

import requests

from utils.cloudflare_source import (
    DEFAULT_AUTOMATIC_MAX_CANDIDATES,
    CloudflareSourceError,
    expand_cloudflare_proxies,
    get_cloudflare_templates,
    validate_candidate_limit,
)


logger = logging.getLogger(__name__)

CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
GITHUB_RELEASES_API = (
    "https://api.github.com/repos/XIU2/CloudflareSpeedTest/releases/latest"
)
DEFAULT_CACHE_DIR = Path(__file__).resolve().parents[1] / ".cache" / "cloudflare-speedtest"
MAX_FEED_BYTES = 64 * 1024
MAX_RELEASE_BYTES = 2 * 1024 * 1024
MAX_ASSET_BYTES = 100 * 1024 * 1024
MAX_SAMPLE_RANGES = 512
SAMPLES_PER_NETWORK = 32
DEFAULT_MAX_CANDIDATES = DEFAULT_AUTOMATIC_MAX_CANDIDATES
CFST_SCAN_TIMEOUT_SECONDS = 180
CFST_DOWNLOAD_SECONDS = 5
CFST_MAX_DOWNLOADS = 40


def _direct_session():
    session = requests.Session()
    session.trust_env = False
    session.headers.update({
        "User-Agent": "get-subscribe/1.0",
        "Accept": "application/json,text/plain,*/*",
    })
    return session


def _read_response(response, max_bytes):
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise CloudflareSourceError("Cloudflare 响应超过大小限制")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_ipv4_networks(raw):
    networks = []
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        raise CloudflareSourceError("Cloudflare 官方 IPv4 网段列表编码无效") from None
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            continue
        if network.version == 4:
            networks.append(network)
    if not networks:
        raise CloudflareSourceError("Cloudflare 官方 IPv4 网段列表为空或格式无效")
    return networks


def fetch_cloudflare_ipv4_networks(cache_dir=DEFAULT_CACHE_DIR):
    """Fetch Cloudflare's public IPv4 ranges directly, with a local cache fallback."""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / "ips-v4.txt"
    session = _direct_session()
    response = None
    try:
        response = session.get(CLOUDFLARE_IPV4_URL, timeout=(5, 15), stream=True)
        response.raise_for_status()
        raw = _read_response(response, MAX_FEED_BYTES)
        networks = _parse_ipv4_networks(raw)
        temporary_path = cache_path.with_suffix(".tmp")
        temporary_path.write_bytes(raw)
        os.replace(temporary_path, cache_path)
        return networks
    except (requests.RequestException, OSError, CloudflareSourceError) as error:
        if cache_path.is_file():
            try:
                networks = _parse_ipv4_networks(cache_path.read_bytes())
                logger.warning(
                    "Cloudflare 官方 IP 列表暂不可达，使用本机缓存（%s）",
                    type(error).__name__,
                )
                return networks
            except (OSError, CloudflareSourceError):
                pass
        if isinstance(error, CloudflareSourceError):
            raise
        raise CloudflareSourceError(
            f"无法直连获取 Cloudflare 官方 IPv4 网段（{type(error).__name__}）"
        ) from None
    finally:
        if response is not None:
            response.close()
        session.close()


def sample_cloudflare_scan_ranges(networks, *, max_ranges=MAX_SAMPLE_RANGES,
                                  samples_per_network=SAMPLES_PER_NETWORK,
                                  rng=None):
    """Sample a bounded number of /24s so the default scan never sweeps all IPs."""
    rng = rng or random.SystemRandom()
    sampled = []
    for network in networks:
        if network.version != 4:
            continue
        if network.prefixlen <= 24:
            subnet_count = 1 << (24 - network.prefixlen)
            sample_count = min(subnet_count, samples_per_network)
            indexes = rng.sample(range(subnet_count), sample_count)
            subnets = [
                ipaddress.IPv4Network((
                    int(network.network_address) + (index << 8), 24
                ))
                for index in indexes
            ]
        else:
            subnets = [network]
        sampled.extend(subnets)
        if len(sampled) >= max_ranges:
            sampled = sampled[:max_ranges]
            break
    return [str(network) for network in sampled]


def _platform_asset_name(system=None, machine=None):
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    architecture = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "x64": "amd64",
        "i386": "386",
        "i486": "386",
        "i586": "386",
        "i686": "386",
        "x86": "386",
        "arm64": "arm64",
        "aarch64": "arm64",
    }.get(machine)
    if system == "windows" and architecture:
        return f"cfst_windows_{architecture}.zip"
    if system == "linux" and architecture in ("amd64", "386", "arm64"):
        return f"cfst_linux_{architecture}.tar.gz"
    raise CloudflareSourceError(
        f"CloudflareSpeedTest 不支持当前平台或架构（{system}/{machine}）"
    )


def _load_latest_release(cache_dir=DEFAULT_CACHE_DIR):
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = cache_dir / "latest-release.json"
    cached_release = None
    if metadata_path.is_file():
        try:
            cached_release = json.loads(metadata_path.read_text(encoding="utf-8"))
            if not isinstance(cached_release, dict) or not isinstance(cached_release.get("assets"), list):
                raise ValueError("Invalid cached release")
            if time.time() - metadata_path.stat().st_mtime < 24 * 60 * 60:
                return cached_release
        except (OSError, ValueError):
            cached_release = None

    session = _direct_session()
    response = None
    try:
        response = session.get(GITHUB_RELEASES_API, timeout=(5, 20), stream=True)
        response.raise_for_status()
        release = json.loads(_read_response(response, MAX_RELEASE_BYTES))
        if not isinstance(release, dict) or not isinstance(release.get("assets"), list):
            raise CloudflareSourceError("CloudflareSpeedTest Release 信息格式无效")
        temporary_path = metadata_path.with_suffix(".tmp")
        temporary_path.write_text(
            json.dumps(release, ensure_ascii=True), encoding="utf-8"
        )
        os.replace(temporary_path, metadata_path)
        return release
    except (requests.RequestException, OSError, ValueError, CloudflareSourceError) as error:
        if cached_release:
            logger.warning(
                "GitHub Release 暂不可达，使用已缓存版本（%s）",
                type(error).__name__,
            )
            return cached_release
        if isinstance(error, CloudflareSourceError):
            raise
        raise CloudflareSourceError(
            f"无法直连读取 CloudflareSpeedTest Release（{type(error).__name__}）"
        ) from None
    finally:
        if response is not None:
            response.close()
        session.close()


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download_asset(asset, archive_path, expected_digest):
    digest_match = re.fullmatch(r"sha256:([0-9a-fA-F]{64})", expected_digest or "")
    if digest_match is None:
        raise CloudflareSourceError("CloudflareSpeedTest Release 缺少有效 SHA-256")
    expected_digest = digest_match.group(1).lower()
    if archive_path.is_file() and _sha256_file(archive_path) == expected_digest:
        return archive_path

    session = _direct_session()
    temporary_path = archive_path.with_suffix(archive_path.suffix + ".part")
    digest = hashlib.sha256()
    total = 0
    response = None
    try:
        response = session.get(
            asset["browser_download_url"], timeout=(5, 30), stream=True
        )
        response.raise_for_status()
        with temporary_path.open("wb") as output:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_ASSET_BYTES:
                    raise CloudflareSourceError(
                        "CloudflareSpeedTest 安装包超过大小限制"
                    )
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != expected_digest:
            raise CloudflareSourceError("CloudflareSpeedTest 安装包 SHA-256 不匹配")
        os.replace(temporary_path, archive_path)
        return archive_path
    except requests.RequestException as error:
        raise CloudflareSourceError(
            f"CloudflareSpeedTest 下载失败（{type(error).__name__}）"
        ) from None
    finally:
        if response is not None:
            response.close()
        session.close()
        if temporary_path.exists():
            temporary_path.unlink()


def _extract_executable(archive_path, asset_name, version_dir):
    executable_name = "cfst.exe" if asset_name.endswith(".zip") else "cfst"
    executable_path = version_dir / executable_name
    temporary_path = executable_path.with_suffix(executable_path.suffix + ".tmp")
    try:
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(archive_path) as archive:
                members = [
                    member for member in archive.infolist()
                    if Path(member.filename).name.lower() in ("cfst.exe", "cloudflarest.exe")
                    and not member.is_dir()
                ]
                if not members:
                    raise CloudflareSourceError(
                        "CloudflareSpeedTest ZIP 中没有可执行文件"
                    )
                source = archive.open(members[0])
                with source, temporary_path.open("wb") as output:
                    shutil.copyfileobj(source, output)
        else:
            with tarfile.open(archive_path, "r:gz") as archive:
                members = [
                    member for member in archive.getmembers()
                    if Path(member.name).name.lower() == "cfst" and member.isfile()
                ]
                if not members:
                    raise CloudflareSourceError(
                        "CloudflareSpeedTest TAR 中没有可执行文件"
                    )
                source = archive.extractfile(members[0])
                if source is None:
                    raise CloudflareSourceError(
                        "CloudflareSpeedTest 可执行文件无法读取"
                    )
                with source, temporary_path.open("wb") as output:
                    shutil.copyfileobj(source, output)
        os.replace(temporary_path, executable_path)
        if os.name != "nt":
            executable_path.chmod(0o755)
        return executable_path
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise CloudflareSourceError(
            f"CloudflareSpeedTest 安装包解压失败（{type(error).__name__}）"
        ) from None
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _get_cloudflare_speedtest_binary(cache_dir=DEFAULT_CACHE_DIR):
    release = _load_latest_release(cache_dir)
    asset_name = _platform_asset_name()
    asset = next(
        (item for item in release["assets"] if item.get("name") == asset_name),
        None,
    )
    if asset is None:
        raise CloudflareSourceError(
            f"CloudflareSpeedTest Release 缺少当前平台安装包（{asset_name}）"
        )
    version = str(release.get("tag_name") or "latest")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", version):
        raise CloudflareSourceError("CloudflareSpeedTest Release 版本号无效")
    version_dir = Path(cache_dir) / version
    version_dir.mkdir(parents=True, exist_ok=True)
    archive_path = version_dir / asset_name
    archive_path = _download_asset(asset, archive_path, asset.get("digest"))
    return _extract_executable(archive_path, asset_name, version_dir)


def _sampled_subnet_text(networks, *, max_ranges=MAX_SAMPLE_RANGES,
                         samples_per_network=SAMPLES_PER_NETWORK):
    return "\n".join(sample_cloudflare_scan_ranges(
        networks,
        max_ranges=max_ranges,
        samples_per_network=samples_per_network,
    ))


def _parse_speedtest_results(raw, max_candidates):
    validate_candidate_limit(max_candidates)
    try:
        rows = csv.reader(io.StringIO(raw.decode("utf-8-sig")))
        headers = next(rows, None)
    except (UnicodeDecodeError, csv.Error):
        raise CloudflareSourceError("CloudflareSpeedTest CSV 编码或格式无效") from None
    normalized = [re.sub(r"\s+", "", value).casefold() for value in headers or []]
    ip_column = next(
        (index for index, value in enumerate(normalized)
         if value in ("ip", "ipaddress", "ip地址")),
        None,
    )
    speed_column = next(
        (index for index, value in enumerate(normalized)
         if "下载" in value or "download" in value or "speed" in value or "速度" in value),
        None,
    )
    if ip_column is None or speed_column is None:
        raise CloudflareSourceError(
            "CloudflareSpeedTest CSV 缺少 IP 地址或下载速度列"
        )

    results = {}
    try:
        for row in rows:
            if max(ip_column, speed_column) >= len(row):
                continue
            value = row[speed_column].strip()
            value = re.sub(r"\s*(?:MB/s|MiB/s)$", "", value, flags=re.IGNORECASE)
            try:
                speed = float(value)
            except ValueError:
                continue
            if not math.isfinite(speed) or speed <= 0:
                continue
            try:
                address = ipaddress.ip_address(row[ip_column].strip())
            except ValueError:
                continue
            if address.version != 4:
                continue
            results[str(address)] = max(speed, results.get(str(address), 0))
    except csv.Error:
        raise CloudflareSourceError("CloudflareSpeedTest CSV 格式无效") from None
    if not results:
        raise CloudflareSourceError("CloudflareSpeedTest 没有产出可用下载测速结果")
    ranked = sorted(results.items(), key=lambda item: (-item[1], item[0]))
    return [{"ip": address, "download_speed": speed}
            for address, speed in ranked[:max_candidates]]


def _write_diagnostic_file(diagnostics_dir, filename, raw):
    """Persist credential-free diagnostics without failing subscription generation."""
    if diagnostics_dir is None:
        return
    temporary_path = None
    try:
        directory = Path(diagnostics_dir)
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
                prefix=f".{filename}.", suffix=".tmp", dir=directory, delete=False) as output:
            temporary_path = Path(output.name)
            output.write(raw)
        os.replace(temporary_path, directory / filename)
    except OSError as error:
        logger.warning("Cloudflare 诊断文件保存失败（%s）", type(error).__name__)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def _write_diagnostic_json(diagnostics_dir, filename, data):
    _write_diagnostic_file(
        diagnostics_dir, filename,
        json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"),
    )


def _scan_parameters(max_candidates):
    download_count = min(max_candidates, CFST_MAX_DOWNLOADS)
    return {
        "port": 443,
        "concurrency": 64,
        "latency_rounds": 4,
        "max_downloads": download_count,
        "download_seconds": CFST_DOWNLOAD_SECONDS,
        "timeout_seconds": (
            CFST_SCAN_TIMEOUT_SECONDS + download_count * (CFST_DOWNLOAD_SECONDS + 10)
        ),
        "max_sample_ranges": MAX_SAMPLE_RANGES,
        "samples_per_network": SAMPLES_PER_NETWORK,
        "direct_connection": True,
    }


def _run_cloudflare_speedtest(networks, *, port, max_candidates, cache_dir,
                              diagnostics_dir, diagnostics):
    validate_candidate_limit(max_candidates)
    if port != 443:
        raise CloudflareSourceError("自动 Cloudflare 优选目前只扫描 443 端口")
    ranges_text = _sampled_subnet_text(networks)
    diagnostics["sampled_range_count"] = len(ranges_text.splitlines())
    if not ranges_text:
        raise CloudflareSourceError("没有可供 CloudflareSpeedTest 扫描的 IPv4 网段")

    executable = _get_cloudflare_speedtest_binary(cache_dir)
    parameters = diagnostics["scan_parameters"]
    download_count = parameters["max_downloads"]
    # Downloads are sequential: 40 * the upstream 10s default exceeds the old 180s total.
    scan_timeout = parameters["timeout_seconds"]
    with tempfile.TemporaryDirectory(prefix="get-subscribe-cfst-") as temporary_dir:
        input_path = Path(temporary_dir) / "ips-v4-sampled.txt"
        output_path = Path(temporary_dir) / "result.csv"
        input_path.write_text(ranges_text + "\n", encoding="ascii")
        command = [
            str(executable),
            "-f", str(input_path.resolve()),
            "-n", str(parameters["concurrency"]),
            "-t", str(parameters["latency_rounds"]),
            "-dn", str(download_count),
            "-dt", str(parameters["download_seconds"]),
            "-tp", str(port),
            "-p", "0",
            "-o", str(output_path.resolve()),
        ]
        environment = os.environ.copy()
        for key in (
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"):
            environment.pop(key, None)
        environment["NO_PROXY"] = "*"
        environment["no_proxy"] = "*"
        try:
            completed = subprocess.run(
                command,
                cwd=temporary_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=scan_timeout,
                env=environment,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CloudflareSourceError(
                f"CloudflareSpeedTest 执行失败（{type(error).__name__}）"
            ) from None
        if completed.returncode != 0:
            logger.warning("CloudflareSpeedTest 输出：%s", completed.stderr[-1000:])
            raise CloudflareSourceError(
                f"CloudflareSpeedTest 返回错误码 {completed.returncode}"
            )
        if not output_path.is_file():
            raise CloudflareSourceError("CloudflareSpeedTest 没有生成结果 CSV")
        if output_path.stat().st_size > MAX_RELEASE_BYTES:
            raise CloudflareSourceError("CloudflareSpeedTest 结果 CSV 超过大小限制")
        raw = output_path.read_bytes()
        _write_diagnostic_file(diagnostics_dir, "cloudflare_speedtest.csv", raw)
        return _parse_speedtest_results(raw, max_candidates)


def run_cloudflare_speedtest(networks, *, port=443,
                             max_candidates=DEFAULT_MAX_CANDIDATES,
                             cache_dir=DEFAULT_CACHE_DIR, diagnostics_dir=None):
    validate_candidate_limit(max_candidates)
    diagnostics = {
        "status": "failed",
        "scan_parameters": _scan_parameters(max_candidates),
        "sampled_range_count": 0,
        "speedtested_ingress_count": 0,
    }
    try:
        addresses = _run_cloudflare_speedtest(
            networks, port=port, max_candidates=max_candidates, cache_dir=cache_dir,
            diagnostics_dir=diagnostics_dir, diagnostics=diagnostics,
        )
        diagnostics["status"] = "completed"
        diagnostics["speedtested_ingress_count"] = len(addresses)
        diagnostics["ingress_results"] = addresses
        return addresses
    except Exception as error:
        diagnostics["error_type"] = type(error).__name__
        raise
    finally:
        _write_diagnostic_json(
            diagnostics_dir, "cloudflare_speedtest_diagnostics.json", diagnostics,
        )


def get_optimized_cloudflare_proxies(proxies, *, max_candidates=DEFAULT_MAX_CANDIDATES,
                                     cache_dir=DEFAULT_CACHE_DIR, diagnostics_dir=None):
    validate_candidate_limit(max_candidates)
    diagnostics = {
        "status": "failed",
        "template_count": 0,
        "speedtested_ingress_count": 0,
        "candidate_count": 0,
        "max_candidates": max_candidates,
        "scan_parameters": _scan_parameters(max_candidates),
        "candidates": [],
    }
    try:
        if not get_cloudflare_templates(proxies, limit=1):
            logger.info("采集节点中没有可复用的 VLESS/WS/TLS/443 模板")
            diagnostics["status"] = "no_reusable_template"
            return []

        networks = fetch_cloudflare_ipv4_networks(cache_dir)
        # Apply the template budget only after validating official network membership.
        templates = get_cloudflare_templates(proxies, networks)
        diagnostics["template_count"] = len(templates)
        if not templates:
            logger.info("采集节点的 VLESS 模板服务器不在 Cloudflare 官方 IPv4 网段")
            diagnostics["status"] = "no_official_template"
            return []

        addresses = run_cloudflare_speedtest(
            networks, port=443, max_candidates=max_candidates,
            cache_dir=cache_dir, diagnostics_dir=diagnostics_dir,
        )
        diagnostics["speedtested_ingress_count"] = len(addresses)
        candidates = expand_cloudflare_proxies(
            templates, addresses, max_candidates=max_candidates, networks=networks
        )
        diagnostics.update(
            status="generated", candidate_count=len(candidates),
            candidates=[{"id": proxy["name"], "ingress_ip": proxy["server"]}
                        for proxy in candidates],
        )
        logger.info("自动 Cloudflare：%d 个模板 × %d 个测速入口，生成 %d 个候选（上限 %d）",
                    len(templates), len(addresses), len(candidates), max_candidates)
        return candidates
    except Exception as error:
        diagnostics["error_type"] = type(error).__name__
        raise
    finally:
        _write_diagnostic_json(diagnostics_dir, "cloudflare_diagnostics.json", diagnostics)
