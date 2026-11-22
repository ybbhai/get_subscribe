"""Validated, portable configuration for Cloudflare and VPN Gate sources."""

import copy
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

import yaml

from utils.cloudflare_source import (
    DEFAULT_AUTOMATIC_MAX_CANDIDATES,
    DEFAULT_MAX_CANDIDATES,
    validate_candidate_limit,
)

DEFAULT_CLOUDFLARE_CONFIG = Path(__file__).resolve().parents[1] / "config" / "cloudflare.yaml"
DEFAULT_MAX_TOTAL_CANDIDATES = 500
MAX_TOTAL_CANDIDATES = 2000
MAX_CONFIGURED_SOURCES = 32
RESERVED_SOURCE_IDS = {
    "rss", "clash_subscriptions", "cloudflare_auto", "vpngate", "cloudflare_legacy",
}
SUBSCRIPTION_FIELDS = {
    "subscription_file", "subscription_url", "addresses_file", "addresses_format",
    "template_index", "max_candidates",
}
CONFIG_FIELDS = SUBSCRIPTION_FIELDS | {
    "automatic_enabled", "automatic_max_candidates", "max_total_candidates", "sources", "vpngate",
}


def _absolute_path(value, base_dir):
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _validate_url(value, label, schemes):
    if (not isinstance(value, str) or not value or value != value.strip()
            or any(char.isspace() or ord(char) < 32 for char in value)):
        raise ValueError(f"{label} 格式无效")
    try:
        parsed = urlsplit(value)
        parsed.port
        valid = (parsed.scheme.lower() in schemes and parsed.hostname
                 and not parsed.username and not parsed.password)
    except ValueError:
        valid = False
    if not valid:
        allowed = "HTTPS" if schemes == {"https"} else "HTTP(S)"
        raise ValueError(f"{label} 必须是有效的 {allowed} 地址")
    return value


def _file_setting(value):
    if value is None or value == "":
        return None
    if not isinstance(value, (str, os.PathLike)):
        raise ValueError("Cloudflare 文件路径格式无效")
    value = os.fspath(value)
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        raise ValueError("Cloudflare 文件路径格式无效")
    return value


def _validate_subscription(source, *, required):
    subscription_file = _file_setting(source.get("subscription_file"))
    subscription_url = source.get("subscription_url")
    addresses_file = _file_setting(source.get("addresses_file"))
    if subscription_url is not None:
        subscription_url = _validate_url(subscription_url, "Cloudflare 订阅 URL", {"https"})
    has_subscription = bool(subscription_file or subscription_url)
    if (subscription_file and subscription_url) or (required and not has_subscription):
        raise ValueError("Cloudflare 配置必须且只能设置订阅文件或订阅 URL")
    if not has_subscription and addresses_file:
        raise ValueError("Cloudflare 地址文件需要订阅文件或 URL")

    addresses_format = source.get("addresses_format", "addresses")
    if addresses_format not in ("addresses", "cloudflare-speedtest-csv"):
        raise ValueError("Cloudflare 地址文件格式无效")

    template_index = source.get("template_index", 1)
    max_candidates = source.get("max_candidates", DEFAULT_MAX_CANDIDATES)
    if (isinstance(template_index, bool) or not isinstance(template_index, int)
            or template_index < 1):
        raise ValueError("Cloudflare 模板序号必须是大于等于 1 的整数")
    validate_candidate_limit(max_candidates)

    return {
        "subscription_file": subscription_file,
        "subscription_url": subscription_url,
        "addresses_file": addresses_file,
        "addresses_format": addresses_format,
        "template_index": template_index,
        "max_candidates": max_candidates,
    }


def _validate_vpngate(value):
    fields = {"enabled", "max_candidates", "api_url", "mirror_urls"}
    if not isinstance(value, dict) or set(value) - fields:
        raise ValueError("VPN Gate 配置格式无效或包含未知字段")
    result = {"max_candidates": value.get("max_candidates", 100)}
    validate_candidate_limit(result["max_candidates"])
    if "enabled" in value:
        if not isinstance(value["enabled"], bool):
            raise ValueError("VPN Gate 开关必须为布尔值")
        result["enabled"] = value["enabled"]
    if "api_url" in value:
        result["api_url"] = _validate_url(value["api_url"], "VPN Gate API URL", {"http", "https"})
    if "mirror_urls" in value:
        mirrors = value["mirror_urls"]
        if not isinstance(mirrors, list) or len(mirrors) > 3:
            raise ValueError("VPN Gate mirror_urls 必须是最多 3 个地址的列表")
        result["mirror_urls"] = [
            _validate_url(url, "VPN Gate 镜像 URL", {"http", "https"}) for url in mirrors
        ]
    return result


def _validate_source(source):
    """Normalize legacy settings and the multi-source schema without choosing an environment."""
    if not isinstance(source, dict) or set(source) - CONFIG_FIELDS:
        raise ValueError("Cloudflare 配置格式无效或包含未知字段")
    result = _validate_subscription(source, required=False)
    automatic_enabled = source.get("automatic_enabled", True)
    if not isinstance(automatic_enabled, bool):
        raise ValueError("Cloudflare 自动优选开关必须为布尔值")
    automatic_max_candidates = source.get("automatic_max_candidates", DEFAULT_AUTOMATIC_MAX_CANDIDATES)
    validate_candidate_limit(automatic_max_candidates)
    total = source.get("max_total_candidates", DEFAULT_MAX_TOTAL_CANDIDATES)
    if isinstance(total, bool) or not isinstance(total, int) or not 1 <= total <= MAX_TOTAL_CANDIDATES:
        raise ValueError("max_total_candidates 必须为 1–2000 的整数")
    sources = source.get("sources", [])
    if not isinstance(sources, list) or len(sources) > MAX_CONFIGURED_SOURCES:
        raise ValueError("Cloudflare sources 必须是最多 32 个来源的列表")
    validated_sources = []
    ids = set()
    for item in sources:
        if not isinstance(item, dict) or set(item) - (SUBSCRIPTION_FIELDS | {"id", "enabled"}):
            raise ValueError("Cloudflare 来源格式无效或包含未知字段")
        identifier = item.get("id")
        if (not isinstance(identifier, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", identifier)
                or identifier.casefold() in RESERVED_SOURCE_IDS):
            raise ValueError("Cloudflare 来源 id 必须是 1–64 位字母、数字、下划线或连字符，且不能使用内置来源名称")
        if identifier.casefold() in ids:
            raise ValueError("Cloudflare 来源 id 重复")
        ids.add(identifier.casefold())
        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("Cloudflare 来源 enabled 必须为布尔值")
        validated_sources.append({"id": identifier, "enabled": enabled,
                                  **_validate_subscription(item, required=True)})
    result.update(automatic_enabled=automatic_enabled,
                  automatic_max_candidates=automatic_max_candidates,
                  max_total_candidates=total, sources=validated_sources)
    if "vpngate" in source:
        result["vpngate"] = _validate_vpngate(source["vpngate"])
    return result


def _resolve_paths(source, base_dir, *, stored_relative_to=None, check_exists=True):
    for item in (source, *source["sources"]):
        for key in ("subscription_file", "addresses_file"):
            value = item.get(key)
            if not value:
                continue
            path = _absolute_path(value, base_dir)
            # Disabled local sources may be placeholders on another machine.
            if check_exists and item.get("enabled", True) and not path.is_file():
                raise ValueError(f"Cloudflare 文件不存在或不可读: {path}")
            item[key] = str(path)
            if stored_relative_to is not None:
                try:
                    item[key] = Path(os.path.relpath(path, stored_relative_to)).as_posix()
                except ValueError:
                    # Windows files on a different drive cannot use a relative path.
                    pass
    return source


def save_cloudflare_config(source, config_path=DEFAULT_CLOUDFLARE_CONFIG):
    """Persist source settings with file paths relative to the config file."""
    config_path = Path(config_path).expanduser().resolve()
    config_dir = config_path.parent
    config_dir.mkdir(parents=True, exist_ok=True)
    if not isinstance(source, dict):
        raise ValueError("Cloudflare 配置格式无效")
    # Existing paths are resolved against their config before applying CLI paths from cwd.
    merged = _read_cloudflare_config(config_path, check_exists=False) or {}
    updates = copy.deepcopy(source)
    if updates.get("subscription_file") and not updates.get("subscription_url"):
        merged["subscription_url"] = None
    elif updates.get("subscription_url") and not updates.get("subscription_file"):
        merged["subscription_file"] = None
    if isinstance(updates.get("vpngate"), dict) and isinstance(merged.get("vpngate"), dict):
        updates["vpngate"] = {**merged["vpngate"], **updates["vpngate"]}
    if "automatic_max_candidates" not in updates and "max_candidates" in updates:
        updates["automatic_max_candidates"] = updates["max_candidates"]
    merged.update(updates)
    validated = _resolve_paths(_validate_source(merged), Path.cwd(), stored_relative_to=config_dir)

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", delete=False,
                dir=str(config_dir), prefix=".cloudflare-", suffix=".yaml") as output:
            temporary_path = output.name
            yaml.safe_dump(validated, output, allow_unicode=True, sort_keys=False)
        os.replace(temporary_path, config_path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)
    return config_path


def _read_cloudflare_config(config_path, *, check_exists):
    """Validate saved structure before resolving paths for loading or updating."""
    config_path = Path(config_path).expanduser().resolve()
    if not config_path.exists():
        return None
    try:
        with config_path.open("r", encoding="utf-8") as source_file:
            source = yaml.safe_load(source_file)
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(f"Cloudflare 配置无法读取: {config_path}") from error

    if not isinstance(source, dict):
        raise ValueError(f"Cloudflare 配置内容无效: {config_path}")
    return _resolve_paths(_validate_source(source), config_path.parent, check_exists=check_exists)


def load_cloudflare_config(config_path=DEFAULT_CLOUDFLARE_CONFIG):
    """Validate settings; let collection isolate unreadable files to their own source."""
    return _read_cloudflare_config(config_path, check_exists=False)
