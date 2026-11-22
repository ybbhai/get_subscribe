"""Bounded VPN Gate CSV/OpenVPN import; source labels are never risk evidence."""

import asyncio
import base64
import binascii
import copy
import csv
import hashlib
import io
import ipaddress
import json
import math
import re
import shlex
import ssl
import time
from urllib.parse import urlsplit

import aiohttp
from requests.utils import get_environ_proxies, select_proxy


DEFAULT_VPNGATE_URL = "https://www.vpngate.net/api/iphone/"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 96 * 1024
MAX_ROWS = 2000
MAX_REMOTES = 4
CSV_HEADER = (
    "HostName", "IP", "Score", "Ping", "Speed", "CountryLong", "CountryShort",
    "NumVpnSessions", "Uptime", "TotalUsers", "TotalTraffic", "LogType",
    "Operator", "Message", "OpenVPN_ConfigData_Base64",
)
CIPHERS = {"AES-128-GCM", "AES-256-GCM", "AES-128-CBC", "AES-256-CBC", "CHACHA20-POLY1305"}
AUTH = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}
INLINE_FIELDS = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "auth-user-pass"}


class VPNGateSourceError(ValueError):
    """Only fixed reason codes are allowed in messages and diagnostics."""


def _reject(reason):
    raise VPNGateSourceError(reason)


def _public_ip(value):
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        address = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None
    return str(address) if address.is_global else None


def _integer(value, minimum=0, maximum=2 ** 63 - 1):
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        _reject("invalid_number")
    number = int(value)
    if not minimum <= number <= maximum:
        _reject("invalid_number")
    return number


def _pem(value, labels):
    for label in labels:
        match = re.fullmatch(r"-----BEGIN " + re.escape(label) + r"-----\s+"
                             r"([A-Za-z0-9+/=\s]+)\s+-----END " + re.escape(label) + r"-----", value)
        if match:
            try:
                if base64.b64decode(re.sub(r"\s", "", match[1]), validate=True):
                    return value + "\n"
            except (ValueError, binascii.Error):
                pass
    _reject("invalid_inline_credential")


def _protocol(value):
    mapping = {"tcp": "tcp", "tcp-client": "tcp", "tcp4-client": "tcp",
               "tcp6-client": "tcp", "udp": "udp", "udp4": "udp", "udp6": "udp"}
    if value not in mapping:
        _reject("unsupported_protocol")
    return mapping[value]


def _remote_address(host, advertised_ip, hostname):
    address = _public_ip(host)
    if address:
        return address
    # The official CSV supplies a public IP for its opengw.net alias. Pin that
    # address instead of resolving arbitrary feed-controlled domains at runtime.
    alias = str(hostname or "").lower().rstrip(".")
    if not alias.endswith(".opengw.net"):
        alias += ".opengw.net"
    if (re.fullmatch(r"[a-z0-9-]+\.opengw\.net", alias)
            and host.lower().rstrip(".") == alias and _public_ip(advertised_ip)):
        return _public_ip(advertised_ip)
    _reject("unsafe_remote")


def parse_openvpn(config, *, advertised_ip=None, hostname=None):
    """Convert a supported profile into independent, bounded remote candidates.

    Scripts, external files, arbitrary routing and unsupported TLS verification
    options are rejected instead of silently changing their security semantics.
    """
    if not isinstance(config, str) or len(config.encode("utf-8")) > MAX_CONFIG_BYTES:
        _reject("config_limit")
    if "\x00" in config or len(config.splitlines()) > 2000:
        _reject("invalid_config")
    directives, inline = {}, {}
    remotes = []
    lines = iter(config.splitlines())
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("<"):
            match = re.fullmatch(r"<([a-z-]+)>", line)
            if not match or match[1] not in INLINE_FIELDS or match[1] in inline:
                _reject("unsupported_inline_block")
            key = match[1]
            body = []
            for raw in lines:
                if raw.strip() == f"</{key}>":
                    break
                if raw.strip().startswith("<"):
                    _reject("invalid_inline_block")
                body.append(raw)
            else:
                _reject("unterminated_inline_block")
            inline[key] = "\n".join(body).strip()
            continue
        try:
            lexer = shlex.shlex(line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#;"
            tokens = list(lexer)
        except ValueError:
            _reject("invalid_directive")
        if not tokens:
            continue
        key, args = tokens[0], tokens[1:]
        if key == "remote":
            if not 1 <= len(args) <= 3 or len(remotes) >= MAX_REMOTES:
                _reject("remote_limit_or_format")
            remotes.append(args)
        elif key in directives:
            _reject("duplicate_directive")
        else:
            directives[key] = args

    result = {"type": "openvpn", "dev": "tun", "handshake-timeout": 30}
    inert_flags = {"client", "nobind", "persist-key", "persist-tun", "pull", "tls-client", "auth-nocache"}
    for key, args in directives.items():
        if key in inert_flags:
            if args:
                _reject("invalid_directive")
        elif key in {"verb", "mute"}:
            if len(args) != 1:
                _reject("invalid_directive")
            _integer(args[0], maximum=1000000)
        elif key == "resolv-retry":
            if len(args) != 1 or (args[0] != "infinite" and not args[0].isdecimal()):
                _reject("invalid_directive")
        elif key == "dev":
            if args != ["tun"]:
                _reject("unsupported_device")
        elif key in {"proto", "port"}:
            if len(args) != 1:
                _reject("invalid_directive")
        elif key in {"cipher", "data-ciphers-fallback", "auth", "comp-lzo", "key-direction"}:
            if not args and key == "comp-lzo":
                args = ["adaptive"]
            allowed = (AUTH if key == "auth" else {"yes", "no", "adaptive"} if key == "comp-lzo"
                       else {"0", "1"} if key == "key-direction" else CIPHERS)
            if len(args) != 1 or args[0] not in allowed:
                _reject("unsupported_crypto_option")
            if key == "key-direction" and key in result and result[key] != args[0]:
                _reject("invalid_key_direction")
            result[key] = args[0]
        elif key == "data-ciphers":
            if len(args) != 1 or not args[0] or any(c not in CIPHERS for c in args[0].split(":")):
                _reject("unsupported_crypto_option")
            result[key] = list(dict.fromkeys(args[0].split(":")))
        elif key in {"ping", "ping-restart", "tran-window", "handshake-timeout", "tun-mtu"}:
            if len(args) != 1:
                _reject("invalid_directive")
            result["mtu" if key == "tun-mtu" else key] = _integer(args[0], maximum=86400)
        elif key in INLINE_FIELDS:
            if key == "auth-user-pass" and not args:
                continue
            if (not args or args[0] != "[inline]" or key not in inline
                    or len(args) > (2 if key == "tls-auth" else 1)):
                _reject("external_credential_file")
            if key == "tls-auth" and len(args) == 2:
                if args[1] not in ("0", "1") or ("key-direction" in result and result["key-direction"] != args[1]):
                    _reject("invalid_key_direction")
                result["key-direction"] = args[1]
        else:
            _reject("unsupported_directive")
    if not remotes or "client" not in directives and not {"tls-client", "pull"}.issubset(directives):
        _reject("not_client_profile")
    if "ca" not in inline:
        _reject("missing_ca")
    result["ca"] = _pem(inline["ca"], ("CERTIFICATE",))
    has_pair = "cert" in inline and "key" in inline
    if ("cert" in inline) != ("key" in inline):
        _reject("incomplete_client_certificate")
    if has_pair:
        result["cert"] = _pem(inline["cert"], ("CERTIFICATE",))
        result["key"] = _pem(inline["key"], ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"))
    if "auth-user-pass" in inline:
        if inline["auth-user-pass"].split() != ["vpn", "vpn"]:
            _reject("unsupported_user_credentials")
    if "auth-user-pass" in directives or "auth-user-pass" in inline:
        result.update(username="vpn", password="vpn")
    elif not has_pair:
        _reject("missing_authentication")
    tls_fields = set(inline) & {"tls-auth", "tls-crypt", "tls-crypt-v2"}
    if len(tls_fields) > 1 or "key-direction" in result and "tls-auth" not in inline:
        _reject("conflicting_tls_keys")
    for field in tls_fields:
        value = inline[field]
        if field == "tls-crypt-v2":
            result[field] = _pem(value, ("OpenVPN tls-crypt-v2 client key",))
        else:
            cleaned = "\n".join(line for line in value.splitlines() if not line.lstrip().startswith("#"))
            match = re.fullmatch(r"-----BEGIN OpenVPN Static key V1-----\s+([0-9a-fA-F\s]+)\s+"
                                 r"-----END OpenVPN Static key V1-----", cleaned)
            if not match or len(re.sub(r"\s", "", match[1])) != 512:
                _reject("invalid_tls_key")
            result[field] = value + "\n"
    # OpenVPN's legacy auth default is SHA1; Mihomo defaults to SHA256.
    result.setdefault("auth", "SHA1")
    if "cipher" not in result and "data-ciphers" not in result:
        _reject("ambiguous_cipher_defaults")
    default_proto = directives.get("proto", ["udp"])[0]
    default_port = directives.get("port", ["1194"])[0]
    _protocol(default_proto)
    _integer(default_port, 1, 65535)
    candidates = []
    for remote in remotes:
        host = _remote_address(remote[0], advertised_ip, hostname)
        port = _integer(remote[1] if len(remote) >= 2 else default_port, 1, 65535)
        protocol = remote[2] if len(remote) == 3 else default_proto
        family = ipaddress.ip_address(host).version
        if ("4" in protocol and family != 4) or ("6" in protocol and family != 6):
            _reject("remote_family_mismatch")
        node = copy.deepcopy(result)
        node.update(server=host, port=port, proto=_protocol(protocol), udp=_protocol(protocol) == "udp")
        candidates.append(node)
    return candidates


def _parse_csv(raw, diagnostics):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        _reject("invalid_utf8")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "*vpn_servers":
        _reject("invalid_csv_marker")
    reader = csv.reader(io.StringIO("\n".join(lines[1:])), strict=True)
    try:
        header = next(reader)
        if not header or header[0] != "#HostName" or tuple([header[0][1:], *header[1:]]) != CSV_HEADER:
            _reject("invalid_csv_header")
        candidates = []
        for row in reader:
            if not row:
                continue
            if row == ["*"]:
                break
            diagnostics["fetched"] += 1
            if diagnostics["fetched"] > MAX_ROWS:
                _reject("row_limit")
            try:
                if len(row) != len(CSV_HEADER):
                    _reject("invalid_csv_row")
                record = dict(zip(CSV_HEADER, row))
                if not _public_ip(record["IP"]):
                    _reject("unsafe_advertised_ip")
                encoded = record["OpenVPN_ConfigData_Base64"]
                if len(encoded) > MAX_CONFIG_BYTES * 4 // 3 + 4:
                    _reject("config_limit")
                config = base64.b64decode(encoded, validate=True).decode("utf-8-sig")
                nodes = parse_openvpn(config, advertised_ip=record["IP"], hostname=record["HostName"])
                score = _integer(record["Score"])
                ping = _integer(record["Ping"]) if record["Ping"].isdecimal() else math.inf
                country = record["CountryShort"] if re.fullmatch(r"[A-Z]{2}", record["CountryShort"]) else "XX"
            except (VPNGateSourceError, ValueError, UnicodeError, binascii.Error):
                diagnostics["rejected"] += 1
                continue
            diagnostics["parsed"] += 1
            for node in nodes:
                identity = json.dumps(node, sort_keys=True, separators=(",", ":"))
                digest = hashlib.sha256(identity.encode()).hexdigest()
                node.update(name=f"VPNGate-{country}-{digest[:12]}", _source="vpngate", _source_ids=["vpngate"])
                candidates.append(((-score, ping, digest), digest, node))
    except (csv.Error, StopIteration):
        _reject("invalid_csv")
    unique = {}
    for rank, identity, node in sorted(candidates, key=lambda item: item[0]):
        unique.setdefault(identity, node)
    diagnostics["unique"] = len(unique)
    return list(unique.values())


def _session_options(session, url):
    proxies = get_environ_proxies(url) if getattr(session, "trust_env", False) else {}
    proxies.update(dict(getattr(session, "proxies", {}) or {}))
    proxy = select_proxy(url, proxies)
    if proxy and urlsplit(proxy).scheme not in ("http", "https"):
        _reject("unsupported_collection_proxy")
    headers = dict(getattr(session, "headers", {}) or {})
    headers["Accept-Encoding"] = "identity"
    verify = getattr(session, "verify", True)
    if verify is False:
        _reject("insecure_collection_session")
    context = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    return proxy, headers, context


async def _fetch_source(session, url, total_timeout, connect_timeout, read_timeout):
    proxy, headers, context = _session_options(session, url)
    deadline = aiohttp.ClientTimeout(total=total_timeout, connect=min(connect_timeout, total_timeout),
                                     sock_read=min(read_timeout, total_timeout), ceil_threshold=math.inf)
    async with aiohttp.ClientSession(headers=headers, trust_env=False, timeout=deadline,
                                     auto_decompress=False) as client:
        async with client.get(url, proxy=proxy, ssl=context, allow_redirects=False) as response:
            if response.status != 200:
                _reject("source_http_error")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                _reject("unsupported_content_encoding")
            if response.content_length is not None and response.content_length > MAX_SOURCE_BYTES:
                _reject("source_size_limit")
            body = bytearray()
            async for chunk in response.content.iter_chunked(8192):
                if len(body) + len(chunk) > MAX_SOURCE_BYTES:
                    _reject("source_size_limit")
                body.extend(chunk)
            return bytes(body)


def get_vpngate_proxies(session, *, max_candidates=100, api_url=DEFAULT_VPNGATE_URL,
                       mirror_urls=(), timeout=(5, 15), diagnostics=None):
    """Fetch one usable source with mirror fallback and a shared total deadline.

    The requests session's selected proxy, headers and CA setting are preserved.
    aiohttp provides cancellable total deadlines, including headers and body.
    Reports contain counts and fixed errors only, never URLs or key material.
    """
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or not 1 <= max_candidates <= 500:
        _reject("invalid_candidate_limit")
    if (not isinstance(timeout, (tuple, list)) or len(timeout) != 2
            or any(isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t) or not 0 < t <= 120 for t in timeout)):
        _reject("invalid_timeout")
    if not isinstance(mirror_urls, (tuple, list)) or len(mirror_urls) > 3:
        _reject("invalid_mirror_list")
    info = diagnostics if diagnostics is not None else {}
    info.update(fetched=0, parsed=0, rejected=0, unique=0, selected=0, status="unavailable", error_type=None)
    expires = time.monotonic() + sum(timeout)
    last_error = "empty_source"
    for url in dict.fromkeys([api_url, *mirror_urls]):
        try:
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
                _reject("invalid_source_url")
            remaining = expires - time.monotonic()
            if remaining <= 0:
                _reject("source_timeout")
            raw = asyncio.run(_fetch_source(session, url, remaining, *timeout))
            attempt = {"fetched": 0, "parsed": 0, "rejected": 0, "unique": 0}
            nodes = _parse_csv(raw, attempt)
            info.update(attempt)
            if not nodes:
                _reject("empty_source")
            selected = nodes[:max_candidates]
            info.update(selected=len(selected), status="ok", error_type=None)
            return selected
        except VPNGateSourceError as error:
            last_error = str(error)
        except (asyncio.TimeoutError, TimeoutError):
            last_error = "source_timeout"
        except (aiohttp.ClientError, OSError, ValueError, TypeError):
            last_error = "source_transport_error"
    info["error_type"] = last_error
    return []
