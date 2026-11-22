"""Keep a measured proxy and its private dialer dependencies together."""

import copy
import hashlib
import json


DEPENDENCIES_KEY = "_dialer_proxies"
BUILTIN_PROXY_NAMES = frozenset({"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"})


def apply_runtime_defaults(proxy):
    """Resolve OpenVPN destinations through its tunnel without overriding user DNS."""
    result = copy.deepcopy(proxy)
    if result.get("type") == "openvpn":
        result.setdefault("remote-dns-resolve", True)
        if result.get("remote-dns-resolve") is True and (
                "dns" not in result or result["dns"] == []):
            result["dns"] = ["1.1.1.1", "8.8.8.8"]
    return result


def bind_dialer(proxy, dialer):
    """Bind one concrete route, independent of source group names and renaming."""
    dependency = copy.deepcopy(dialer)
    identity = {key: value for key, value in dependency.items()
                if key != "name" and not key.startswith("_")}
    digest = hashlib.sha256(json.dumps(
        identity, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:24]
    dependency["name"] = f"CF-DIALER-{digest}"
    result = copy.deepcopy(proxy)
    result["dialer-proxy"] = dependency["name"]
    result[DEPENDENCIES_KEY] = [dependency]
    return result


def materialize_proxies(proxies, reserved_names=()):
    """Export dependencies without making them independently selectable exits."""
    result = []
    used = {proxy["name"] for proxy in proxies} | set(reserved_names) | BUILTIN_PROXY_NAMES | {"GLOBAL"}
    dependencies = {}
    for proxy in proxies:
        node = apply_runtime_defaults({key: value for key, value in proxy.items()
                                       if not key.startswith("_")})
        for dependency in proxy.get(DEPENDENCIES_KEY, []):
            clean = apply_runtime_defaults({key: value for key, value in dependency.items()
                                            if not key.startswith("_")})
            original_name = clean["name"]
            identity = json.dumps(clean, sort_keys=True, ensure_ascii=True)
            if identity not in dependencies:
                name = original_name
                suffix = 1
                while name in used:
                    name = f"{original_name}-{suffix}"
                    suffix += 1
                used.add(name)
                clean["name"] = name
                dependencies[identity] = name
                result.append(clean)
            if node.get("dialer-proxy") == original_name:
                node["dialer-proxy"] = dependencies[identity]
        result.append(node)
    return result
