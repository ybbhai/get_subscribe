"""Shared channel provenance and pipeline counts for subscription collectors."""

from utils.node_policy import proxy_source_ids


def source_proxy_name(proxy, base_name=None, collision=0):
    """Keep the CF source suffix last, including after name disambiguation."""
    name = str(base_name if base_name is not None else proxy.get("name") or "proxy")
    cloudflare_sources = {"cloudflare_auto", "cloudflare_subscription", "cloudflare_legacy"}
    is_cloudflare = (proxy.get("_source") in cloudflare_sources
                    or bool(cloudflare_sources.intersection(proxy_source_ids(proxy))))
    if is_cloudflare and name.endswith("-cf"):
        name = name[:-3]
    return name + (f"-{collision}" if collision else "") + ("-cf" if is_cloudflare else "")


def tag_source(proxy, source_id, category):
    """Copy a node and merge its channel membership without losing CF provenance."""
    if not isinstance(source_id, str) or not source_id.strip():
        raise ValueError("来源 ID 必须是非空字符串")
    if not isinstance(category, str) or not category.strip():
        raise ValueError("来源分类必须是非空字符串")
    tagged = dict(proxy)
    sources = set(proxy_source_ids(proxy)) if proxy.get("_source_ids") or proxy.get("_source") else set()
    sources.add(source_id.strip())
    tagged["_source_ids"] = sorted(sources)
    if proxy.get("_source") == "cloudflare_auto" or category.strip() == "cloudflare_auto":
        tagged["_source"] = "cloudflare_auto"
    else:
        tagged["_source"] = category.strip()
    tagged["name"] = source_proxy_name(tagged)
    return tagged


def stage_counts(proxies):
    """Count each node once overall and once for every channel that supplied it."""
    total = 0
    cloudflare_auto = 0
    by_source = {}
    for proxy in proxies or []:
        total += 1
        if not isinstance(proxy, dict):
            continue
        sources = proxy_source_ids(proxy)
        cloudflare_auto += proxy.get("_source") == "cloudflare_auto" or "cloudflare_auto" in sources
        for source in sources:
            by_source[source] = by_source.get(source, 0) + 1
    return {"total": total, "cloudflare_auto": cloudflare_auto, "by_source": dict(sorted(by_source.items()))}


__all__ = ["proxy_source_ids", "source_proxy_name", "tag_source", "stage_counts"]
