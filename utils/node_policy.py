"""Evidence-based exit selection; unknown reputation never implies clean."""

from dataclasses import asdict, dataclass
import math
import os
from pathlib import Path

import yaml


DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "node_policy.yaml"
SERVICES = ("google", "youtube", "chatgpt")
TIER_LABELS = {1: "优质低风险家宽候选", 2: "低风险节点", 3: "性能兜底"}


@dataclass(frozen=True)
class NodePolicy:
    max_risk_score: float = 10
    max_abuse_score: float = 0.01
    residential_min_speed_kbps: float = 5000
    residential_max_latency_ms: float = 1000
    lookup_timeout_seconds: float = 8
    max_lookups_per_round: int = 200
    min_speed_kbps: float = 0
    max_latency_ms: float = 60000


def load_node_policy(path=None, profile=None):
    defaults = NodePolicy(min_speed_kbps=5000, max_latency_ms=1500) if profile == "prod" else NodePolicy()
    path = Path(path or os.environ.get("NODE_POLICY_CONFIG") or DEFAULT_POLICY_PATH).expanduser()
    if not path.is_file():
        if path != DEFAULT_POLICY_PATH:
            raise ValueError("指定的节点优选策略文件不存在")
        return defaults
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError("节点优选策略文件无法读取") from error
    if not isinstance(data, dict) or set(data) - set(asdict(defaults)):
        raise ValueError("节点优选策略存在未知字段或格式错误")
    values = asdict(defaults)
    values.update(data)
    ranges = {
        "max_risk_score": (0, 100), "max_abuse_score": (0, 1),
        "residential_min_speed_kbps": (1, 1_000_000_000),
        "residential_max_latency_ms": (1, 60000),
        "lookup_timeout_seconds": (1, 30), "max_lookups_per_round": (1, 2000),
        "min_speed_kbps": (0, 1_000_000_000), "max_latency_ms": (0, 60000),
    }
    for key, value in values.items():
        low, high = ranges[key]
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or not low <= value <= high
                or (key == "max_lookups_per_round" and not isinstance(value, int))):
            raise ValueError(f"节点优选参数 {key} 无效，范围 {low}–{high}")
    return NodePolicy(**values)


def finite_number(value, default):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return default
    return value


def meets_performance_floor(proxy, policy=None):
    """Require measured performance before applying the reputation preference."""
    policy = policy or NodePolicy()
    latency = finite_number(proxy.get("_latency"), float("inf"))
    speed = finite_number(proxy.get("_speed_kbps"), float("-inf"))
    return (0 <= latency <= policy.max_latency_ms
            and speed >= policy.min_speed_kbps
            and (policy.min_speed_kbps <= 0 or proxy.get("_download_passed") is True))


def quality_tier(proxy, policy=None):
    policy = policy or NodePolicy()
    evidence = proxy.get("_exit_quality", {})
    if not isinstance(evidence, dict) or evidence.get("status") != "clean":
        return 3
    latency = finite_number(proxy.get("_latency"), float("inf"))
    speed = finite_number(proxy.get("_speed_kbps"), 0)
    if (evidence.get("residential") is True and proxy.get("_download_passed") is True
            and 0 <= latency <= policy.residential_max_latency_ms
            and speed >= policy.residential_min_speed_kbps):
        return 1
    return 2


def performance_key(proxy):
    latency = finite_number(proxy.get("_latency"), float("inf"))
    speed = max(0, finite_number(proxy.get("_speed_kbps"), 0))
    if latency < 0 or not math.isfinite(latency):
        return (float("inf"), 0, float("inf"))
    latency_score = 100 / (1 + latency / 500)
    speed_score = 100 * (speed / (speed + 10000))
    score = latency_score * 0.7 + speed_score * 0.3
    return (-score, -len(proxy.get("_categories", ())), latency)


def rank_proxies(proxies, policy=None):
    """Rank all measurements, including rejected ones needed by diagnostics."""
    return sorted(proxies, key=lambda proxy: (quality_tier(proxy, policy), *performance_key(proxy)))


def proxy_source_ids(proxy):
    """Return channel IDs, falling back to legacy source metadata for old nodes."""
    raw = proxy.get("_source_ids")
    sources = {value.strip() for value in raw if isinstance(value, str) and value.strip()} \
        if isinstance(raw, (list, tuple, set)) else set()
    if not sources:
        legacy = proxy.get("_source")
        sources.add(legacy.strip() if isinstance(legacy, str) and legacy.strip() else "subscription")
    return sorted(sources)


def select_inspection_candidates(proxies, limit, policy=None):
    """Allocate exit lookups by current performance with service/source coverage."""
    if limit <= 0:
        return []
    ranked = sorted(
        (proxy for proxy in proxies if meets_performance_floor(proxy, policy)),
        key=lambda proxy: (*performance_key(proxy), str(proxy.get("name", "")),
                           str(proxy.get("type", "")), str(proxy.get("server", "")),
                           str(proxy.get("port", ""))),
    )
    selected = set()
    for categories in (SERVICES, ("google",), ("youtube",), ("chatgpt",)):
        required = set(categories)
        for index, proxy in enumerate(ranked):
            if required.issubset(proxy.get("_categories", ())):
                if len(selected) < limit:
                    selected.add(index)
                break

    memberships = [proxy_source_ids(proxy) for proxy in ranked]
    by_source = {}
    for index, sources in enumerate(memberships):
        for source in sources:
            by_source.setdefault(source, []).append(index)
    source_counts = {source: sum(source in memberships[index] for index in selected)
                     for source in by_source}
    cloudflare_quota = min(10, max(1, limit // 5))
    # At most half the budget is reserved for channel diversity; shared nodes
    # count toward every channel that supplied them but consume one lookup.
    for _ in range(min(limit // 2, limit - len(selected))):
        available = []
        for source, indexes in by_source.items():
            if source == "cloudflare_auto" and source_counts[source] >= cloudflare_quota:
                continue
            next_index = next((index for index in indexes if index not in selected), None)
            if next_index is not None:
                available.append((source_counts[source], indexes[0], source, next_index))
        if not available:
            break
        _, _, _, index = min(available)
        selected.add(index)
        for source in memberships[index]:
            source_counts[source] += 1

    for index in range(len(ranked)):
        if len(selected) >= limit:
            break
        selected.add(index)
    return [proxy for index, proxy in enumerate(ranked) if index in selected]


def preferred_pool(proxies, categories, policy=None):
    required = set(categories)
    eligible = [proxy for proxy in proxies if meets_performance_floor(proxy, policy)
                and required.issubset(proxy.get("_categories", ()))]
    if not eligible:
        return []
    tier = min(quality_tier(proxy, policy) for proxy in eligible)
    return [proxy for proxy in eligible if quality_tier(proxy, policy) == tier]


def select_candidates(proxies, limit=50, policy=None):
    """Preserve each service's best tier, then fill from the union of those pools."""
    if limit <= 0:
        return []
    ranked = rank_proxies(proxies, policy)
    indexes = {id(proxy): index for index, proxy in enumerate(ranked)}
    selected = set()
    allowed = set()
    for categories in (SERVICES, ("google",), ("youtube",), ("chatgpt",)):
        pool = preferred_pool(ranked, categories, policy)
        allowed.update(indexes[id(proxy)] for proxy in pool)
        if pool and len(selected) < limit:
            selected.add(indexes[id(pool[0])])
    for index in sorted(allowed):
        if len(selected) >= limit:
            break
        selected.add(index)
    return [proxy for index, proxy in enumerate(ranked) if index in selected]
