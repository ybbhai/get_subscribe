"""Local audit output without subscription URLs, proxy credentials or API keys."""

from dataclasses import asdict
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
from pathlib import Path
import tempfile

from utils.node_policy import (
    SERVICES, TIER_LABELS, meets_performance_floor, preferred_pool, proxy_source_ids, quality_tier,
)


def _observed_exit_ip(node):
    evidence = node.get("_exit_quality")
    value = evidence.get("ip") if isinstance(evidence, dict) else None
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(address) if address.is_global else None


def _exit_counts(observed, selected):
    observed_ips = [_observed_exit_ip(node) for node in observed]
    selected_ips = [_observed_exit_ip(node) for node in selected]
    return {
        "observed_unique_exit_count": len({ip for ip in observed_ips if ip is not None}),
        "selected_unique_exit_count": len({ip for ip in selected_ips if ip is not None}),
        "observed_unknown_exit_count": sum(ip is None for ip in observed_ips),
        "selected_unknown_exit_count": sum(ip is None for ip in selected_ips),
    }


def write_selection_report(measured, selected, policy, output_dir, *,
                           diagnostics=None, inspection=None):
    """Write measurement evidence and caller-sanitized pipeline/inspection summaries."""
    selected_names = {proxy["name"] for proxy in selected}
    production = (diagnostics or {}).get("profile") == "prod"
    test_input = (diagnostics or {}).get("stage_counts", {}).get("test_input", {})

    def export_eligible(node):
        return (meets_performance_floor(node, policy) and bool(node.get("_categories"))
                and (not production or node.get("_verification") == "passed"))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(), "policy": asdict(policy),
        "measured_count": len(measured), "selected_count": len(selected),
        "test_input_count": test_input.get("total", len(measured)),
        "service_passed_count": len(measured),
        "performance_eligible_count": sum(meets_performance_floor(node, policy) for node in measured),
        "export_eligible_count": sum(export_eligible(node) for node in measured),
        "verified_count": sum(node.get("_verification") == "passed" for node in measured),
        **_exit_counts(measured, selected),
        "diagnostics": diagnostics if diagnostics is not None else {},
        "inspection": inspection if inspection is not None else {},
        "groups": {}, "nodes": [], "sources": [],
    }
    source_metadata = {}
    for source in (diagnostics or {}).get("sources", []):
        if isinstance(source, dict) and isinstance(source.get("id"), str):
            source_metadata[source["id"]] = dict(source)
    for node in (*measured, *selected):
        for source in proxy_source_ids(node):
            source_metadata.setdefault(source, {"id": source})
    for source_id in sorted(source_metadata):
        observed = [node for node in measured if source_id in proxy_source_ids(node)]
        chosen = [node for node in selected if source_id in proxy_source_ids(node)]
        report["sources"].append({
            **source_metadata[source_id],
            "measured_count": len(observed),
            "test_input_count": test_input.get("by_source", {}).get(source_id, len(observed)),
            "service_passed_count": len(observed),
            "performance_eligible_count": sum(meets_performance_floor(node, policy) for node in observed),
            "verified_count": sum(node.get("_verification") == "passed" for node in observed),
            "export_eligible_count": sum(export_eligible(node) for node in observed),
            "selected_count": len(chosen),
            **_exit_counts(observed, chosen),
        })
    for service, categories in (("global", SERVICES), *((s, (s,)) for s in SERVICES)):
        pool = preferred_pool(selected, categories, policy)
        tier = quality_tier(pool[0], policy) if pool else None
        report["groups"][service] = {
            "tier": tier, "label": TIER_LABELS.get(tier, "无可用节点"),
            "nodes": [proxy["name"] for proxy in pool],
        }
    for node in measured:
        report["nodes"].append({
            "name": node["name"], "tier": quality_tier(node, policy),
            "selected": node["name"] in selected_names,
            "source": node.get("_source", "subscription"),
            "sources": proxy_source_ids(node),
            "performance_eligible": meets_performance_floor(node, policy),
            "export_eligible": export_eligible(node),
            "download_passed": node.get("_download_passed") is True,
            "service_latency_ms": node.get("_service_latency_ms", {}),
            "verification": node.get("_verification"),
            "services": sorted(node.get("_categories", [])),
            "latency_ms": node.get("_latency"), "speed_kbps": node.get("_speed_kbps"),
            "exit": node.get("_exit_quality", {"status": "unknown"}),
        })
    temporary = None
    try:
        target = Path(output_dir) / "node_selection_report.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                         prefix=".node-report-", suffix=".json", delete=False) as stream:
            temporary = stream.name
            json.dump(report, stream, ensure_ascii=False, indent=2)
        os.replace(temporary, target)
    except (OSError, TypeError, ValueError) as error:
        logging.getLogger(__name__).warning("优选报告写入失败（%s）", type(error).__name__)
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
