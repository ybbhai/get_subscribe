import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from utils.node_policy import (
    NodePolicy, load_node_policy, meets_performance_floor, preferred_pool,
    proxy_source_ids, quality_tier, rank_proxies, select_candidates, select_inspection_candidates,
)


def node(name, status="unknown", residential=False, speed=10000, latency=100):
    return {
        "name": name,
        "_categories": {"google", "youtube", "chatgpt"},
        "_latency": latency,
        "_speed_kbps": speed,
        "_download_passed": True,
        "_exit_quality": {"status": status, "residential": residential},
    }


class PolicyDefaultsTests(unittest.TestCase):
    def test_prod_defaults_apply_even_without_a_config_file(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {"NODE_POLICY_CONFIG": ""}), \
                patch("utils.node_policy.DEFAULT_POLICY_PATH", Path(directory) / "absent.yaml"):
            ordinary = load_node_policy()
            development = load_node_policy(profile="dev")
            production = load_node_policy(profile="prod")
        self.assertEqual(ordinary, NodePolicy())
        self.assertEqual(development, ordinary)
        self.assertEqual(production.min_speed_kbps, 5000)
        self.assertEqual(production.max_latency_ms, 1500)

    def test_explicit_config_overrides_only_specified_profile_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.yaml"
            path.write_text("min_speed_kbps: 8000\n", encoding="utf-8")
            production = load_node_policy(path, profile="prod")
            self.assertEqual(production.min_speed_kbps, 8000)
            self.assertEqual(production.max_latency_ms, 1500)
            path.write_text("min_speed_kbps: 0\nmax_latency_ms: 2500\n", encoding="utf-8")
            production = load_node_policy(path, profile="prod")
            self.assertEqual(production.min_speed_kbps, 0)
            self.assertEqual(production.max_latency_ms, 2500)

    def test_invalid_performance_thresholds_are_rejected(self):
        cases = (
            {"min_speed_kbps": -1}, {"min_speed_kbps": True},
            {"min_speed_kbps": float("nan")}, {"min_speed_kbps": "5000"},
            {"max_latency_ms": -1}, {"max_latency_ms": False},
            {"max_latency_ms": float("inf")}, {"max_latency_ms": 60001},
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.yaml"
            for data in cases:
                with self.subTest(data=data):
                    path.write_text(yaml.safe_dump(data), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_node_policy(path, profile="prod")


class PerformanceEligibilityTests(unittest.TestCase):
    policy = NodePolicy(min_speed_kbps=5000, max_latency_ms=1500)

    def test_every_tier_must_pass_floor_before_export_and_group_inclusion(self):
        for status, residential, tier in (("clean", True, 1), ("clean", False, 2), ("unknown", False, 3)):
            for field, value in (("_speed_kbps", 4500), ("_latency", 1600)):
                with self.subTest(tier=tier, field=field):
                    candidate = node("candidate", status, residential)
                    self.assertEqual(quality_tier(candidate, self.policy), tier)
                    candidate[field] = value
                    self.assertFalse(meets_performance_floor(candidate, self.policy))
                    self.assertEqual(preferred_pool([candidate], ["google"], self.policy), [])
                    self.assertEqual(select_candidates([candidate], policy=self.policy), [])
                    self.assertEqual(rank_proxies([candidate], self.policy), [candidate])

    def test_invalid_or_missing_measurements_are_never_eligible(self):
        for field in ("_latency", "_speed_kbps"):
            for value in (None, True, "100", -1, float("nan"), float("inf")):
                with self.subTest(field=field, value=value):
                    candidate = node("invalid")
                    candidate[field] = value
                    self.assertFalse(meets_performance_floor(candidate, self.policy))
                    self.assertFalse(meets_performance_floor(candidate, NodePolicy()))
            candidate = node("missing")
            candidate.pop(field)
            self.assertFalse(meets_performance_floor(candidate, self.policy))

    def test_incomplete_download_cannot_meet_positive_minimum_speed(self):
        for value in (False, None, 1, "true"):
            candidate = node("incomplete")
            candidate["_download_passed"] = value
            self.assertFalse(meets_performance_floor(candidate, self.policy))
        candidate = node("legacy")
        candidate.pop("_download_passed")
        self.assertTrue(meets_performance_floor(candidate, NodePolicy()))
        self.assertFalse(meets_performance_floor(candidate, self.policy))

    def test_thresholds_are_inclusive(self):
        candidate = node("boundary", speed=5000, latency=1500)
        self.assertTrue(meets_performance_floor(candidate, self.policy))
        self.assertTrue(meets_performance_floor(node("zero-latency", latency=0), self.policy))

    def test_fast_fallback_wins_when_clean_candidates_fail_floor(self):
        slow_home = node("slow-home", "clean", True, speed=4999)
        slow_clean = node("slow-clean", "clean", latency=1501)
        fallback = node("fast-fallback", speed=20000, latency=50)
        candidates = [slow_home, slow_clean, fallback]
        self.assertEqual(select_candidates(candidates, policy=self.policy), [fallback])
        self.assertEqual(preferred_pool(candidates, ["google"], self.policy), [fallback])

    def test_service_fallback_is_independent_after_filtering(self):
        clean = node("google-clean", "clean")
        clean["_categories"] = {"google"}
        slow_clean = node("youtube-clean", "clean", speed=4500)
        slow_clean["_categories"] = {"youtube"}
        fast = node("youtube-fast")
        fast["_categories"] = {"youtube"}
        selected = select_candidates([slow_clean, fast, clean], policy=self.policy)
        self.assertEqual(selected, [clean, fast])
        self.assertEqual(preferred_pool(selected, ["google"], self.policy), [clean])
        self.assertEqual(preferred_pool(selected, ["youtube"], self.policy), [fast])


class ContinuousRankingTests(unittest.TestCase):
    def test_latency_still_contributes_above_one_second(self):
        fast = node("one-second", speed=10000, latency=1100)
        slow = node("three-seconds", speed=10100, latency=3000)
        self.assertEqual(rank_proxies([slow, fast]), [fast, slow])

    def test_speed_still_contributes_above_ten_megabits(self):
        fast = node("faster", speed=100000)
        slow = node("slower", speed=10001)
        self.assertEqual(rank_proxies([slow, fast]), [fast, slow])


class InspectionBudgetTests(unittest.TestCase):
    policy = NodePolicy(min_speed_kbps=5000, max_latency_ms=1500)

    def test_lookups_prioritize_performance_over_previous_quality(self):
        old_clean = node("old-clean", "clean", True, speed=5000, latency=1000)
        fast = node("fast", speed=20000, latency=20)
        self.assertEqual(select_inspection_candidates([old_clean, fast], 1, self.policy), [fast])

    def test_lookup_budget_excludes_nodes_failing_performance_floor(self):
        slow = node("slow-clean", "clean", speed=4999)
        slow["_source"] = "cloudflare_auto"
        incomplete = node("incomplete", speed=100000)
        incomplete["_download_passed"] = False
        fast = node("fast")
        self.assertEqual(select_inspection_candidates([slow, incomplete, fast], 20, self.policy), [fast])

    def test_each_service_and_all_service_candidate_keep_lookup_coverage(self):
        google = node("google", latency=10)
        google["_categories"] = {"google"}
        youtube = node("youtube", latency=20)
        youtube["_categories"] = {"youtube"}
        chatgpt = node("chatgpt", latency=30)
        chatgpt["_categories"] = {"chatgpt"}
        global_node = node("global", latency=1000)
        extras = [dict(google, name=f"extra-{index}", _latency=11 + index) for index in range(5)]
        result = select_inspection_candidates([*extras, global_node, youtube, chatgpt, google], 4, self.policy)
        self.assertEqual(result, [google, youtube, chatgpt, global_node])

    def test_cloudflare_reservation_is_bounded_and_still_requires_performance(self):
        ordinary = [node(f"ordinary-{index:03d}", latency=10 + index) for index in range(220)]
        cloudflare = [dict(node(f"cloudflare-{index:03d}", latency=1000 + index),
                           _source="cloudflare_auto") for index in range(20)]
        for limit, expected_count in ((5, 1), (20, 4), (100, 10)):
            with self.subTest(limit=limit):
                result = select_inspection_candidates([*ordinary, *cloudflare], limit, self.policy)
                self.assertEqual(len(result), limit)
                self.assertEqual(sum(p.get("_source") == "cloudflare_auto" for p in result), expected_count)
                self.assertTrue(all(p in result for p in cloudflare[:expected_count]))

    def test_cloudflare_coverage_already_selected_counts_toward_reservation(self):
        best = dict(node("best-cf", latency=1), _source="cloudflare_auto")
        slower_cf = dict(node("slower-cf", latency=1000), _source="cloudflare_auto")
        ordinary = [node(f"ordinary-{index}", latency=10 + index) for index in range(10)]
        result = select_inspection_candidates([slower_cf, *ordinary, best], 5, self.policy)
        self.assertIn(best, result)
        self.assertNotIn(slower_cf, result)

    def test_ties_are_independent_of_input_order(self):
        nodes = [node(name) for name in ("z", "b", "a", "y", "c")]
        forward = select_inspection_candidates(nodes, 3, self.policy)
        backward = select_inspection_candidates(list(reversed(nodes)), 3, self.policy)
        self.assertEqual(forward, backward)
        self.assertEqual([p["name"] for p in forward], ["a", "b", "c"])

    def test_small_and_empty_budgets_never_overflow(self):
        nodes = []
        for service in ("google", "youtube", "chatgpt"):
            candidate = node(service)
            candidate["_categories"] = {service}
            candidate["_source"] = "cloudflare_auto"
            nodes.append(candidate)
        for limit in (0, -1, 1, 2, 3, 4):
            with self.subTest(limit=limit):
                result = select_inspection_candidates(nodes, limit, self.policy)
                self.assertEqual(len(result), min(3, max(0, limit)))
                self.assertEqual(len({id(p) for p in result}), len(result))
        self.assertEqual(select_inspection_candidates([], 10, self.policy), [])


class SourceFairnessTests(unittest.TestCase):
    policy = NodePolicy(min_speed_kbps=5000, max_latency_ms=1500)

    def test_source_ids_prefer_channels_and_support_legacy_nodes(self):
        self.assertEqual(proxy_source_ids({"_source": "subscription", "_source_ids": ["b", "a", "b"]}), ["a", "b"])
        self.assertEqual(proxy_source_ids({"_source": "cloudflare_auto"}), ["cloudflare_auto"])
        self.assertEqual(proxy_source_ids({"_source_ids": [None, 42, ""]}), ["subscription"])

    def test_small_channels_receive_fair_lookup_share_after_service_coverage(self):
        large = [dict(node(f"large-{i}", latency=10 + i), _source_ids=["large"]) for i in range(20)]
        small_b = [dict(node(f"b-{i}", latency=1000 + i), _source_ids=["b"]) for i in range(5)]
        small_c = [dict(node(f"c-{i}", latency=1100 + i), _source_ids=["c"]) for i in range(5)]
        candidates = [*large, *small_b, *small_c]
        result = select_inspection_candidates(candidates, 10, self.policy)
        self.assertEqual(len(result), 10)
        counts = {source: sum(source in proxy_source_ids(proxy) for proxy in result)
                  for source in ("large", "b", "c")}
        self.assertEqual(counts, {"large": 6, "b": 2, "c": 2})
        self.assertEqual(result, select_inspection_candidates(list(reversed(candidates)), 10, self.policy))

    def test_channel_reservations_never_displace_more_than_half_the_budget(self):
        fast = [dict(node(f"fast-{i}", latency=10 + i), _source_ids=["large"]) for i in range(20)]
        channels = [dict(node(f"small-{i}", latency=1000 + i), _source_ids=[f"source-{i}"]) for i in range(15)]
        result = select_inspection_candidates([*fast, *channels], 10, self.policy)
        self.assertEqual(len(result), 10)
        self.assertEqual(sum(proxy in channels for proxy in result), 5)
        self.assertTrue(all(proxy in result for proxy in fast[:5]))

    def test_multi_source_node_uses_one_slot_and_covers_both_channels(self):
        fast = [dict(node(f"fast-{i}", latency=10 + i), _source_ids=["large"]) for i in range(10)]
        shared = dict(node("shared", latency=900), _source_ids=["small-a", "small-b"])
        only_a = dict(node("only-a", latency=1000), _source_ids=["small-a"])
        only_b = dict(node("only-b", latency=1100), _source_ids=["small-b"])
        result = select_inspection_candidates([*fast, shared, only_a, only_b], 4, self.policy)
        self.assertEqual(len(result), 4)
        self.assertEqual(sum(proxy is shared for proxy in result), 1)
        self.assertIn(shared, result)
        self.assertNotIn(only_a, result)
        self.assertNotIn(only_b, result)

    def test_same_exit_with_different_service_coverage_is_not_discarded(self):
        google, youtube = node("google"), node("youtube")
        google["_categories"], youtube["_categories"] = {"google"}, {"youtube"}
        for candidate in (google, youtube):
            candidate["_exit_quality"]["ip"] = "8.8.8.8"
        self.assertEqual(select_candidates([google, youtube], policy=self.policy), [google, youtube])


if __name__ == "__main__":
    unittest.main()
