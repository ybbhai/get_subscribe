import copy
import unittest

from utils.source_tracking import proxy_source_ids, stage_counts, tag_source


class SourceTrackingTests(unittest.TestCase):
    def test_new_source_tag_does_not_invent_another_channel(self):
        original = {"name": "node"}
        tagged = tag_source(original, "paid-a", "subscription")
        self.assertEqual(tagged["_source_ids"], ["paid-a"])
        self.assertEqual(tagged["_source"], "subscription")
        self.assertEqual(original, {"name": "node"})

    def test_existing_channels_are_merged_without_mutating_input(self):
        original = {"name": "node", "_source": "rss", "_source_ids": ["rss", "paid-a"]}
        before = copy.deepcopy(original)
        tagged = tag_source(original, "paid-a", "subscription")
        self.assertEqual(tagged["_source_ids"], ["paid-a", "rss"])
        self.assertEqual(original, before)
        self.assertIsNot(tagged["_source_ids"], original["_source_ids"])

    def test_legacy_cloudflare_marker_survives_additional_channel_tags(self):
        automatic = tag_source({"name": "node", "_source": "rss"}, "cloudflare_auto", "cloudflare_auto")
        tagged = tag_source(automatic, "paid-a", "subscription")
        self.assertEqual(tagged["_source"], "cloudflare_auto")
        self.assertEqual(proxy_source_ids(tagged), ["cloudflare_auto", "paid-a", "rss"])

    def test_stage_counts_count_shared_nodes_once_per_channel(self):
        nodes = [
            {"_source": "cloudflare_auto", "_source_ids": ["cloudflare_auto", "rss", "rss"]},
            {"_source": "subscription", "_source_ids": ["rss", "paid-a"]},
            {"_source_ids": ["cloudflare_auto"]},
            {},
        ]
        self.assertEqual(stage_counts(iter(nodes)), {
            "total": 4, "cloudflare_auto": 2,
            "by_source": {"cloudflare_auto": 2, "paid-a": 1, "rss": 2, "subscription": 1},
        })
        self.assertEqual(stage_counts([]), {"total": 0, "cloudflare_auto": 0, "by_source": {}})

    def test_empty_identifiers_are_rejected(self):
        for source_id, category in ((None, "rss"), ("", "rss"), ("rss", ""), ("rss", None)):
            with self.subTest(source_id=source_id, category=category):
                with self.assertRaises(ValueError):
                    tag_source({}, source_id, category)

    def test_invalid_collection_entries_count_total_without_source_attribution(self):
        self.assertEqual(stage_counts([None, "invalid", 1, {"_source": "rss"}]),
                         {"total": 4, "cloudflare_auto": 0, "by_source": {"rss": 1}})


if __name__ == "__main__":
    unittest.main()
