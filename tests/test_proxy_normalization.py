import copy
import unittest

from utils.clash_manager import _normalize_proxies


def node(name="subscription"):
    return {
        "name": name, "type": "vless", "server": "104.16.0.1", "port": 443,
        "uuid": "11111111-1111-4111-8111-111111111111", "network": "ws",
        "tls": True, "servername": "worker.example",
        "ws-opts": {"path": "/", "headers": {"Host": "worker.example"}},
    }


class ProxyNormalizationTests(unittest.TestCase):
    def test_source_metadata_does_not_duplicate_transport_and_preserves_cf_identity(self):
        ordinary = node()
        automatic = dict(node("CF-Auto-001"), _source="cloudflare_auto",
                         _cloudflare_candidate_id="candidate-1")
        for inputs in ([ordinary, automatic], [automatic, ordinary]):
            with self.subTest(first=inputs[0]["name"]):
                before = copy.deepcopy(inputs)
                result = _normalize_proxies(inputs)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["name"], inputs[0]["name"] + "-cf")
                self.assertEqual(_normalize_proxies(result), result)
                self.assertEqual(result[0]["_source"], "cloudflare_auto")
                self.assertEqual(result[0]["_cloudflare_candidate_id"], "candidate-1")
                self.assertEqual(inputs, before)

    def test_differing_candidate_ids_do_not_create_duplicate_nodes(self):
        first = dict(node("first"), _source="cloudflare_auto", _cloudflare_candidate_id="candidate-1")
        second = dict(node("second"), _source="cloudflare_auto", _cloudflare_candidate_id="candidate-2")
        result = _normalize_proxies([first, second])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["_source"], "cloudflare_auto")
        self.assertIn(result[0]["_cloudflare_candidate_id"], {"candidate-1", "candidate-2"})

    def test_non_cloudflare_source_cannot_replace_cf_provenance(self):
        automatic = dict(node(), _source="cloudflare_auto", _cloudflare_candidate_id="candidate-1")
        manual = dict(node(), _source="subscription")
        for inputs in ([automatic, manual], [manual, automatic]):
            result = _normalize_proxies(inputs)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["_source"], "cloudflare_auto")
            self.assertEqual(result[0]["_cloudflare_candidate_id"], "candidate-1")

    def test_different_measured_service_coverage_remains_separate(self):
        google = dict(node("same"), _categories={"google"})
        youtube = dict(node("same"), _categories={"youtube"}, _source="cloudflare_auto")
        result = _normalize_proxies([google, youtube])
        self.assertEqual(len(result), 2)
        self.assertEqual([proxy["name"] for proxy in result], ["same", "same-cf"])
        self.assertEqual([proxy["_categories"] for proxy in result], [{"google"}, {"youtube"}])

    def test_performance_and_reputation_differences_still_distinguish_measurements(self):
        for field, first_value, second_value in (
            ("_latency", 100, 1000), ("_http_latency", 200, 2000),
            ("_speed_kbps", 5000, 20000), ("_download_passed", True, False),
            ("_exit_quality", {"status": "clean"}, {"status": "unknown"}),
        ):
            with self.subTest(field=field):
                first, second = node(), node()
                first[field], second[field] = first_value, second_value
                second["_source"] = "cloudflare_auto"
                self.assertEqual(len(_normalize_proxies([first, second])), 2)

    def test_dialer_dependencies_remain_part_of_transport_identity(self):
        first, second = node(), node()
        first["dialer-proxy"] = second["dialer-proxy"] = "front"
        first["_dialer_proxies"] = [{"name": "front", "type": "socks5", "server": "front-a.example", "port": 1080}]
        second["_dialer_proxies"] = [{"name": "front", "type": "socks5", "server": "front-b.example", "port": 1080}]
        second["_source"] = "cloudflare_auto"
        result = _normalize_proxies([first, second])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["_dialer_proxies"], first["_dialer_proxies"])
        self.assertEqual(result[1]["_dialer_proxies"], second["_dialer_proxies"])

    def test_only_known_diagnostic_fields_are_ignored(self):
        first = dict(node(), _other_private_field="a")
        second = dict(node(), _other_private_field="b")
        self.assertEqual(len(_normalize_proxies([first, second])), 2)

    def test_equivalent_category_sets_still_deduplicate(self):
        first = dict(node(), _categories=set(["youtube", "google"]))
        second = dict(node("other"), _categories=set(["google", "youtube"]),
                      _source="cloudflare_auto", _cloudflare_candidate_id="candidate-1")
        result = _normalize_proxies([first, second])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["_categories"], {"google", "youtube"})
        self.assertEqual(result[0]["_cloudflare_candidate_id"], "candidate-1")

    def test_duplicate_transports_merge_source_ids_without_mutating_inputs(self):
        first = dict(node("rss-node"), _source="rss", _source_ids=["rss", "paid-a"])
        for category in ("cloudflare_auto", "cloudflare_subscription"):
            second = dict(node("CF-node"), _source=category, _source_ids=["custom-worker"])
            for inputs in ([first, second], [second, first]):
                before = copy.deepcopy(inputs)
                result = _normalize_proxies(inputs)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["_source_ids"], ["custom-worker", "paid-a", "rss"])
                self.assertEqual(result[0]["_source"], category)
                self.assertEqual(result[0]["name"], inputs[0]["name"] + "-cf")
                self.assertEqual(inputs, before)
                # A different route with the same display name keeps -cf last.
                other = dict(result[0], port=8443)
                unique = _normalize_proxies([*result, other])
                self.assertEqual(unique[1]["name"], inputs[0]["name"] + "-1-cf")
                self.assertEqual(_normalize_proxies(unique), unique)

    def test_legacy_and_new_source_provenance_merge(self):
        legacy = dict(node(), _source="rss")
        current = dict(node(), _source="subscription", _source_ids=["my-channel"])
        result = _normalize_proxies([legacy, current])
        self.assertEqual(result[0]["_source_ids"], ["my-channel", "rss"])

    def test_source_lists_do_not_merge_different_service_measurements(self):
        first = dict(node(), _source_ids=["rss"], _categories={"google"})
        second = dict(node(), _source_ids=["cloudflare_auto"], _categories={"youtube"})
        result = _normalize_proxies([first, second])
        self.assertEqual(len(result), 2)
        self.assertEqual([proxy["_source_ids"] for proxy in result], [["rss"], ["cloudflare_auto"]])


if __name__ == "__main__":
    unittest.main()
