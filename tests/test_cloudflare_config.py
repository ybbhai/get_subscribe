import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from utils.cloudflare_config import load_cloudflare_config, save_cloudflare_config


class CloudflareConfigTests(unittest.TestCase):
    def test_saved_relative_paths_load_from_any_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / "get_subscribe" / "config"
            config_dir.mkdir(parents=True)
            subscription = root / "subscription.txt"
            addresses = root / "addresses.txt"
            subscription.write_text("vless subscription", encoding="utf-8")
            addresses.write_text("104.16.0.1", encoding="utf-8")
            config = config_dir / "cloudflare.yaml"

            with patch("utils.cloudflare_config.Path.cwd", return_value=root):
                save_cloudflare_config({
                    "subscription_file": "subscription.txt",
                    "subscription_url": None,
                    "addresses_file": "addresses.txt",
                    "addresses_format": "addresses",
                    "template_index": 2,
                    "max_candidates": 25,
                }, config)

            with patch("utils.cloudflare_config.Path.cwd", return_value=Path("/")):
                loaded = load_cloudflare_config(config)

        self.assertEqual(Path(loaded["subscription_file"]), subscription)
        self.assertEqual(Path(loaded["addresses_file"]), addresses)
        self.assertEqual(loaded["template_index"], 2)
        self.assertEqual(loaded["max_candidates"], 25)
        self.assertEqual(loaded["automatic_max_candidates"], 25)

    def test_legacy_config_keeps_automatic_default(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "cloudflare.yaml"
            subscription = Path(directory) / "subscription.txt"
            subscription.write_text("vless subscription", encoding="utf-8")
            config.write_text(
                "subscription_file: subscription.txt\n"
                "subscription_url: null\n"
                "max_candidates: 100\n",
                encoding="utf-8",
            )

            loaded = load_cloudflare_config(config)

        self.assertEqual(loaded["max_candidates"], 100)
        self.assertEqual(loaded["automatic_max_candidates"], 40)

    def test_missing_config_disables_cloudflare_source(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "cloudflare.yaml"
            self.assertIsNone(load_cloudflare_config(config))

    def test_invalid_saved_url_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "cloudflare.yaml"
            config.write_text(
                "subscription_url: http://edge.example/sub\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "HTTPS"):
                load_cloudflare_config(config)

    def test_save_requires_subscription_file_to_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "missing.txt"
            config = Path(directory) / "config" / "cloudflare.yaml"

            with self.assertRaisesRegex(ValueError, "不存在或不可读"):
                save_cloudflare_config({
                    "subscription_file": str(source),
                    "subscription_url": None,
                }, config)

    def test_multiple_sources_resolve_paths_relative_to_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "data").mkdir()
            subscription = root / "data" / "edge.yaml"
            subscription.write_text("proxies: []", encoding="utf-8")
            addresses = root / "data" / "ingress.txt"
            addresses.write_text("104.16.0.1", encoding="utf-8")
            config = root / "config" / "cloudflare.yaml"
            config.write_text(yaml.safe_dump({"sources": [
                {"id": "edge-one", "subscription_file": "../data/edge.yaml",
                 "addresses_file": "../data/ingress.txt", "max_candidates": 12},
                {"id": "edge-two", "enabled": False, "subscription_url": "https://edge.example/sub"},
            ]}), encoding="utf-8")

            with patch("utils.cloudflare_config.Path.cwd", return_value=root / "elsewhere"):
                result = load_cloudflare_config(config)

        self.assertEqual(result["max_total_candidates"], 500)
        self.assertEqual(result["automatic_max_candidates"], 40)
        self.assertNotIn("vpngate", result)
        self.assertEqual(result["sources"][0]["subscription_file"], str(subscription))
        self.assertEqual(result["sources"][0]["addresses_file"], str(addresses))
        self.assertEqual(result["sources"][0]["max_candidates"], 12)
        self.assertTrue(result["sources"][0]["enabled"])
        self.assertFalse(result["sources"][1]["enabled"])
        self.assertEqual(result["sources"][1]["max_candidates"], 100)

    def test_legacy_save_preserves_sources_and_vpngate_with_original_path_base(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / "config"
            config_dir.mkdir()
            old_file = root / "old.yaml"
            old_file.write_text("proxies: []", encoding="utf-8")
            caller_dir = root / "caller"
            caller_dir.mkdir()
            new_file = caller_dir / "new.yaml"
            new_file.write_text("proxies: []", encoding="utf-8")
            config = config_dir / "cloudflare.yaml"
            config.write_text(yaml.safe_dump({
                "subscription_url": "https://legacy.example/sub",
                "automatic_enabled": False, "max_total_candidates": 700,
                "sources": [{"id": "existing", "subscription_file": "../old.yaml"}],
                "vpngate": {"enabled": True, "api_url": "https://vpn.example/api/", "max_candidates": 30},
            }), encoding="utf-8")

            with patch("utils.cloudflare_config.Path.cwd", return_value=caller_dir):
                save_cloudflare_config({"subscription_file": "new.yaml", "max_candidates": 25}, config)
            result = load_cloudflare_config(config)
            stored = yaml.safe_load(config.read_text(encoding="utf-8"))

        self.assertEqual(result["subscription_file"], str(new_file))
        self.assertIsNone(result["subscription_url"])
        self.assertEqual(result["automatic_max_candidates"], 25)
        self.assertFalse(result["automatic_enabled"])
        self.assertEqual(result["max_total_candidates"], 700)
        self.assertEqual(result["sources"][0]["subscription_file"], str(old_file))
        self.assertEqual(result["vpngate"]["api_url"], "https://vpn.example/api/")
        self.assertEqual(result["vpngate"]["max_candidates"], 30)
        self.assertFalse(Path(stored["sources"][0]["subscription_file"]).is_absolute())
        self.assertFalse(Path(stored["subscription_file"]).is_absolute())
        self.assertNotIn("\\", stored["sources"][0]["subscription_file"])
        self.assertNotIn("\\", stored["subscription_file"])

    def test_partial_vpngate_save_keeps_existing_api_and_mirrors(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "cloudflare.yaml"
            save_cloudflare_config({"vpngate": {
                "api_url": "http://vpn.example/api/", "mirror_urls": ["https://mirror.example/api/"],
                "max_candidates": 22,
            }}, config)
            save_cloudflare_config({"vpngate": {"enabled": False}}, config)
            result = load_cloudflare_config(config)

        self.assertEqual(result["vpngate"], {
            "enabled": False, "max_candidates": 22, "api_url": "http://vpn.example/api/",
            "mirror_urls": ["https://mirror.example/api/"],
        })

    def test_disabled_local_sources_resolve_missing_paths_until_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config" / "cloudflare.yaml"
            config.parent.mkdir()
            config.write_text(yaml.safe_dump({"sources": [{
                "id": "disabled", "enabled": False,
                "subscription_file": "../missing-subscription.yaml",
                "addresses_file": "../missing-addresses.txt",
            }]}), encoding="utf-8")

            loaded = load_cloudflare_config(config)
            disabled = loaded["sources"][0]
            self.assertEqual(disabled["subscription_file"], str(root / "missing-subscription.yaml"))
            self.assertEqual(disabled["addresses_file"], str(root / "missing-addresses.txt"))
            save_cloudflare_config({"vpngate": {"enabled": True}}, config)
            self.assertFalse(load_cloudflare_config(config)["sources"][0]["enabled"])

            disabled["enabled"] = True
            with self.assertRaisesRegex(ValueError, "不存在或不可读"):
                save_cloudflare_config({"sources": [disabled]}, config)
            self.assertFalse(load_cloudflare_config(config)["sources"][0]["enabled"])

    def test_save_can_replace_missing_legacy_file_with_url(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "cloudflare.yaml"
            config.write_text("subscription_file: moved-away.yaml\n", encoding="utf-8")
            save_cloudflare_config({"subscription_url": "https://new.example/sub"}, config)
            result = load_cloudflare_config(config)

        self.assertIsNone(result["subscription_file"])
        self.assertEqual(result["subscription_url"], "https://new.example/sub")

    def test_save_can_disable_stale_source_but_retained_enabled_paths_must_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config" / "cloudflare.yaml"
            config.parent.mkdir()
            stale_source = {"id": "stale", "subscription_file": "../moved-away.yaml"}
            original = yaml.safe_dump({"sources": [stale_source]})
            config.write_text(original, encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "不存在或不可读"):
                save_cloudflare_config({"vpngate": {"enabled": True}}, config)
            self.assertEqual(config.read_text(encoding="utf-8"), original)

            with patch("utils.cloudflare_config.Path.cwd", return_value=config.parent):
                save_cloudflare_config({"sources": [{**stale_source, "enabled": False}]}, config)
            result = load_cloudflare_config(config)

        self.assertFalse(result["sources"][0]["enabled"])
        self.assertEqual(result["sources"][0]["subscription_file"], str(root / "moved-away.yaml"))

    def test_save_does_not_overwrite_invalid_existing_structure(self):
        for original in ("unknown_field: true\n", "sources: wrong-type\n", "sources: [\n"):
            with self.subTest(original=original), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "cloudflare.yaml"
                config.write_text(original, encoding="utf-8")
                with self.assertRaises(ValueError):
                    save_cloudflare_config({"subscription_url": "https://new.example/sub"}, config)
                self.assertEqual(config.read_text(encoding="utf-8"), original)

    def test_config_can_only_control_automatic_or_vpngate_without_a_subscription(self):
        for data in ({}, {"automatic_enabled": False}, {"sources": []}, {"vpngate": {}},
                     {"vpngate": {"enabled": True}}, {"vpngate": {"enabled": False}}):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "cloudflare.yaml"
                config.write_text(yaml.safe_dump(data), encoding="utf-8")
                result = load_cloudflare_config(config)
                self.assertIsNone(result["subscription_file"])
                self.assertIsNone(result["subscription_url"])
                if "vpngate" not in data:
                    self.assertNotIn("vpngate", result)
                else:
                    self.assertEqual(result["vpngate"]["max_candidates"], 100)
                    self.assertEqual("enabled" in result["vpngate"], "enabled" in data["vpngate"])

    def test_source_ids_are_safe_unique_and_cannot_shadow_builtin_sources(self):
        invalid_ids = [None, "", "a" * 65, "https://secret.example/token", "a/b", "a b", "_name",
                       "rss", "clash_subscriptions", "cloudflare_auto", "vpngate", "cloudflare_legacy", "VPNGate"]
        for identifier in invalid_ids:
            with self.subTest(identifier=identifier), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "cloudflare.yaml"
                config.write_text(yaml.safe_dump({"sources": [
                    {"id": identifier, "subscription_url": "https://example.test/sub"},
                ]}), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "id") as raised:
                    load_cloudflare_config(config)
                self.assertNotIn("secret.example", str(raised.exception))
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "cloudflare.yaml"
            config.write_text(yaml.safe_dump({"sources": [
                {"id": "duplicate", "subscription_url": "https://example.test/one"},
                {"id": "Duplicate", "subscription_url": "https://example.test/two"},
            ]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "重复"):
                load_cloudflare_config(config)

    def test_rejects_malformed_source_lists_and_fields(self):
        valid = {"id": "edge", "subscription_url": "https://example.test/sub"}
        invalid = [
            {"sources": {}}, {"sources": [None]}, {"sources": [valid] * 33},
            {"sources": [{"id": "missing-subscription"}]},
            {"sources": [{**valid, "enabled": "false"}]},
            {"sources": [{**valid, "max_candidates": True}]},
            {"sources": [{**valid, "max_candidates": 501}]},
            {"sources": [{**valid, "subscription_file": "also.yaml"}]},
            {"sources": [{**valid, "unknown": "value"}]},
            {"automatic_enabled": 1}, {"max_total_candidates": 0},
            {"max_total_candidates": 2001}, {"max_total_candidates": True},
            {"max_total_candidates": 1.5}, {"unknown": True},
            {"subscription_file": False}, {"addresses_file": "orphan.txt"},
        ]
        for data in invalid:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "cloudflare.yaml"
                config.write_text(yaml.safe_dump(data), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_cloudflare_config(config)

    def test_vpngate_urls_limits_and_flags_are_validated_without_exposing_tokens(self):
        invalid = [None, [], {"enabled": "false"}, {"max_candidates": 0},
                   {"max_candidates": 501}, {"max_candidates": True},
                   {"api_url": "ftp://secret.example/private-token"},
                   {"api_url": "https://user:private-token@secret.example/"},
                   {"api_url": "https://secret.example:99999/private-token"},
                   {"api_url": " https://secret.example/private-token"},
                   {"mirror_urls": "https://secret.example/private-token"},
                   {"mirror_urls": ["https://example.test/"] * 4},
                   {"mirror_urls": [None]}, {"unknown": True}]
        for value in invalid:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "cloudflare.yaml"
                config.write_text(yaml.safe_dump({"vpngate": value}), encoding="utf-8")
                with self.assertRaises(ValueError) as raised:
                    load_cloudflare_config(config)
                self.assertNotIn("private-token", str(raised.exception))
                self.assertNotIn("secret.example", str(raised.exception))

    def test_save_uses_absolute_path_if_windows_drives_cannot_be_relativized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subscription = root / "edge.yaml"
            subscription.write_text("proxies: []", encoding="utf-8")
            config = root / "cloudflare.yaml"
            with patch("utils.cloudflare_config.os.path.relpath", side_effect=ValueError("different drive")):
                save_cloudflare_config({"sources": [
                    {"id": "other-drive", "subscription_file": subscription},
                ]}, config)
            stored = yaml.safe_load(config.read_text(encoding="utf-8"))
            result = load_cloudflare_config(config)
        self.assertEqual(stored["sources"][0]["subscription_file"], str(subscription))
        self.assertEqual(result["sources"][0]["subscription_file"], str(subscription))

    def test_invalid_update_does_not_replace_saved_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "cloudflare.yaml"
            original = "automatic_enabled: false\nsources: []\n"
            config.write_text(original, encoding="utf-8")
            with self.assertRaises(ValueError):
                save_cloudflare_config({"max_total_candidates": 0}, config)
            self.assertEqual(config.read_text(encoding="utf-8"), original)

    def test_config_accepts_budget_boundaries_and_thirty_two_independent_sources(self):
        for total in (1, 2000):
            with self.subTest(total=total), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "cloudflare.yaml"
                source_list = [{"id": f"Source_{index}-ok", "subscription_url": "https://example.test/sub",
                                "max_candidates": 1 if index % 2 else 500} for index in range(32)]
                save_cloudflare_config({"max_total_candidates": total, "sources": source_list,
                                        "vpngate": {"max_candidates": 500, "enabled": True}}, config)
                result = load_cloudflare_config(config)
            self.assertEqual(result["max_total_candidates"], total)
            self.assertEqual(len(result["sources"]), 32)
            self.assertEqual(result["sources"][1]["id"], "Source_1-ok")

    def test_example_config_is_valid_without_network_or_local_subscription_files(self):
        example = Path(__file__).resolve().parents[1] / "config" / "cloudflare.example.yaml"
        result = load_cloudflare_config(example)
        self.assertEqual(result["max_total_candidates"], 500)
        self.assertTrue(result["sources"])
        self.assertTrue(all(not source["enabled"] for source in result["sources"]))
        self.assertNotIn("enabled", result["vpngate"])


if __name__ == "__main__":
    unittest.main()
