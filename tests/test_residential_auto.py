import json
import os
from pathlib import Path
import tempfile
import traceback
import unittest
from unittest.mock import patch

from utils.exit_quality import ExitInspector, IPAPI_URL, IPQUERY_URL, LookupError


def ipquery():
    return {"ip": "8.8.4.4", "risk": {
        "is_mobile": False, "is_vpn": False, "is_tor": False,
        "is_proxy": False, "is_datacenter": False, "risk_score": 0,
    }}


def ipapi():
    return {
        "ip": "8.8.4.4", "is_bogon": False, "is_abuser": False,
        "is_proxy": False, "is_vpn": False, "is_tor": False,
        "is_crawler": False, "is_datacenter": False, "is_mobile": False,
        "is_satellite": False, "is_anycast": False,
        "company": {"type": "isp", "abuser_score": "0.0001 (Very Low)"},
        "asn": {"type": "isp", "abuser_score": "0.0001 (Very Low)"},
    }


class ResidentialAutoTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.config = self.directory / "exit_quality.yaml"
        env = patch.dict(os.environ, {"IPAPI_IS_KEY": "", "EXIT_QUALITY_CONFIG": ""})
        env.start()
        self.addCleanup(env.stop)
        path = patch("utils.exit_quality.DEFAULT_EXIT_QUALITY_CONFIG", self.config)
        path.start()
        self.addCleanup(path.stop)

    def test_prod_auto_enables_but_missing_key_never_claims_residential(self):
        with patch("utils.exit_quality._request_json", return_value=ipquery()) as request:
            inspector = ExitInspector(profile="prod")
            result = inspector.inspect(18010)
        self.assertEqual(inspector.capabilities(), {
            "enabled": True, "available": False, "reason": "missing_api_key",
        })
        self.assertEqual(result["status"], "clean")
        self.assertIsNone(result["residential"])
        self.assertEqual(result["residential_reason"], "missing_api_key")
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.args[2], IPQUERY_URL)

    def test_nonprod_without_key_remains_disabled(self):
        for profile in (None, "test", "dev"):
            with self.subTest(profile=profile):
                self.assertEqual(ExitInspector(profile=profile).capabilities(), {
                    "enabled": False, "available": False, "reason": "disabled",
                })

    def test_default_local_config_enables_lookup_in_prod(self):
        self.config.write_text("ipapi_is_key: local-private-key\n", encoding="utf-8")
        with patch("utils.exit_quality._request_json", side_effect=[ipquery(), ipapi()]) as request:
            inspector = ExitInspector(profile="prod")
            result = inspector.inspect(18010)
        self.assertEqual(inspector.capabilities(), {
            "enabled": True, "available": True, "reason": "ready",
        })
        self.assertTrue(result["residential"])
        self.assertEqual(request.call_args.args[:3], ("http://127.0.0.1:18010", "POST", IPAPI_URL))
        self.assertEqual(request.call_args.kwargs["json"], {"q": "8.8.4.4", "key": "local-private-key"})
        self.assertNotIn("local-private-key", json.dumps([result, inspector.capabilities()]))

    def test_config_override_and_nonprod_key_remain_supported(self):
        override = self.directory / "private custom.yaml"
        override.write_text("ipapi_is_key: override-private-key\n", encoding="utf-8")
        with patch.dict(os.environ, {"EXIT_QUALITY_CONFIG": str(override)}), \
                patch("utils.exit_quality._request_json", side_effect=[ipquery(), ipapi()]) as request:
            inspector = ExitInspector(profile="test")
            result = inspector.inspect(18010)
        self.assertTrue(inspector.capabilities()["enabled"])
        self.assertTrue(result["residential"])
        self.assertEqual(request.call_args.kwargs["json"]["key"], "override-private-key")

    def test_environment_key_takes_priority_even_over_invalid_config(self):
        self.config.write_text("ipapi_is_key: [broken\n", encoding="utf-8")
        with patch.dict(os.environ, {"IPAPI_IS_KEY": " env-private-key "}), \
                patch("utils.exit_quality._request_json", side_effect=[ipquery(), ipapi()]) as request:
            result = ExitInspector(profile="prod").inspect(18010)
        self.assertTrue(result["residential"])
        self.assertEqual(request.call_args.kwargs["json"]["key"], "env-private-key")
        self.assertNotIn("env-private-key", json.dumps(result))

    def test_config_errors_do_not_expose_private_contents(self):
        for contents in ("ipapi_is_key: [secret-from-config", "ipapi_is_key: [secret-from-config]\n"):
            with self.subTest(contents=contents):
                self.config.write_text(contents, encoding="utf-8")
                try:
                    ExitInspector(profile="prod")
                except ValueError:
                    error = traceback.format_exc()
                else:
                    self.fail("Malformed credentials should be rejected")
                self.assertNotIn("secret-from-config", error)
        with patch.dict(os.environ, {"EXIT_QUALITY_CONFIG": str(self.directory / "missing.yaml")}):
            with self.assertRaisesRegex(ValueError, "不存在"):
                ExitInspector(profile="prod")

    def test_failed_optional_enrichment_preserves_clean_and_redacts_errors(self):
        failures = (
            (LookupError("lookup_timeout"), "reputation_timeout"),
            (LookupError("failed with secret-key"), "reputation_unavailable"),
            (OSError("failed with secret-key"), "reputation_unavailable"),
        )
        for failure, expected in failures:
            with self.subTest(reason=expected), \
                    patch.dict(os.environ, {"IPAPI_IS_KEY": "secret-key"}), \
                    patch("utils.exit_quality._request_json", side_effect=[ipquery(), failure]):
                inspector = ExitInspector(profile="prod")
                result = inspector.inspect(18010)
            self.assertEqual(result["status"], "clean")
            self.assertEqual(result["reason"], "low_risk_signals")
            self.assertIsNone(result["residential"])
            self.assertEqual(result["reputation_reason"], expected)
            self.assertNotIn("secret-key", json.dumps([result, inspector.capabilities()]))

    def test_quota_failure_preserves_clean_and_stops_additional_keyed_calls(self):
        next_exit = ipquery()
        next_exit["ip"] = "1.1.1.1"
        for status in (403, 429):
            with self.subTest(status=status), \
                    patch.dict(os.environ, {"IPAPI_IS_KEY": "secret-key"}), \
                    patch("utils.exit_quality._request_json", side_effect=[
                        ipquery(), LookupError("quota secret-key", status), next_exit,
                    ]) as request:
                inspector = ExitInspector(profile="prod")
                results = [inspector.inspect(18010), inspector.inspect(18020)]
            for result in results:
                self.assertEqual(result["status"], "clean")
                self.assertIsNone(result["residential"])
                self.assertEqual(result["reputation_reason"], "reputation_rate_limited")
            self.assertEqual(inspector.capabilities(), {
                "enabled": True, "available": False, "reason": "reputation_rate_limited",
            })
            self.assertEqual([call.args[1] for call in request.call_args_list], ["GET", "POST", "GET"])
            self.assertNotIn("secret-key", json.dumps(results))

    def test_real_reputation_risk_still_overrides_clean(self):
        record = ipapi()
        record["is_abuser"] = True
        with patch.dict(os.environ, {"IPAPI_IS_KEY": "secret-key"}), \
                patch("utils.exit_quality._request_json", side_effect=[ipquery(), record]):
            result = ExitInspector(profile="prod").inspect(18010)
        self.assertEqual(result["status"], "risk")
        self.assertFalse(result["residential"])

    def test_enrichment_failure_does_not_upgrade_incomplete_risk_evidence(self):
        record = ipquery()
        record["risk"].pop("risk_score")
        with patch.dict(os.environ, {"IPAPI_IS_KEY": "secret-key"}), \
                patch("utils.exit_quality._request_json", side_effect=[record, LookupError("lookup_timeout")]):
            result = ExitInspector(profile="prod").inspect(18010)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "missing_risk_fields")
        self.assertIsNone(result["residential"])


if __name__ == "__main__":
    unittest.main()
