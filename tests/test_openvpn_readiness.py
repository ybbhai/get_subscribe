import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from utils.utils import _test_node_metrics_async


GOOGLE = "https://www.google.com/generate_204"
YOUTUBE = "https://www.youtube.com"
CHATGPT = "https://chatgpt.com/api/auth/providers"
GITHUB = "https://github.com"
HEALTH = "https://www.gstatic.com/generate_204"
DOWNLOAD = "https://speed.cloudflare.com/__down?bytes=1048576"


class FakeClock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def failed_services(elapsed=5):
    return [(url, False, elapsed, 0) for url in (GOOGLE, YOUTUBE, CHATGPT, GITHUB)]


class OpenVPNReadinessTests(unittest.TestCase):
    def test_five_second_dial_failure_retries_same_node_then_measures_success(self):
        clock = FakeClock()
        attempts = []

        async def probe(links, proxies, timeout, max_concurrent):
            attempts.append((list(links), dict(proxies), timeout))
            if len(attempts) == 1:
                clock.now += 5
                return failed_services()
            if links == [HEALTH]:
                return [(HEALTH, True, 0.1, 0)]
            if links == [DOWNLOAD]:
                return [(DOWNLOAD, True, 0.5, 1048576)]
            clock.now += 0.2
            return [(GOOGLE, True, 0.2, 0), (YOUTUBE, False, 0.1, 0),
                    (CHATGPT, False, 0.1, 0), (GITHUB, False, 0.1, 0)]

        with patch("utils.utils.monotonic", side_effect=clock.monotonic), \
                patch("utils.utils.asyncio.sleep", new=clock.sleep), \
                patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=probe)):
            result = asyncio.run(_test_node_metrics_async({"type": "openvpn"}, 18012, timeout=2))
        self.assertTrue(result["is_available"])
        self.assertTrue(result["download_passed"])
        self.assertEqual(result["avg_latency"], 100)
        self.assertEqual(result["google_latency"], 200)
        self.assertEqual(len(attempts), 4)
        self.assertEqual(attempts[0][2], 35)
        self.assertEqual(attempts[1][2], 29.75)
        self.assertEqual(attempts[0][0], attempts[1][0])
        for _, proxies, _ in attempts:
            self.assertEqual(proxies, {"http": "http://127.0.0.1:18012", "https": "http://127.0.0.1:18012"})
        self.assertEqual(clock.sleeps, [0.25])

    def test_failed_readiness_stops_at_shared_budget_without_download_or_lookup(self):
        clock = FakeClock()
        timeouts = []

        async def probe(links, proxies, timeout, max_concurrent):
            self.assertEqual(links, [GOOGLE, YOUTUBE, CHATGPT, GITHUB])
            timeouts.append(timeout)
            clock.now += min(5, timeout)
            return failed_services(min(5, timeout))

        with patch("utils.utils.monotonic", side_effect=clock.monotonic), \
                patch("utils.utils.asyncio.sleep", new=clock.sleep), \
                patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=probe)):
            result = asyncio.run(_test_node_metrics_async({"type": "openvpn"}, 18012))
        self.assertFalse(result["is_available"])
        self.assertFalse(result["download_passed"])
        self.assertEqual(clock.now, 135)
        self.assertEqual(len(timeouts), 7)
        self.assertEqual(timeouts[-1], 3.5)
        self.assertTrue(all(earlier > later for earlier, later in zip(timeouts, timeouts[1:])))

    def test_immediate_failures_back_off_and_do_not_loop_forever(self):
        clock = FakeClock()
        with patch("utils.utils.monotonic", side_effect=clock.monotonic), \
                patch("utils.utils.asyncio.sleep", new=clock.sleep), \
                patch("utils.utils.test_links_concurrent", new=AsyncMock(return_value=failed_services(0))) as probe:
            result = asyncio.run(_test_node_metrics_async({"type": "openvpn"}, 18012))
        self.assertFalse(result["is_available"])
        self.assertEqual(clock.now, 135)
        self.assertEqual(probe.await_count, 140)
        self.assertTrue(all(0 < delay <= 0.25 for delay in clock.sleeps))

    def test_github_alone_does_not_end_readiness_but_target_service_does(self):
        clock = FakeClock()
        calls = 0

        async def probe(links, proxies, timeout, max_concurrent):
            nonlocal calls
            calls += 1
            if calls == 1:
                clock.now += 5
                return [(GITHUB, True, 0.1, 100)]
            if calls == 2:
                return [(CHATGPT, True, 0.2, 100)]
            return [(links[0], False, 0.1, 0)]

        with patch("utils.utils.monotonic", side_effect=clock.monotonic), \
                patch("utils.utils.asyncio.sleep", new=clock.sleep), \
                patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=probe)):
            result = asyncio.run(_test_node_metrics_async({"type": "openvpn"}, 18012))
        self.assertTrue(result["is_available"])
        self.assertEqual(calls, 4)
        self.assertEqual(result["chatgpt_latency"], 200)

    def test_ordinary_protocol_retains_single_probe_and_original_timeout(self):
        with patch("utils.utils.asyncio.sleep", new=AsyncMock()) as sleep, \
                patch("utils.utils.test_links_concurrent", new=AsyncMock(return_value=failed_services())) as probe:
            result = asyncio.run(_test_node_metrics_async({"type": "vless"}, 18012, timeout=2))
        self.assertFalse(result["is_available"])
        self.assertEqual(probe.await_count, 1)
        self.assertEqual(probe.call_args.kwargs["timeout"], 6)
        sleep.assert_not_awaited()

    def test_outer_timeout_cancels_probe_without_continuing_after_deadline(self):
        clock = FakeClock()

        async def cancelled_probe(links, proxies, timeout, max_concurrent):
            clock.now += timeout
            raise asyncio.TimeoutError

        with patch("utils.utils.monotonic", side_effect=clock.monotonic), \
                patch("utils.utils.asyncio.sleep", new=clock.sleep), \
                patch("utils.utils.test_links_concurrent", new=AsyncMock(side_effect=cancelled_probe)) as probe:
            result = asyncio.run(_test_node_metrics_async({"type": "openvpn"}, 18012))
        self.assertFalse(result["is_available"])
        self.assertEqual(probe.await_count, 1)
        self.assertEqual(clock.sleeps, [])


if __name__ == "__main__":
    unittest.main()
