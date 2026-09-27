"""Unit tests for bridge payload translation (no network)."""

import concurrent.futures
import json
import sys
import os
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import bridge
from bridge import commanded_state, discovery_payload, ha_to_plist


class TestHaToPlist(unittest.TestCase):
    def test_off(self):
        self.assertEqual(ha_to_plist({"state": "OFF"}), [{"pid": "P3", "pvalue": "0"}])

    def test_on_only(self):
        self.assertEqual(ha_to_plist({"state": "ON"}), [{"pid": "P3", "pvalue": "1"}])

    def test_brightness_scale(self):
        p = ha_to_plist({"state": "ON", "brightness": 255})
        self.assertIn({"pid": "P1501", "pvalue": "100"}, p)
        p = ha_to_plist({"state": "ON", "brightness": 128})
        self.assertIn({"pid": "P1501", "pvalue": "50"}, p)
        p = ha_to_plist({"state": "ON", "brightness": 1})
        self.assertIn({"pid": "P1501", "pvalue": "1"}, p)

    def test_rgb(self):
        p = ha_to_plist({"state": "ON", "rgb_color": [255, 45, 0]})
        self.assertIn({"pid": "P1507", "pvalue": "FF2D00"}, p)

    def test_color_dict_modern_schema(self):
        p = ha_to_plist({"state": "ON", "color": {"r": 255, "g": 45, "b": 0}})
        self.assertIn({"pid": "P1507", "pvalue": "FF2D00"}, p)

    def test_color_dict_clamps(self):
        p = ha_to_plist({"state": "ON", "color": {"r": 300, "g": -5, "b": 128}})
        self.assertIn({"pid": "P1507", "pvalue": "FF0080"}, p)

    def test_color_dict_ignored_when_temp_set(self):
        p = ha_to_plist({"state": "ON", "color_temp": 370, "color": {"r": 1, "g": 2, "b": 3}})
        self.assertTrue(any(x["pid"] == "P1502" for x in p))
        self.assertFalse(any(x["pid"] == "P1507" for x in p))

    def test_color_temp_mireds(self):
        p = ha_to_plist({"state": "ON", "color_temp": 370})
        self.assertIn({"pid": "P1502", "pvalue": "2703"}, p)

    def test_color_temp_clamped(self):
        p = ha_to_plist({"state": "ON", "color_temp": 1000})
        self.assertIn({"pid": "P1502", "pvalue": "1800"}, p)
        p = ha_to_plist({"state": "ON", "color_temp": 100})
        self.assertIn({"pid": "P1502", "pvalue": "6500"}, p)

    def test_temp_wins_over_rgb(self):
        p = ha_to_plist({"state": "ON", "color_temp": 370, "rgb_color": [1, 2, 3]})
        self.assertTrue(any(x["pid"] == "P1502" for x in p))
        self.assertFalse(any(x["pid"] == "P1507" for x in p))

    def test_empty(self):
        self.assertEqual(ha_to_plist({}), [])


class TestDiscovery(unittest.TestCase):
    def test_topics(self):
        d = discovery_payload("7C67ABAABBCC", "Desk Lamp", "roku")
        self.assertEqual(d["command_topic"], "roku/light/7C67ABAABBCC/set")
        self.assertEqual(d["state_topic"], "roku/light/7C67ABAABBCC/state")
        self.assertEqual(d["unique_id"], "roku_7C67ABAABBCC")
        self.assertTrue(d["optimistic"])
        self.assertLess(d["min_mireds"], d["max_mireds"])
        self.assertEqual(d["supported_color_modes"], ["color_temp", "rgb"])
        self.assertIsNone(d["name"])


class TestCommandedState(unittest.TestCase):
    def test_color_modes(self):
        self.assertEqual(
            commanded_state({"state": "ON", "color_temp": 370})["color_mode"],
            "color_temp",
        )
        self.assertEqual(
            commanded_state({"state": "ON", "rgb_color": [1, 2, 3]})["color_mode"],
            "rgb",
        )
        self.assertEqual(
            commanded_state({"state": "ON", "color": {"r": 1, "g": 2, "b": 3}})["color_mode"],
            "rgb",
        )
        self.assertEqual(
            commanded_state({"state": "ON", "color": {"r": 1, "g": 2, "b": 3}})["color"],
            {"r": 1, "g": 2, "b": 3},
        )
        self.assertNotIn(
            "color_mode", commanded_state({"state": "ON", "brightness": 10})
        )
        self.assertNotIn("color_mode", commanded_state({"state": "OFF"}))
        self.assertEqual(commanded_state({"state": "OFF"})["state"], "OFF")


class TestDispatch(unittest.TestCase):
    def _bulbs(self):
        return {
            "SLOW": {"name": "Slow", "ip": "192.168.1.51", "enr": "E" * 16},
            "FAST": {"name": "Fast", "ip": "192.168.1.52", "enr": "E" * 16},
        }

    def test_route_slug_known_and_unknown(self):
        bulbs = self._bulbs()
        self.assertEqual(bridge.route_slug("roku/light/slow/set", bulbs), "SLOW")
        self.assertIsNone(bridge.route_slug("roku/light/nope/set", bulbs))

    def test_slow_bulb_does_not_block_fast_bulb(self):
        bulbs = self._bulbs()
        started = threading.Event()
        release = threading.Event()
        published = []
        lock = threading.Lock()

        real_send = bridge.send_local

        def fake_send(ip, mac, enr, plist):
            if mac == "SLOW":
                started.set()
                self.assertTrue(release.wait(timeout=5))
                time.sleep(0.05)
            with lock:
                published.append(mac)

        class FakeClient:
            def publish(self, *a, **k):
                pass

        bridge.send_local = fake_send
        try:
            executors = {
                s: concurrent.futures.ThreadPoolExecutor(max_workers=1)
                for s in bulbs
            }
            try:
                payload = json.dumps({"state": "ON"}).encode()
                f_slow = executors["SLOW"].submit(
                    bridge._handle_set, FakeClient(), "roku", bulbs, "SLOW", payload,
                    "roku/light/SLOW/set",
                )
                self.assertTrue(started.wait(timeout=5))
                t0 = time.monotonic()
                f_fast = executors["FAST"].submit(
                    bridge._handle_set, FakeClient(), "roku", bulbs, "FAST", payload,
                    "roku/light/FAST/set",
                )
                f_fast.result(timeout=5)
                elapsed = time.monotonic() - t0
                self.assertLess(elapsed, 1.0)
                release.set()
                f_slow.result(timeout=5)
            finally:
                for ex in executors.values():
                    ex.shutdown(wait=True)
        finally:
            bridge.send_local = real_send
        self.assertIn("FAST", published)
        self.assertIn("SLOW", published)

    def test_same_bulb_commands_stay_ordered(self):
        bulbs = self._bulbs()
        order = []
        lock = threading.Lock()
        real_send = bridge.send_local

        def fake_send(ip, mac, enr, plist):
            time.sleep(0.02)
            with lock:
                order.append(
                    next(p["pvalue"] for p in plist if p["pid"] == "P1501")
                )

        class FakeClient:
            def publish(self, *a, **k):
                pass

        bridge.send_local = fake_send
        try:
            ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                futs = [
                    ex.submit(
                        bridge._handle_set, FakeClient(), "roku", bulbs, "FAST",
                        json.dumps({"state": "ON", "brightness": b}).encode(),
                        "roku/light/FAST/set",
                    )
                    for b in (10, 20, 30)
                ]
                for f in futs:
                    f.result(timeout=5)
            finally:
                ex.shutdown(wait=True)
        finally:
            bridge.send_local = real_send
        pct = lambda b: str(max(1, min(100, round(b * 100 / 255))))
        self.assertEqual(order, [pct(10), pct(20), pct(30)])

    def test_empty_plist_sends_nothing(self):
        calls = []

        class FakeClient:
            def publish(self, *a, **k):
                calls.append("publish")

        real_send = bridge.send_local
        bridge.send_local = lambda *a: calls.append("send")
        try:
            bridge._handle_set(
                FakeClient(), "roku", self._bulbs(), "FAST", b"{}",
                "roku/light/FAST/set",
            )
        finally:
            bridge.send_local = real_send
        self.assertEqual(calls, [])

    def test_send_failure_does_not_raise(self):
        class FakeClient:
            def publish(self, *a, **k):
                raise AssertionError("must not publish on failure")

        real_send = bridge.send_local

        def boom(*a):
            raise TimeoutError("timed out")

        bridge.send_local = boom
        try:
            bridge._handle_set(
                FakeClient(), "roku", self._bulbs(), "FAST",
                json.dumps({"state": "ON"}).encode(), "roku/light/FAST/set",
            )
        finally:
            bridge.send_local = real_send


if __name__ == "__main__":
    unittest.main()
