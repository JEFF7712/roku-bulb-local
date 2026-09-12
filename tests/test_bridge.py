"""Unit tests for bridge payload translation (no network)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
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


if __name__ == "__main__":
    unittest.main()
