"""Phase 827 — detection thresholds must be reachable from config.

WHY THIS EXISTS
---------------
All three detectors were constructed with zero arguments:

    CampaignDetector()          SlowScanDetector()      JA4FingerprintIntelligence()

so every threshold was a hardcoded Python default. The constructors accepted
parameters; nothing ever passed one. Tuning detection sensitivity — an ordinary
operator task — required editing source and rebuilding the image, in breach of
the config-driven requirement every other feature in this project follows.

It also made the thresholds invisible: an operator asking "why do I get no
campaign findings?" had no file to look in, and the real answer (density >= 0.15
of a /24 means 39+ distinct IPs in one 256-address block) was buried in a
default argument.

Two things are guarded here: that config actually reaches the detectors, and
that a PARTIAL config does not silently reset the keys it does not mention —
load_config()'s default merge is only two levels deep, so a nested block is the
exact shape that breaks it.
"""

from __future__ import annotations

import pytest
import yaml
from pathlib import Path

from src.analytics.stream_consumer import StreamConsumer

REPO = Path(__file__).resolve().parents[3]

# The values that were hardcoded before this phase. Defaults must not drift
# from these, or an existing deployment changes behaviour on upgrade.
HISTORICAL = {
    "campaign": {"min_unique_ips": 10, "density_threshold": 0.15, "block_rate_threshold": 0.70},
    "slow_scan": {"min_unique_ips": 20, "max_requests_per_ip": 3},
    "ja4_intelligence": {"min_observations": 10, "block_rate_threshold": 0.95},
}


def consumer(detection=None) -> StreamConsumer:
    return StreamConsumer("redis://localhost:6379/0", detection_config=detection)


class TestDefaultsUnchanged:
    """An absent config block must behave exactly as before this phase."""

    def test_campaign_defaults(self):
        c = consumer().campaign_detector
        assert c.min_unique_ips == HISTORICAL["campaign"]["min_unique_ips"]
        assert c.density_threshold == HISTORICAL["campaign"]["density_threshold"]
        assert c.block_rate_threshold == HISTORICAL["campaign"]["block_rate_threshold"]

    def test_slow_scan_defaults(self):
        s = consumer().slow_scan_detector
        assert s.min_unique_ips == HISTORICAL["slow_scan"]["min_unique_ips"]
        assert s.max_requests_per_ip == HISTORICAL["slow_scan"]["max_requests_per_ip"]

    def test_ja4_defaults(self):
        j = consumer().ja4_intelligence
        assert j.min_observations == HISTORICAL["ja4_intelligence"]["min_observations"]
        assert j.block_rate_threshold == HISTORICAL["ja4_intelligence"]["block_rate_threshold"]


class TestConfigReachesDetectors:
    def test_slow_scan_min_unique_ips_is_configurable(self):
        """The specific number the operator asked about."""
        s = consumer({"slow_scan": {"min_unique_ips": 5}}).slow_scan_detector
        assert s.min_unique_ips == 5

    def test_campaign_density_is_configurable(self):
        c = consumer({"campaign": {"density_threshold": 0.02}}).campaign_detector
        assert c.density_threshold == 0.02

    def test_ja4_min_observations_is_configurable(self):
        j = consumer({"ja4_intelligence": {"min_observations": 3}}).ja4_intelligence
        assert j.min_observations == 3


class TestPartialConfig:
    """A partial block must not blank its siblings.

    load_config()'s default merge is two levels deep; `detection` is three, so
    setting one nested key is precisely the case that silently loses the rest.
    Reading with per-key fallbacks is what makes this safe.
    """

    def test_setting_one_key_keeps_siblings_at_default(self):
        c = consumer({"slow_scan": {"min_unique_ips": 5}})
        assert c.slow_scan_detector.min_unique_ips == 5
        assert c.slow_scan_detector.max_requests_per_ip == 3, "sibling was reset"

    def test_setting_one_section_leaves_other_sections_default(self):
        c = consumer({"slow_scan": {"min_unique_ips": 5}})
        assert c.campaign_detector.min_unique_ips == 10
        assert c.ja4_intelligence.min_observations == 10

    @pytest.mark.parametrize("empty", [{}, None, {"slow_scan": {}}, {"slow_scan": None}])
    def test_empty_shapes_fall_back_cleanly(self, empty):
        """None and {} both appear in real YAML (`slow_scan:` with no children)."""
        assert consumer(empty).slow_scan_detector.min_unique_ips == 20


class TestHotReload:
    def test_apply_updates_live_thresholds(self):
        c = consumer()
        c.apply_detection_config({"slow_scan": {"min_unique_ips": 4}})
        assert c.slow_scan_detector.min_unique_ips == 4

    def test_reload_preserves_accumulated_state(self):
        """Rebuilding the detectors would discard the observation history.

        A detection is built from accumulated per-subnet counts. An operator
        LOWERING a threshold expects it to apply to what has already been seen;
        resetting the window would mean the change appears to do nothing until
        enough new traffic arrives.
        """
        c = consumer()
        c.slow_scan_detector.subnet_data["10.0.0.0/24"]["unique_ips"].add("10.0.0.7")
        c.ja4_intelligence.fingerprint_data["t13d1212h2_a_b"]["total_seen"] = 42
        before_slow = id(c.slow_scan_detector)

        c.apply_detection_config({"slow_scan": {"min_unique_ips": 2}})

        assert id(c.slow_scan_detector) == before_slow, "detector was replaced"
        assert "10.0.0.7" in c.slow_scan_detector.subnet_data["10.0.0.0/24"]["unique_ips"]
        assert c.ja4_intelligence.fingerprint_data["t13d1212h2_a_b"]["total_seen"] == 42

    def test_reload_to_empty_restores_defaults(self):
        c = consumer({"slow_scan": {"min_unique_ips": 4}})
        c.apply_detection_config({})
        assert c.slow_scan_detector.min_unique_ips == 20


class TestShippedConfig:
    """The shipped YAML must document the real defaults, not aspirational ones."""

    def test_analytics_yaml_detection_matches_code_defaults(self):
        cfg = yaml.safe_load((REPO / "config" / "analytics.yaml").read_text())
        detection = cfg.get("detection")
        assert detection, "config/analytics.yaml has no detection block"
        for section, expected in HISTORICAL.items():
            for key, value in expected.items():
                assert detection[section][key] == value, (
                    f"config/analytics.yaml detection.{section}.{key} is "
                    f"{detection[section][key]}, code default is {value} — the "
                    "file would mislead an operator reading it"
                )

    def test_shipped_config_actually_loads_into_detectors(self):
        cfg = yaml.safe_load((REPO / "config" / "analytics.yaml").read_text())
        c = consumer(cfg["detection"])
        assert c.slow_scan_detector.min_unique_ips == 20
        assert c.campaign_detector.density_threshold == 0.15
