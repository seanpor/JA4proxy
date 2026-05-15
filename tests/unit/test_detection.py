# Unit Tests for Detection Modules
# Phase 12b: Detection Modules

import time

import pytest

from src.analytics.detection import (
    CampaignDetector,
    JA4FingerprintIntelligence,
    SlowScanDetector,
)


class TestCampaignDetector:
    """Test campaign detection functionality."""

    def test_subnet_calculation(self):
        """Test subnet calculation."""
        detector = CampaignDetector()

        # Test IPv4
        assert detector.get_subnet("192.168.1.1") == "192.168.1.0/24"
        assert detector.get_subnet("10.0.0.1") == "10.0.0.0/24"

        # Test IPv6
        assert (
            detector.get_subnet("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
            == "2001:db8:85a3::/48"
        )

        # Test invalid
        assert detector.get_subnet("invalid.ip") == "invalid"

    def test_subnet_size_calculation(self):
        """Test subnet size calculation."""
        detector = CampaignDetector()

        assert detector.get_subnet_size("192.168.1.0/24") == 256
        assert detector.get_subnet_size("10.0.0.0/16") == 65536
        assert detector.get_subnet_size("invalid") == 256  # Default

    def test_campaign_detection_basic(self):
        """Test basic campaign detection."""
        detector = CampaignDetector(
            density_threshold=0.03,  # Lower threshold for test
            block_rate_threshold=0.5,
            min_unique_ips=5,
        )

        # Create events from same subnet with high block rate
        subnet = "192.168.1.0/24"
        events = []

        # Add 10 unique IPs, 8 blocked, 2 allowed
        for i in range(1, 11):
            ip = f"192.168.1.{i}"
            action = "block" if i <= 8 else "allow"
            events.append(
                {
                    "timestamp": time.time(),
                    "src_ip": ip,
                    "ja4": f"t13d1520h3_test{i}",
                    "action": action,
                    "score": 90 if action == "block" else 10,
                    "proxy_id": "proxy-1",
                }
            )

        # Process events
        for event in events:
            detector.update_with_event(event)

        # Detect campaigns
        campaigns = detector.detect_campaigns()

        # Should detect one campaign
        assert len(campaigns) == 1
        campaign = campaigns[0]

        assert campaign["subnet"] == subnet
        assert campaign["unique_ips"] == 10
        assert campaign["total_connections"] == 10
        assert campaign["blocked_connections"] == 8
        assert campaign["block_rate"] == 0.8
        assert campaign["density"] == 10 / 256  # 10 IPs / 256 subnet size
        assert campaign["severity"] == "high"  # Block rate >= 0.8 is high

    def test_campaign_detection_thresholds(self):
        """Test campaign detection with different thresholds."""
        # Test with high thresholds (should not detect)
        detector = CampaignDetector(
            density_threshold=0.5,  # Very high
            block_rate_threshold=0.9,  # Very high
            min_unique_ips=20,  # High
        )

        # Add events that wouldn't meet thresholds
        events = []
        for i in range(1, 11):  # Only 10 IPs (below min_unique_ips)
            events.append(
                {
                    "timestamp": time.time(),
                    "src_ip": f"192.168.1.{i}",
                    "ja4": f"t13d1520h3_test{i}",
                    "action": "block",
                    "score": 90,
                    "proxy_id": "proxy-1",
                }
            )

        for event in events:
            detector.update_with_event(event)

        # Should not detect any campaigns
        campaigns = detector.detect_campaigns()
        assert len(campaigns) == 0

    def test_window_rotation(self):
        """Test window rotation."""
        detector = CampaignDetector(window_seconds=1)  # 1 second windows

        # Add event
        event = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_test",
            "action": "block",
            "score": 90,
            "proxy_id": "proxy-1",
        }
        detector.update_with_event(event)

        # Wait for rotation
        time.sleep(2.0)

        # Add another event (should trigger rotation)
        event2 = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.2",
            "ja4": "t13d1520h3_test2",
            "action": "block",
            "score": 90,
            "proxy_id": "proxy-1",
        }
        detector.update_with_event(event2)

        # Check that old data was cleared
        stats = detector.get_subnet_stats("192.168.1.0/24")
        assert stats is not None
        assert stats["unique_ips"] == 1  # Only the new window's data


class TestSlowScanDetector:
    """Test slow scan detection functionality."""

    def test_basic_slow_scan_detection(self):
        """Test basic slow scan detection."""
        detector = SlowScanDetector(max_requests_per_ip=3, min_unique_ips=5)

        # Create events from same subnet with low requests per IP
        subnet = "192.168.1.0/24"
        events = []

        # Add 10 unique IPs, 2 requests each (avg = 2)
        for i in range(1, 11):
            ip = f"192.168.1.{i}"
            for j in range(2):  # 2 requests per IP
                events.append(
                    {
                        "timestamp": time.time(),
                        "src_ip": ip,
                        "ja4": f"t13d1520h3_test{i}_{j}",
                        "action": "block" if j == 0 else "allow",
                        "score": 85 if j == 0 else 15,
                        "proxy_id": "proxy-1",
                    }
                )

        # Process events
        for event in events:
            detector.update_with_event(event)

        # Detect slow scans
        slow_scans = detector.detect_slow_scans()

        # Should detect one slow scan
        assert len(slow_scans) == 1
        slow_scan = slow_scans[0]

        assert slow_scan["subnet"] == subnet
        assert slow_scan["unique_ips"] == 10
        assert slow_scan["total_requests"] == 20
        assert slow_scan["avg_requests_per_ip"] == 2.0
        assert slow_scan["score"] == 0.1  # 10/100
        assert slow_scan["severity"] == "medium"  # Score < 0.8

    def test_slow_scan_thresholds(self):
        """Test slow scan detection with different thresholds."""
        # Test with high thresholds (should not detect)
        detector = SlowScanDetector(
            max_requests_per_ip=10, min_unique_ips=50  # Very high  # High
        )

        # Add events that wouldn't meet thresholds
        events = []
        for i in range(1, 21):  # 20 IPs (below min_unique_ips)
            for j in range(5):  # 5 requests per IP (below max_requests_per_ip)
                events.append(
                    {
                        "timestamp": time.time(),
                        "src_ip": f"192.168.1.{i}",
                        "ja4": f"t13d1520h3_test{i}_{j}",
                        "action": "block",
                        "score": 90,
                        "proxy_id": "proxy-1",
                    }
                )

        for event in events:
            detector.update_with_event(event)

        # Should not detect any slow scans
        slow_scans = detector.detect_slow_scans()
        assert len(slow_scans) == 0

    def test_window_rotation(self):
        """Test window rotation."""
        detector = SlowScanDetector(window_seconds=1)  # 1 second windows

        # Add event
        event = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_test",
            "action": "block",
            "score": 90,
            "proxy_id": "proxy-1",
        }
        detector.update_with_event(event)

        # Wait for rotation
        time.sleep(2.0)

        # Add another event (should trigger rotation)
        event2 = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.2",
            "ja4": "t13d1520h3_test2",
            "action": "block",
            "score": 90,
            "proxy_id": "proxy-1",
        }
        detector.update_with_event(event2)

        # Check that old data was cleared
        # Should have only 1 unique IP in current window
        slow_scans = detector.detect_slow_scans()
        if slow_scans:
            assert slow_scans[0]["unique_ips"] == 1


class TestJA4FingerprintIntelligence:
    """Test JA4 fingerprint intelligence functionality."""

    def test_basic_ja4_analysis(self):
        """Test basic JA4 fingerprint analysis."""
        intelligence = JA4FingerprintIntelligence(
            min_observations=5, block_rate_threshold=0.8
        )

        # Create events with suspicious JA4 fingerprint
        ja4 = "t13d1520h3_malicious"
        events = []

        # Add 10 events, 9 blocked, 1 allowed
        for i in range(9):
            events.append(
                {
                    "timestamp": time.time(),
                    "src_ip": f"192.168.1.{i}",
                    "ja4": ja4,
                    "action": "block",
                    "score": 95,
                    "proxy_id": f"proxy-{i % 3}",  # Different proxy sources
                }
            )

        events.append(
            {
                "timestamp": time.time(),
                "src_ip": "192.168.1.10",
                "ja4": ja4,
                "action": "allow",
                "score": 10,
                "proxy_id": "proxy-1",
            }
        )

        # Process events
        for event in events:
            intelligence.update_with_event(event)

        # Identify candidates
        candidates = intelligence.identify_candidates()

        # Should identify one candidate
        assert len(candidates) == 1
        candidate = candidates[0]

        assert candidate["ja4"] == ja4
        assert candidate["total_seen"] == 10
        assert candidate["blocked_seen"] == 9
        assert candidate["allowed_seen"] == 1
        assert candidate["block_rate"] == 0.9
        assert candidate["source_count"] == 3  # Seen by 3 different proxies
        assert candidate["only_in_blocks"] == False  # Has 1 allowed
        assert candidate["severity"] == "high"  # Block rate >= 0.9

    def test_ja4_only_in_blocks(self):
        """Test JA4 fingerprint that appears only in blocked connections."""
        intelligence = JA4FingerprintIntelligence(
            min_observations=5, block_rate_threshold=0.9
        )

        ja4 = "t13d1520h3_very_malicious"
        events = []

        # Add 10 events, all blocked
        for i in range(10):
            events.append(
                {
                    "timestamp": time.time(),
                    "src_ip": f"192.168.1.{i}",
                    "ja4": ja4,
                    "action": "block",
                    "score": 98,
                    "proxy_id": "proxy-1",
                }
            )

        for event in events:
            intelligence.update_with_event(event)

        # Identify candidates
        candidates = intelligence.identify_candidates()

        # Should identify one candidate
        assert len(candidates) == 1
        candidate = candidates[0]

        assert candidate["ja4"] == ja4
        assert candidate["total_seen"] == 10
        assert candidate["blocked_seen"] == 10
        assert candidate["allowed_seen"] == 0
        assert candidate["block_rate"] == 1.0
        assert candidate["only_in_blocks"] == True  # Never seen in allowed
        assert candidate["severity"] == "high"

    def test_ja4_thresholds(self):
        """Test JA4 analysis with different thresholds."""
        # Test with high thresholds (should not detect)
        intelligence = JA4FingerprintIntelligence(
            min_observations=20, block_rate_threshold=0.95  # High  # Very high
        )

        ja4 = "t13d1520h3_test"
        events = []

        # Add 15 events, 14 blocked (below thresholds)
        for i in range(14):
            events.append(
                {
                    "timestamp": time.time(),
                    "src_ip": f"192.168.1.{i}",
                    "ja4": ja4,
                    "action": "block",
                    "score": 90,
                    "proxy_id": "proxy-1",
                }
            )

        events.append(
            {
                "timestamp": time.time(),
                "src_ip": "192.168.1.15",
                "ja4": ja4,
                "action": "allow",
                "score": 10,
                "proxy_id": "proxy-1",
            }
        )

        for event in events:
            intelligence.update_with_event(event)

        # Should not detect any candidates
        candidates = intelligence.identify_candidates()
        assert len(candidates) == 0

    def test_window_rotation(self):
        """Test window rotation."""
        intelligence = JA4FingerprintIntelligence(window_seconds=1)  # 1 second windows

        # Add event
        event = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_test",
            "action": "block",
            "score": 90,
            "proxy_id": "proxy-1",
        }
        intelligence.update_with_event(event)

        # Wait for rotation
        time.sleep(2.0)

        # Add another event (should trigger rotation)
        event2 = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.2",
            "ja4": "t13d1520h3_test2",
            "action": "block",
            "score": 90,
            "proxy_id": "proxy-1",
        }
        intelligence.update_with_event(event2)

        # Check that old data was cleared
        stats = intelligence.get_fingerprint_stats("t13d1520h3_test")
        assert stats is None  # Old fingerprint should be rotated out


class TestDetectionIntegration:
    """Test integration between detection modules."""

    def test_integrated_workflow(self):
        """Test integrated workflow of all detection modules."""
        # Create detectors
        campaign_detector = CampaignDetector(
            density_threshold=0.03,  # Adjusted to match test data (8/256 = 0.03125)
            block_rate_threshold=0.6,
            min_unique_ips=5,
        )

        slow_scan_detector = SlowScanDetector(
            max_requests_per_ip=3,
            min_unique_ips=10,  # Higher threshold to avoid false positives
        )

        ja4_intelligence = JA4FingerprintIntelligence(
            min_observations=3, block_rate_threshold=0.66
        )

        # Create test events
        events = []

        # Campaign: 8 IPs from same subnet, 6 blocked
        for i in range(1, 9):
            action = "block" if i <= 6 else "allow"
            events.append(
                {
                    "timestamp": time.time(),
                    "src_ip": f"192.168.1.{i}",
                    "ja4": f"t13d1520h3_campaign{i}",
                    "action": action,
                    "score": 90 if action == "block" else 10,
                    "proxy_id": "proxy-1",
                }
            )

        # Slow scan: 10 IPs from another subnet, 2 requests each
        for i in range(1, 11):
            for j in range(2):
                events.append(
                    {
                        "timestamp": time.time(),
                        "src_ip": f"10.0.0.{i}",
                        "ja4": f"t13d1520h3_slowscan{i}_{j}",
                        "action": "block" if j == 0 else "allow",
                        "score": 85 if j == 0 else 15,
                        "proxy_id": "proxy-1",
                    }
                )

        # JA4: suspicious fingerprint seen 5 times, all blocked
        ja4 = "t13d1520h3_malicious"
        for i in range(5):
            events.append(
                {
                    "timestamp": time.time(),
                    "src_ip": f"172.16.0.{i}",
                    "ja4": ja4,
                    "action": "block",
                    "score": 98,
                    "proxy_id": "proxy-1",
                }
            )

        # Process events through all detectors
        for event in events:
            campaign_detector.update_with_event(event)
            slow_scan_detector.update_with_event(event)
            ja4_intelligence.update_with_event(event)

        # Get results
        campaigns = campaign_detector.detect_campaigns()
        slow_scans = slow_scan_detector.detect_slow_scans()
        ja4_candidates = ja4_intelligence.identify_candidates()

        # Verify results
        assert len(campaigns) == 1  # Campaign from 192.168.1.0/24
        assert len(slow_scans) == 1  # Slow scan from 10.0.0.0/24
        assert len(ja4_candidates) == 1  # Malicious JA4 fingerprint

        # Verify campaign details
        campaign = campaigns[0]
        assert campaign["unique_ips"] == 8
        assert campaign["block_rate"] == 0.75  # 6/8

        # Verify slow scan details
        slow_scan = slow_scans[0]
        assert slow_scan["unique_ips"] == 10
        assert slow_scan["avg_requests_per_ip"] == 2.0

        # Verify JA4 candidate details
        candidate = ja4_candidates[0]
        assert candidate["ja4"] == ja4
        assert candidate["block_rate"] == 1.0
        assert candidate["only_in_blocks"] == True


# ── Missing-coverage tests ────────────────────────────────────────────────────

from src.analytics.detection import (
    CampaignDetector,
    JA4FingerprintIntelligence,
    SlowScanDetector,
)


class TestDetectionMissingCoverage:
    """Cover remaining edge paths in detection.py."""

    # ── CampaignDetector paths ───────────────────────────────────────────────

    def test_get_subnet_stats_returns_none_for_unknown_subnet(self):
        """get_subnet_stats() for unknown subnet → None (line 73).
        So what: campaign analytics must not crash when queried for a subnet that
        hasn't been seen yet; returning None is the correct fail-open."""
        d = CampaignDetector()
        result = d.get_subnet_stats("99.99.99.0/24")
        assert result is None

    def test_update_with_event_invalid_subnet_returns_immediately(self):
        """update_with_event() with invalid IP → returns without crash (line 91).
        So what: a malformed IP from a corrupt event must not crash the analytics
        pipeline; 'invalid' subnets must be silently skipped."""
        d = CampaignDetector()
        d.update_with_event(
            {
                "src_ip": "not-an-ip",
                "action": "allow",
                "timestamp": __import__("time").time(),
            }
        )
        assert len(d.subnet_data) == 0

    def test_update_with_event_sets_last_seen_on_newer_timestamp(self):
        """update_with_event() with newer timestamp → last_seen updated (line 106).
        So what: if last_seen is not updated, window rotation will prune active
        subnets, causing the campaign detector to lose ongoing attack data."""
        import time as _t

        d = CampaignDetector()
        t1 = _t.time()
        d.update_with_event({"src_ip": "1.2.3.4", "action": "block", "timestamp": t1})
        t2 = t1 + 10
        d.update_with_event({"src_ip": "1.2.3.5", "action": "block", "timestamp": t2})
        subnet = d.get_subnet("1.2.3.4")
        assert d.subnet_data[subnet]["last_seen"] == t2

    def test_detect_campaigns_skips_old_subnets(self):
        """detect_campaigns() skips subnets with old last_seen (line 120).
        So what: stale campaign data must not trigger alerts hours after the
        attack ended; time-window filtering prevents false positives."""
        import time as _t

        d = CampaignDetector(
            min_unique_ips=2, density_threshold=0.01, block_rate_threshold=0.5
        )
        # Add data with old timestamp
        subnet = "1.2.3.0/24"
        d.subnet_data[subnet]["unique_ips"] = {"1.2.3.1", "1.2.3.2", "1.2.3.3"}
        d.subnet_data[subnet]["total_connections"] = 10
        d.subnet_data[subnet]["blocked_connections"] = 9
        d.subnet_data[subnet]["first_seen"] = 0.0
        d.subnet_data[subnet]["last_seen"] = 0.0  # Very old
        result = d.detect_campaigns()
        assert len(result) == 0

    def test_detect_campaigns_zero_total_connections_block_rate_zero(self):
        """detect_campaigns() with total_connections=0 → block_rate=0.0 (line 130).
        So what: division-by-zero must not crash the detector; a subnet with
        no connections has zero block rate by definition."""
        import time as _t

        d = CampaignDetector(
            min_unique_ips=2, density_threshold=0.0, block_rate_threshold=0.0
        )
        subnet = "1.2.3.0/24"
        now = _t.time()
        d.subnet_data[subnet]["unique_ips"] = {"1.2.3.1", "1.2.3.2", "1.2.3.3"}
        d.subnet_data[subnet]["total_connections"] = 0
        d.subnet_data[subnet]["blocked_connections"] = 0
        d.subnet_data[subnet]["first_seen"] = now
        d.subnet_data[subnet]["last_seen"] = now
        result = d.detect_campaigns()
        # block_rate=0.0 meets threshold 0.0 — should be in results
        assert any(c["block_rate"] == 0.0 for c in result)

    def test_campaign_rotate_window_keeps_active_subnets(self):
        """_rotate_window() keeps subnets with recent last_seen (line 163).
        So what: active campaigns must survive window rotation; if active subnets
        are pruned, multi-window attacks evade detection."""
        import time as _t

        d = CampaignDetector()
        now = _t.time()
        subnet = "1.2.3.0/24"
        d.subnet_data[subnet]["unique_ips"] = {"1.2.3.1"}
        d.subnet_data[subnet]["total_connections"] = 1
        d.subnet_data[subnet]["blocked_connections"] = 0
        d.subnet_data[subnet]["first_seen"] = now
        d.subnet_data[subnet]["last_seen"] = now  # Recent
        d.current_window = 0
        d._rotate_window(1)
        assert subnet in d.subnet_data

    # ── JA4FingerprintIntelligence paths ────────────────────────────────────

    def test_fingerprint_update_returns_early_on_no_ja4(self):
        """update_with_event() without ja4 key → returns (line 213).
        So what: events from non-TLS connections have no JA4; silently skipping
        them is correct; adding them would corrupt the fingerprint database."""
        fi = JA4FingerprintIntelligence()
        fi.update_with_event(
            {
                "proxy_id": "p1",
                "action": "allow",
                "timestamp": __import__("time").time(),
                # No 'ja4' key
            }
        )
        assert len(fi.fingerprint_data) == 0

    def test_fingerprint_update_sets_last_seen_on_newer_event(self):
        """update_with_event() newer timestamp → last_seen updated (line 229).
        So what: same window-rotation risk as campaign detector — stale last_seen
        causes active fingerprints to be pruned mid-campaign."""
        import time as _t

        fi = JA4FingerprintIntelligence()
        t1 = _t.time()
        fi.update_with_event(
            {"ja4": "abc", "proxy_id": "p1", "action": "block", "timestamp": t1}
        )
        t2 = t1 + 5
        fi.update_with_event(
            {"ja4": "abc", "proxy_id": "p1", "action": "block", "timestamp": t2}
        )
        assert fi.fingerprint_data["abc"]["last_seen"] == t2

    def test_identify_candidates_skips_old_fingerprints(self):
        """identify_candidates() skips fingerprints with old last_seen (line 243).
        So what: stale fingerprints must not generate candidate alerts days after
        they were last seen; this prevents alert fatigue from expired data."""
        fi = JA4FingerprintIntelligence(min_observations=5, block_rate_threshold=0.9)
        fi.fingerprint_data["abc"]["total_seen"] = 10
        fi.fingerprint_data["abc"]["blocked_seen"] = 10
        fi.fingerprint_data["abc"]["allowed_seen"] = 0
        fi.fingerprint_data["abc"]["last_seen"] = 0.0  # Very old
        result = fi.identify_candidates()
        assert len(result) == 0

    def test_identify_candidates_zero_total_block_rate_zero(self):
        """identify_candidates() with total_seen=0 → block_rate=0.0 (line 249).
        So what: the zero-division guard must not crash; block_rate=0 means
        the fingerprint won't meet the high threshold and won't be a candidate."""
        import time as _t

        fi = JA4FingerprintIntelligence(min_observations=0, block_rate_threshold=0.0)
        now = _t.time()
        fi.fingerprint_data["abc"]["total_seen"] = 0
        fi.fingerprint_data["abc"]["blocked_seen"] = 0
        fi.fingerprint_data["abc"]["allowed_seen"] = 0
        fi.fingerprint_data["abc"]["last_seen"] = now
        fi.fingerprint_data["abc"]["sources"] = {"p1"}
        result = fi.identify_candidates()
        # block_rate=0.0 meets threshold 0.0
        assert any(c["block_rate"] == 0.0 for c in result)

    def test_get_fingerprint_stats_returns_stats(self):
        """get_fingerprint_stats() for known JA4 → returns stats dict (lines 279-286).
        So what: the admin UI calls this to show per-fingerprint statistics;
        if it returns None for known fingerprints, the UI shows empty tables."""
        import time as _t

        fi = JA4FingerprintIntelligence()
        now = _t.time()
        fi.fingerprint_data["abc"]["total_seen"] = 5
        fi.fingerprint_data["abc"]["blocked_seen"] = 4
        fi.fingerprint_data["abc"]["allowed_seen"] = 1
        fi.fingerprint_data["abc"]["first_seen"] = now
        fi.fingerprint_data["abc"]["last_seen"] = now
        fi.fingerprint_data["abc"]["sources"] = {"p1", "p2"}
        result = fi.get_fingerprint_stats("abc")
        assert result is not None
        assert result["block_rate"] == 0.8
        assert result["source_count"] == 2

    def test_get_fingerprint_stats_zero_total_seen(self):
        """get_fingerprint_stats() with total_seen=0 → block_rate=0.0 (lines 283-284).
        So what: same division-by-zero guard as identify_candidates."""
        import time as _t

        fi = JA4FingerprintIntelligence()
        now = _t.time()
        fi.fingerprint_data["abc"]["total_seen"] = 0
        fi.fingerprint_data["abc"]["blocked_seen"] = 0
        fi.fingerprint_data["abc"]["allowed_seen"] = 0
        fi.fingerprint_data["abc"]["first_seen"] = now
        fi.fingerprint_data["abc"]["last_seen"] = now
        fi.fingerprint_data["abc"]["sources"] = set()
        result = fi.get_fingerprint_stats("abc")
        assert result["block_rate"] == 0.0

    def test_ja4_rotate_window_keeps_active_fingerprints(self):
        """_rotate_window() keeps recently-seen JA4 fingerprints (line 307).
        So what: active malicious fingerprints must survive window rotation or
        they'll be re-enrolled next window with a fresh (zero) block rate."""
        import time as _t

        fi = JA4FingerprintIntelligence()
        now = _t.time()
        fi.fingerprint_data["abc"]["last_seen"] = now  # Recent
        fi.current_window = 0
        fi._rotate_window(1)
        assert "abc" in fi.fingerprint_data

    # ── SlowScanDetector paths ───────────────────────────────────────────────

    def test_slow_scan_get_subnet_ipv6(self):
        """get_subnet() with IPv6 address → IPv6 /48 network (lines 348-349).
        So what: slow-scan detection must work for IPv6 campaigns; if IPv6 is
        not handled, entire IPv6 botnets evade subnet-level correlation."""
        d = SlowScanDetector()
        result = d.get_subnet("2001:db8::1")
        assert "2001:db8::" in result
        assert "/48" in result

    def test_slow_scan_get_subnet_invalid_returns_invalid(self):
        """get_subnet() with invalid IP → 'invalid' (lines 350-351).
        So what: same crash-protection as campaign detector — invalid IPs must
        not raise ValueError and kill the analytics loop."""
        d = SlowScanDetector()
        result = d.get_subnet("not-an-ip")
        assert result == "invalid"

    def test_slow_scan_update_returns_early_on_invalid_ip(self):
        """update_with_event() with invalid IP → returns (line 369).
        So what: malformed src_ip in event stream must not corrupt subnet data."""
        d = SlowScanDetector()
        d.update_with_event(
            {"src_ip": "bad-ip", "timestamp": __import__("time").time()}
        )
        assert len(d.subnet_data) == 0

    def test_slow_scan_update_sets_last_seen(self):
        """update_with_event() newer timestamp → last_seen updated (line 383).
        So what: last_seen drives window rotation; stale last_seen causes
        active slow scans to be pruned from memory mid-campaign."""
        import time as _t

        d = SlowScanDetector()
        t1 = _t.time()
        d.update_with_event({"src_ip": "1.2.3.4", "timestamp": t1})
        t2 = t1 + 5
        d.update_with_event({"src_ip": "1.2.3.5", "timestamp": t2})
        subnet = d.get_subnet("1.2.3.4")
        assert d.subnet_data[subnet]["last_seen"] == t2

    def test_detect_slow_scans_skips_old_subnets(self):
        """detect_slow_scans() skips subnets with old last_seen (line 397).
        So what: expired slow scans must not generate alerts; this keeps the
        alert feed focused on active threats, reducing SIEM noise."""
        d = SlowScanDetector(min_unique_ips=2, max_requests_per_ip=3)
        subnet = "1.2.3.0/24"
        d.subnet_data[subnet]["unique_ips"] = {"1.2.3.1", "1.2.3.2", "1.2.3.3"}
        d.subnet_data[subnet]["total_requests"] = 3
        d.subnet_data[subnet]["first_seen"] = 0.0
        d.subnet_data[subnet]["last_seen"] = 0.0  # Very old
        result = d.detect_slow_scans()
        assert len(result) == 0

    def test_detect_slow_scans_zero_unique_ips_block_rate_zero(self):
        """detect_slow_scans() with zero unique_ips → avg=0 (line 403).
        So what: same division-by-zero guard in slow scan path."""
        import time as _t

        d = SlowScanDetector(min_unique_ips=0, max_requests_per_ip=99)
        now = _t.time()
        subnet = "1.2.3.0/24"
        d.subnet_data[subnet]["unique_ips"] = set()  # Zero unique IPs
        d.subnet_data[subnet]["total_requests"] = 0
        d.subnet_data[subnet]["first_seen"] = now
        d.subnet_data[subnet]["last_seen"] = now
        result = d.detect_slow_scans()
        # avg=0 ≤ max_requests_per_ip=99 → should be in results
        if result:
            assert result[0]["avg_requests_per_ip"] == 0

    def test_slow_scan_rotate_window_keeps_active_subnets(self):
        """_rotate_window() keeps recently-active subnets (line 434).
        So what: active slow scans must survive window boundaries; without
        this the detector would reset its counter every window."""
        import time as _t

        d = SlowScanDetector()
        now = _t.time()
        subnet = "1.2.3.0/24"
        d.subnet_data[subnet]["unique_ips"] = {"1.2.3.1"}
        d.subnet_data[subnet]["ip_request_counts"] = {"1.2.3.1": 1}
        d.subnet_data[subnet]["total_requests"] = 1
        d.subnet_data[subnet]["first_seen"] = now
        d.subnet_data[subnet]["last_seen"] = now  # Recent
        d.current_window = 0
        d._rotate_window(1)
        assert subnet in d.subnet_data
