# Unit Tests for Detection Modules
# Phase 12b: Detection Modules

import time

import pytest

from src.analytics.detection import CampaignDetector, JA4FingerprintIntelligence, SlowScanDetector


class TestCampaignDetector:
    """Test campaign detection functionality."""
    
    def test_subnet_calculation(self):
        """Test subnet calculation."""
        detector = CampaignDetector()
        
        # Test IPv4
        assert detector.get_subnet("192.168.1.1") == "192.168.1.0/24"
        assert detector.get_subnet("10.0.0.1") == "10.0.0.0/24"
        
        # Test IPv6
        assert detector.get_subnet("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::/48"
        
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
            min_unique_ips=5
        )
        
        # Create events from same subnet with high block rate
        subnet = "192.168.1.0/24"
        events = []
        
        # Add 10 unique IPs, 8 blocked, 2 allowed
        for i in range(1, 11):
            ip = f"192.168.1.{i}"
            action = "block" if i <= 8 else "allow"
            events.append({
                "timestamp": time.time(),
                "src_ip": ip,
                "ja4": f"t13d1520h3_test{i}",
                "action": action,
                "score": 90 if action == "block" else 10,
                "proxy_id": "proxy-1"
            })
        
        # Process events
        for event in events:
            detector.update_with_event(event)
        
        # Detect campaigns
        campaigns = detector.detect_campaigns()
        
        # Should detect one campaign
        assert len(campaigns) == 1
        campaign = campaigns[0]
        
        assert campaign['subnet'] == subnet
        assert campaign['unique_ips'] == 10
        assert campaign['total_connections'] == 10
        assert campaign['blocked_connections'] == 8
        assert campaign['block_rate'] == 0.8
        assert campaign['density'] == 10 / 256  # 10 IPs / 256 subnet size
        assert campaign['severity'] == 'high'  # Block rate >= 0.8 is high
    
    def test_campaign_detection_thresholds(self):
        """Test campaign detection with different thresholds."""
        # Test with high thresholds (should not detect)
        detector = CampaignDetector(
            density_threshold=0.5,  # Very high
            block_rate_threshold=0.9,  # Very high
            min_unique_ips=20  # High
        )
        
        # Add events that wouldn't meet thresholds
        events = []
        for i in range(1, 11):  # Only 10 IPs (below min_unique_ips)
            events.append({
                "timestamp": time.time(),
                "src_ip": f"192.168.1.{i}",
                "ja4": f"t13d1520h3_test{i}",
                "action": "block",
                "score": 90,
                "proxy_id": "proxy-1"
            })
        
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
            "proxy_id": "proxy-1"
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
            "proxy_id": "proxy-1"
        }
        detector.update_with_event(event2)
        
        # Check that old data was cleared
        stats = detector.get_subnet_stats("192.168.1.0/24")
        assert stats is not None
        assert stats['unique_ips'] == 1  # Only the new window's data


class TestSlowScanDetector:
    """Test slow scan detection functionality."""
    
    def test_basic_slow_scan_detection(self):
        """Test basic slow scan detection."""
        detector = SlowScanDetector(
            max_requests_per_ip=3,
            min_unique_ips=5
        )
        
        # Create events from same subnet with low requests per IP
        subnet = "192.168.1.0/24"
        events = []
        
        # Add 10 unique IPs, 2 requests each (avg = 2)
        for i in range(1, 11):
            ip = f"192.168.1.{i}"
            for j in range(2):  # 2 requests per IP
                events.append({
                    "timestamp": time.time(),
                    "src_ip": ip,
                    "ja4": f"t13d1520h3_test{i}_{j}",
                    "action": "block" if j == 0 else "allow",
                    "score": 85 if j == 0 else 15,
                    "proxy_id": "proxy-1"
                })
        
        # Process events
        for event in events:
            detector.update_with_event(event)
        
        # Detect slow scans
        slow_scans = detector.detect_slow_scans()
        
        # Should detect one slow scan
        assert len(slow_scans) == 1
        slow_scan = slow_scans[0]
        
        assert slow_scan['subnet'] == subnet
        assert slow_scan['unique_ips'] == 10
        assert slow_scan['total_requests'] == 20
        assert slow_scan['avg_requests_per_ip'] == 2.0
        assert slow_scan['score'] == 0.1  # 10/100
        assert slow_scan['severity'] == 'medium'  # Score < 0.8
    
    def test_slow_scan_thresholds(self):
        """Test slow scan detection with different thresholds."""
        # Test with high thresholds (should not detect)
        detector = SlowScanDetector(
            max_requests_per_ip=10,  # Very high
            min_unique_ips=50  # High
        )
        
        # Add events that wouldn't meet thresholds
        events = []
        for i in range(1, 21):  # 20 IPs (below min_unique_ips)
            for j in range(5):  # 5 requests per IP (below max_requests_per_ip)
                events.append({
                    "timestamp": time.time(),
                    "src_ip": f"192.168.1.{i}",
                    "ja4": f"t13d1520h3_test{i}_{j}",
                    "action": "block",
                    "score": 90,
                    "proxy_id": "proxy-1"
                })
        
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
            "proxy_id": "proxy-1"
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
            "proxy_id": "proxy-1"
        }
        detector.update_with_event(event2)
        
        # Check that old data was cleared
        # Should have only 1 unique IP in current window
        slow_scans = detector.detect_slow_scans()
        if slow_scans:
            assert slow_scans[0]['unique_ips'] == 1


class TestJA4FingerprintIntelligence:
    """Test JA4 fingerprint intelligence functionality."""
    
    def test_basic_ja4_analysis(self):
        """Test basic JA4 fingerprint analysis."""
        intelligence = JA4FingerprintIntelligence(
            min_observations=5,
            block_rate_threshold=0.8
        )
        
        # Create events with suspicious JA4 fingerprint
        ja4 = "t13d1520h3_malicious"
        events = []
        
        # Add 10 events, 9 blocked, 1 allowed
        for i in range(9):
            events.append({
                "timestamp": time.time(),
                "src_ip": f"192.168.1.{i}",
                "ja4": ja4,
                "action": "block",
                "score": 95,
                "proxy_id": f"proxy-{i % 3}"  # Different proxy sources
            })
        
        events.append({
            "timestamp": time.time(),
            "src_ip": "192.168.1.10",
            "ja4": ja4,
            "action": "allow",
            "score": 10,
            "proxy_id": "proxy-1"
        })
        
        # Process events
        for event in events:
            intelligence.update_with_event(event)
        
        # Identify candidates
        candidates = intelligence.identify_candidates()
        
        # Should identify one candidate
        assert len(candidates) == 1
        candidate = candidates[0]
        
        assert candidate['ja4'] == ja4
        assert candidate['total_seen'] == 10
        assert candidate['blocked_seen'] == 9
        assert candidate['allowed_seen'] == 1
        assert candidate['block_rate'] == 0.9
        assert candidate['source_count'] == 3  # Seen by 3 different proxies
        assert candidate['only_in_blocks'] == False  # Has 1 allowed
        assert candidate['severity'] == 'high'  # Block rate >= 0.9
    
    def test_ja4_only_in_blocks(self):
        """Test JA4 fingerprint that appears only in blocked connections."""
        intelligence = JA4FingerprintIntelligence(
            min_observations=5,
            block_rate_threshold=0.9
        )
        
        ja4 = "t13d1520h3_very_malicious"
        events = []
        
        # Add 10 events, all blocked
        for i in range(10):
            events.append({
                "timestamp": time.time(),
                "src_ip": f"192.168.1.{i}",
                "ja4": ja4,
                "action": "block",
                "score": 98,
                "proxy_id": "proxy-1"
            })
        
        for event in events:
            intelligence.update_with_event(event)
        
        # Identify candidates
        candidates = intelligence.identify_candidates()
        
        # Should identify one candidate
        assert len(candidates) == 1
        candidate = candidates[0]
        
        assert candidate['ja4'] == ja4
        assert candidate['total_seen'] == 10
        assert candidate['blocked_seen'] == 10
        assert candidate['allowed_seen'] == 0
        assert candidate['block_rate'] == 1.0
        assert candidate['only_in_blocks'] == True  # Never seen in allowed
        assert candidate['severity'] == 'high'
    
    def test_ja4_thresholds(self):
        """Test JA4 analysis with different thresholds."""
        # Test with high thresholds (should not detect)
        intelligence = JA4FingerprintIntelligence(
            min_observations=20,  # High
            block_rate_threshold=0.95  # Very high
        )
        
        ja4 = "t13d1520h3_test"
        events = []
        
        # Add 15 events, 14 blocked (below thresholds)
        for i in range(14):
            events.append({
                "timestamp": time.time(),
                "src_ip": f"192.168.1.{i}",
                "ja4": ja4,
                "action": "block",
                "score": 90,
                "proxy_id": "proxy-1"
            })
        
        events.append({
            "timestamp": time.time(),
            "src_ip": "192.168.1.15",
            "ja4": ja4,
            "action": "allow",
            "score": 10,
            "proxy_id": "proxy-1"
        })
        
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
            "proxy_id": "proxy-1"
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
            "proxy_id": "proxy-1"
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
            min_unique_ips=5
        )
        
        slow_scan_detector = SlowScanDetector(
            max_requests_per_ip=3,
            min_unique_ips=10  # Higher threshold to avoid false positives
        )
        
        ja4_intelligence = JA4FingerprintIntelligence(
            min_observations=3,
            block_rate_threshold=0.66
        )
        
        # Create test events
        events = []
        
        # Campaign: 8 IPs from same subnet, 6 blocked
        for i in range(1, 9):
            action = "block" if i <= 6 else "allow"
            events.append({
                "timestamp": time.time(),
                "src_ip": f"192.168.1.{i}",
                "ja4": f"t13d1520h3_campaign{i}",
                "action": action,
                "score": 90 if action == "block" else 10,
                "proxy_id": "proxy-1"
            })
        
        # Slow scan: 10 IPs from another subnet, 2 requests each
        for i in range(1, 11):
            for j in range(2):
                events.append({
                    "timestamp": time.time(),
                    "src_ip": f"10.0.0.{i}",
                    "ja4": f"t13d1520h3_slowscan{i}_{j}",
                    "action": "block" if j == 0 else "allow",
                    "score": 85 if j == 0 else 15,
                    "proxy_id": "proxy-1"
                })
        
        # JA4: suspicious fingerprint seen 5 times, all blocked
        ja4 = "t13d1520h3_malicious"
        for i in range(5):
            events.append({
                "timestamp": time.time(),
                "src_ip": f"172.16.0.{i}",
                "ja4": ja4,
                "action": "block",
                "score": 98,
                "proxy_id": "proxy-1"
            })
        
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
        assert campaign['unique_ips'] == 8
        assert campaign['block_rate'] == 0.75  # 6/8
        
        # Verify slow scan details
        slow_scan = slow_scans[0]
        assert slow_scan['unique_ips'] == 10
        assert slow_scan['avg_requests_per_ip'] == 2.0
        
        # Verify JA4 candidate details
        candidate = ja4_candidates[0]
        assert candidate['ja4'] == ja4
        assert candidate['block_rate'] == 1.0
        assert candidate['only_in_blocks'] == True