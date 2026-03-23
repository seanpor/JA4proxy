# Unit Tests for Aggregation
# Phase 12a: Foundation

import time

import pytest

from src.analytics.aggregation import AggregationManager, HyperLogLogManager


class TestAggregationManager:
    """Test aggregation manager functionality."""
    
    def test_subnet_calculation(self):
        """Test subnet calculation for IPv4 and IPv6."""
        manager = AggregationManager()
        
        # Test IPv4
        assert manager.get_subnet("192.168.1.1") == "192.168.1.0/24"
        assert manager.get_subnet("10.0.0.1") == "10.0.0.0/24"
        assert manager.get_subnet("8.8.8.8") == "8.8.8.0/24"
        
        # Test IPv6
        assert manager.get_subnet("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::/48"
        assert manager.get_subnet("::1") == "::/48"  # Updated to match actual output
        
        # Test invalid
        assert manager.get_subnet("invalid.ip") == "invalid"
    
    def test_event_aggregation(self):
        """Test basic event aggregation."""
        manager = AggregationManager(window_seconds=300)
        
        # Create test events
        events = [
            {
                "timestamp": time.time(),
                "src_ip": "192.168.1.1",
                "ja4": "t13d1520h3_abc123",
                "action": "block",
                "score": 85,
                "proxy_id": "proxy-1"
            },
            {
                "timestamp": time.time(),
                "src_ip": "192.168.1.2",
                "ja4": "t13d1520h3_def456",
                "action": "allow",
                "score": 15,
                "proxy_id": "proxy-1"
            },
            {
                "timestamp": time.time(),
                "src_ip": "10.0.0.1",
                "ja4": "t13d1520h3_abc123",
                "action": "monitor",
                "score": 50,
                "proxy_id": "proxy-2"
            }
        ]
        
        # Process events
        for event in events:
            manager.update_aggregation(event)
        
        # Get results
        results = manager.get_aggregation_results()
        
        # Check subnet 192.168.1.0/24
        subnet1 = "192.168.1.0/24"
        assert subnet1 in results
        assert results[subnet1]["total_events"] == 2
        assert results[subnet1]["block_events"] == 1  # Updated to match actual key name
        assert results[subnet1]["allow_events"] == 1   # Updated to match actual key name
        assert results[subnet1]["monitor_events"] == 0  # Updated to match actual key name
        assert results[subnet1]["unique_ip_count"] == 2
        assert results[subnet1]["avg_score"] == 50.0  # (85 + 15) / 2
        
        # Check subnet 10.0.0.0/24
        subnet2 = "10.0.0.0/24"
        assert subnet2 in results
        assert results[subnet2]["total_events"] == 1
        assert results[subnet2]["monitor_events"] == 1  # Updated to match actual key name
        assert results[subnet2]["unique_ip_count"] == 1
        assert results[subnet2]["avg_score"] == 50.0
        
        # Check top JA4
        assert len(results[subnet1]["top_ja4"]) == 2
        assert results[subnet1]["top_ja4"][0]["ja4"] == "t13d1520h3_abc123"
        assert results[subnet1]["top_ja4"][0]["count"] == 1
    
    def test_window_rotation(self):
        """Test window rotation."""
        manager = AggregationManager(window_seconds=1)  # 1 second windows for testing
        
        # Add event in current window
        event = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1"
        }
        manager.update_aggregation(event)
        
        # Get current window
        current_window = int(time.time()) // 1
        assert manager.current_window == current_window
        
        # Wait for window rotation
        time.sleep(2.0)
        
        # Add another event (should trigger rotation)
        event2 = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.2",
            "ja4": "t13d1520h3_def456",
            "action": "allow",
            "score": 15,
            "proxy_id": "proxy-1"
        }
        manager.update_aggregation(event2)
        
        # Check that old data was cleared
        results = manager.get_aggregation_results()
        assert len(results) == 1  # Only the new window's data
        subnet = "192.168.1.0/24"
        assert results[subnet]["total_events"] == 1


class TestHyperLogLogManager:
    """Test HyperLogLog manager (set-based implementation for Phase 12a)."""
    
    def test_basic_operations(self):
        """Test basic HyperLogLog operations."""
        hll = HyperLogLogManager()
        
        # Add IPs
        hll.add_ip("192.168.1.0/24", "192.168.1.1")
        hll.add_ip("192.168.1.0/24", "192.168.1.2")
        hll.add_ip("192.168.1.0/24", "192.168.1.1")  # Duplicate
        hll.add_ip("10.0.0.0/24", "10.0.0.1")
        
        # Check counts
        assert hll.count_unique_ips("192.168.1.0/24") == 2
        assert hll.count_unique_ips("10.0.0.0/24") == 1
        assert hll.count_unique_ips("8.8.8.0/24") == 0
        
        # Check all counts
        all_counts = hll.get_all_counts()
        assert all_counts["192.168.1.0/24"] == 2
        assert all_counts["10.0.0.0/24"] == 1
        assert len(all_counts) == 2
    
    def test_multiple_subnets(self):
        """Test multiple subnets."""
        hll = HyperLogLogManager()
        
        # Add IPs to multiple subnets
        subnets = [
            ("192.168.1.0/24", ["192.168.1.1", "192.168.1.2", "192.168.1.3"]),
            ("10.0.0.0/24", ["10.0.0.1", "10.0.0.2"]),
            ("8.8.8.0/24", ["8.8.8.8"])
        ]
        
        for subnet, ips in subnets:
            for ip in ips:
                hll.add_ip(subnet, ip)
        
        # Verify counts
        for subnet, ips in subnets:
            assert hll.count_unique_ips(subnet) == len(ips)
        
        # Verify total
        all_counts = hll.get_all_counts()
        assert sum(all_counts.values()) == 6


class TestIntegration:
    """Test integration between aggregation and HyperLogLog."""
    
    def test_integrated_workflow(self):
        """Test integrated workflow of aggregation and HyperLogLog."""
        agg_manager = AggregationManager()
        hll_manager = HyperLogLogManager()
        
        # Create events
        events = [
            {
                "timestamp": time.time(),
                "src_ip": "192.168.1.1",
                "ja4": "t13d1520h3_abc123",
                "action": "block",
                "score": 85,
                "proxy_id": "proxy-1"
            },
            {
                "timestamp": time.time(),
                "src_ip": "192.168.1.2",
                "ja4": "t13d1520h3_def456",
                "action": "allow",
                "score": 15,
                "proxy_id": "proxy-1"
            },
            {
                "timestamp": time.time(),
                "src_ip": "192.168.1.1",  # Duplicate IP
                "ja4": "t13d1520h3_ghi789",
                "action": "monitor",
                "score": 50,
                "proxy_id": "proxy-2"
            }
        ]
        
        # Process events
        for event in events:
            # Update aggregation
            agg_manager.update_aggregation(event)
            
            # Update HyperLogLog
            subnet = agg_manager.get_subnet(event["src_ip"])
            hll_manager.add_ip(subnet, event["src_ip"])
        
        # Verify aggregation
        agg_results = agg_manager.get_aggregation_results()
        subnet = "192.168.1.0/24"
        assert agg_results[subnet]["total_events"] == 3
        assert agg_results[subnet]["unique_ip_count"] == 2
        
        # Verify HyperLogLog
        assert hll_manager.count_unique_ips(subnet) == 2
        
        # Verify consistency
        assert agg_results[subnet]["unique_ip_count"] == hll_manager.count_unique_ips(subnet)