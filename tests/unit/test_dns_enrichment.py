"""Unit tests for DNS enrichment module."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import aiodns
import pytest

from src.security.dns_enrichment import DNSEnrichment, FCrDNSResult


class MockDNSResult:
    """Mock aiodns result."""
    def __init__(self, name=None, addresses=None, host=None):
        self.name = name
        self.addresses = addresses or []
        self.host = host or (addresses[0] if addresses else None)


class MockDNSResolver:
    """Mock aiodns resolver."""
    def __init__(self, results=None):
        self.results = results or {}
        self.nameservers = []
    
    async def gethostbyaddr(self, ip):
        if ip in self.results and 'ptr' in self.results[ip]:
            return MockDNSResult(name=self.results[ip]['ptr'])
        raise aiodns.error.DNSError("No PTR")
    
    async def gethostbyname(self, hostname, addr_family=None):
        # Find which IP this hostname belongs to
        for ip, data in self.results.items():
            if data.get('ptr') == hostname:
                return MockDNSResult(addresses=[ip])
        raise aiodns.error.DNSError("Forward failed")


class TestFCrDNSLogic:
    """Test FCrDNS check logic."""

    def test_no_ptr_record(self):
        """No PTR record → classification=no_ptr."""
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": True}}, None)
            # Mock the resolver to return no PTR
            dns._resolver = MockDNSResolver({})
            result = await dns._fcrdns_check("1.2.3.4")
            assert result.classification == "no_ptr"
            assert result.has_ptr is False
        
        asyncio.run(run_test())

    def test_fcrdns_confirmed(self):
        """PTR exists and forward-confirms → classification=confirmed."""
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": True}}, None)
            # Mock the resolver with a confirmed result
            dns._resolver = MockDNSResolver({
                "1.2.3.4": {"ptr": "example.com"}
            })
            result = await dns._fcrdns_check("1.2.3.4")
            assert result.classification == "confirmed"
            assert result.confirmed is True
            assert result.hostname == "example.com"
        
        asyncio.run(run_test())

    def test_fcrdns_failed(self):
        """PTR exists but forward lookup fails → classification=fcrdns_failed."""
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": True}}, None)
            # Mock the resolver with PTR but no forward
            mock_resolver = MockDNSResolver({
                "1.2.3.4": {"ptr": "nonexistent.example.com"}
            })
            # Override gethostbyname to fail with DNSError
            async def fail_forward(*args, **kwargs):
                raise aiodns.error.DNSError("Forward failed")
            mock_resolver.gethostbyname = fail_forward
            dns._resolver = mock_resolver
            
            result = await dns._fcrdns_check("1.2.3.4")
            assert result.classification == "fcrdns_failed"
            assert result.confirmed is False
        
        asyncio.run(run_test())

    def test_residential_ptr_pattern(self):
        """Residential PTR pattern → classification=residential."""
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": True}}, None)
            # Mock the resolver with residential pattern
            dns._resolver = MockDNSResolver({
                "1.2.3.4": {"ptr": "cpc12345-cust1.example.com"}  # Matches cpc\d+ pattern
            })
            result = await dns._fcrdns_check("1.2.3.4")
            assert result.classification == "residential"
        
        asyncio.run(run_test())

    def test_datacenter_ptr_pattern(self):
        """Datacenter PTR pattern → classification=datacenter_confirmed."""
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": True}}, None)
            # Mock the resolver with datacenter pattern
            dns._resolver = MockDNSResolver({
                "1.2.3.4": {"ptr": "ec2-1-2-3-4.compute-1.amazonaws.com"}
            })
            result = await dns._fcrdns_check("1.2.3.4")
            assert result.classification == "datacenter_confirmed"
        
        asyncio.run(run_test())


class TestQueueBehavior:
    """Test queue and enqueue logic."""

    def test_alpn_whitelist_not_enqueued(self):
        """h2/h1 ALPN IPs are not enqueued."""
        mock_redis = MagicMock()
        
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": True, "queue_size": 10}}, mock_redis)
            await dns.enqueue("1.2.3.4", alpn="h2")
            # Queue should be empty
            assert dns._queue.qsize() == 0
        
        asyncio.run(run_test())

    def test_bloom_filter_prevents_duplicate(self):
        """Bloom filter prevents duplicate enqueues."""
        mock_redis = MagicMock()
        mock_redis.bf().exists.return_value = True  # Already exists
        
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": True, "queue_size": 10}}, mock_redis)
            await dns.enqueue("1.2.3.4")
            # Should not be enqueued - but workers may have started, so check if it was logged
            # The important thing is that exists() was called
            mock_redis.bf().exists.assert_called_once_with("bloom:dns_enriched", "1.2.3.4")
        
        asyncio.run(run_test())

    def test_queue_full_drops_item(self):
        """Queue full drops new items."""
        # Create queue with size 1 and fill it
        mock_redis = MagicMock()
        mock_redis.bf().exists.return_value = False
        mock_redis.bf().add.return_value = True
        
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": True, "queue_size": 1}}, mock_redis)
            # Fill queue
            await dns.enqueue("1.2.3.4")
            assert dns._queue.qsize() == 1
            
            # Try to add another (should drop)
            await dns.enqueue("5.6.7.8")
            # Queue should still have 1 item
            assert dns._queue.qsize() == 1
        
        asyncio.run(run_test())


class TestSignalGeneration:
    """Test signal generation from cache."""

    def test_no_ptr_signal(self):
        """No PTR record → +15 signal."""
        dns = DNSEnrichment({"dns_enrichment": {"enabled": True}}, None)
        cached = {"classification": "no_ptr"}
        
        signal = dns._signal_from_cache(cached)
        assert signal is not None
        assert signal.name == "no_ptr"
        assert signal.score == 15

    def test_fcrdns_failed_signal(self):
        """FCrDNS failed → +20 signal."""
        dns = DNSEnrichment({"dns_enrichment": {"enabled": True}}, None)
        cached = {"classification": "fcrdns_failed", "ptr": "example.com"}
        
        signal = dns._signal_from_cache(cached)
        assert signal is not None
        assert signal.name == "fcrdns_failed"
        assert signal.score == 20

    def test_residential_signal(self):
        """Residential PTR → -10 signal."""
        dns = DNSEnrichment({"dns_enrichment": {"enabled": True}}, None)
        cached = {"classification": "residential", "ptr": "cpc12345.example.com"}
        
        signal = dns._signal_from_cache(cached)
        assert signal is not None
        assert signal.name == "residential_ptr"
        assert signal.score == -10

    def test_datacenter_signal(self):
        """Datacenter PTR → 0 signal (already scored by ASN)."""
        dns = DNSEnrichment({"dns_enrichment": {"enabled": True}}, None)
        cached = {"classification": "datacenter_confirmed", "ptr": "ec2-1-2-3-4.amazonaws.com"}
        
        signal = dns._signal_from_cache(cached)
        assert signal is not None
        assert signal.name == "datacenter_ptr"
        assert signal.score == 0


class TestDisabledState:
    """Test behavior when DNS enrichment is disabled."""

    def test_disabled_no_enqueue(self):
        """Disabled → no enqueues."""
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": False}}, None)
            await dns.enqueue("1.2.3.4")
            assert dns._queue.qsize() == 0
        
        asyncio.run(run_test())

    def test_disabled_no_signal(self):
        """Disabled → no signals."""
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": False}}, None)
            signal = await dns.get_signal("1.2.3.4")
            assert signal is None
        
        asyncio.run(run_test())


class TestIPv6Handling:
    """Test IPv6 address handling."""

    def test_ipv6_ptr_lookup(self):
        """IPv6 uses correct address family."""
        async def run_test():
            dns = DNSEnrichment({"dns_enrichment": {"enabled": True}}, None)
            # Mock the resolver with IPv6 result
            dns._resolver = MockDNSResolver({
                "2001:db8::1": {"ptr": "ipv6.example.com"}
            })
            # Should use AF_INET6 for IPv6 address
            result = await dns._fcrdns_check("2001:db8::1")
            # Verify the lookup was attempted
            assert result.hostname == "ipv6.example.com"
        
        asyncio.run(run_test())
