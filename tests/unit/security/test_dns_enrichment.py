"""Unit tests for DNS Enrichment (Phase 7)."""

import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from src.security.dns_enrichment import (
    DNSEnrichment,
    FCrDNSResult,
    PassiveDNS,
    RISK_SCORES,
)


class TestFCrDNSResult(unittest.TestCase):
    """Test FCrDNSResult dataclass."""

    def test_dataclass_fields(self):
        result = FCrDNSResult(
            ip="1.2.3.4",
            has_ptr=True,
            confirmed=True,
            classification="confirmed",
            hostname="example.com",
            risk_score=0,
        )
        self.assertEqual(result.ip, "1.2.3.4")
        self.assertEqual(result.has_ptr, True)
        self.assertEqual(result.confirmed, True)
        self.assertEqual(result.classification, "confirmed")
        self.assertEqual(result.hostname, "example.com")
        self.assertEqual(result.risk_score, 0)


class TestDNSEnrichment(unittest.TestCase):
    """Test DNS Enrichment module."""

    def setUp(self):
        self.config = {
            "dns_enrichment": {
                "enabled": True,
                "queue_size": 1000,
                "worker_count": 5,
                "min_enqueue_score": 10,
                "resolver_timeout_seconds": 5,
                "fcrdns": {
                    "enabled": True,
                    "cache_ttl_seconds": 21600,
                    "score": 15,
                    "residential_score_reduction": 10,
                },
                "passive_dns": {
                    "enabled": False,
                },
            }
        }
        self.mock_redis = MagicMock()

    def test_init_disabled(self):
        """Test initialization when disabled."""
        enrichment = DNSEnrichment({"dns_enrichment": {"enabled": False}}, None)
        self.assertFalse(enrichment._enabled)

    def test_init_with_config(self):
        """Test initialization with config."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)
        self.assertTrue(enrichment._enabled)
        self.assertEqual(enrichment._queue_size, 1000)
        self.assertEqual(enrichment._worker_count, 5)

    def test_classify_hostname_residential(self):
        """Test hostname classification for residential patterns."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)

        result = enrichment._classify_hostname("host-123-456.dynamic.example.net", True)
        self.assertEqual(result, "residential")

    def test_classify_hostname_datacenter(self):
        """Test hostname classification for datacenter patterns."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)

        result = enrichment._classify_hostname(
            "ec2-1-2-3-4.compute.amazonaws.com", True
        )
        self.assertEqual(result, "datacenter_confirmed")

    def test_classify_hostname_fcrdns_failed(self):
        """Test hostname classification when FCrDNS fails."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)

        result = enrichment._classify_hostname("suspicious.example.com", False)
        self.assertEqual(result, "fcrdns_failed")

    def test_classify_hostname_ptr_literal(self):
        """Test hostname classification for IP literal PTR."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)

        result = enrichment._classify_hostname("123", True)
        self.assertEqual(result, "ptr_ip_literal")

    def test_classify_hostname_confirmed(self):
        """Test hostname classification for confirmed but generic PTR."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)

        result = enrichment._classify_hostname("mail.business.example.com", True)
        self.assertEqual(result, "confirmed")

    def test_get_signal_from_cache(self):
        """Test getting signal from Redis cache."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)

        cached_data = json.dumps(
            {
                "hostname": "example.com",
                "confirmed": True,
                "classification": "confirmed",
                "risk_score": 0,
            }
        )
        self.mock_redis.get.return_value = cached_data

        signal = enrichment.get_signal("1.2.3.4")
        self.assertIsNone(signal)  # No signal for 0 score

    def test_get_signal_with_positive_score(self):
        """Test getting signal with positive risk score."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)

        cached_data = json.dumps(
            {
                "hostname": "bad.ptr.example.com",
                "confirmed": False,
                "classification": "fcrdns_failed",
                "risk_score": 20,
            }
        )
        self.mock_redis.get.return_value = cached_data

        signal = enrichment.get_signal("1.2.3.4")
        self.assertIsNotNone(signal)
        self.assertEqual(signal.name, "dns_fcrdns_failed")
        self.assertEqual(signal.score, 20)

    def test_get_signal_cache_miss(self):
        """Test cache miss returns no signal."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)

        self.mock_redis.get.return_value = None

        signal = enrichment.get_signal("1.2.3.4")
        self.assertIsNone(signal)

    def test_risk_scores_constants(self):
        """Test risk score constants."""
        self.assertEqual(RISK_SCORES["no_ptr"], 15)
        self.assertEqual(RISK_SCORES["fcrdns_failed"], 20)
        self.assertEqual(RISK_SCORES["residential"], -10)
        self.assertEqual(RISK_SCORES["confirmed"], 0)


class TestPassiveDNS(unittest.TestCase):
    """Test Passive DNS module."""

    def setUp(self):
        self.config = {
            "dns_enrichment": {
                "passive_dns": {
                    "enabled": False,
                    "feed": "circl",
                    "api_key": "",
                    "cache_ttl_seconds": 3600,
                    "score": 20,
                    "new_domain_days": 7,
                }
            }
        }

    def test_passive_dns_disabled(self):
        """Test PassiveDNS when disabled."""
        dns = PassiveDNS(self.config, None)
        self.assertFalse(dns.is_enabled())

    def test_passive_dns_enabled(self):
        """Test PassiveDNS when enabled."""
        config = {
            "dns_enrichment": {
                "passive_dns": {
                    "enabled": True,
                    "feed": "circl",
                    "api_key": "test_key",
                }
            }
        }
        dns = PassiveDNS(config, None)
        self.assertTrue(dns.is_enabled())

    def test_check_ip_returns_none(self):
        """Test check_ip returns None (not implemented)."""
        dns = PassiveDNS(self.config, None)

        async def run_test():
            result = await dns.check_ip("1.2.3.4")
            self.assertIsNone(result)

        import asyncio

        asyncio.run(run_test())


class TestDNSEnrichmentAsync(unittest.TestCase):
    """Test async methods of DNS Enrichment."""

    def setUp(self):
        self.config = {
            "dns_enrichment": {
                "enabled": True,
                "queue_size": 100,
                "worker_count": 2,
                "resolver_timeout_seconds": 5,
                "fcrdns": {
                    "enabled": True,
                    "cache_ttl_seconds": 21600,
                    "score": 15,
                },
            }
        }

    def test_fcrdns_check_disabled(self):
        """Test FCrDNS check when disabled."""
        enrichment = DNSEnrichment({"dns_enrichment": {"enabled": False}}, None)

        async def run_test():
            result = await enrichment.fcrdns_check("1.2.3.4")
            self.assertEqual(result.classification, "disabled")

        import asyncio

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
