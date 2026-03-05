import unittest
from unittest.mock import MagicMock, patch, mock_open
from src.security.asn_classifier import ASNClassifier, ASNClassification, RISK_SCORES
from src.security.models import ConnectionContext


class TestASNClassifier(unittest.TestCase):
    """Unit tests for ASN classifier."""

    def setUp(self):
        self.config = {
            "asn_classifier": {
                "enabled": True,
                "datacenter_list_path": "config/asn_datacenter_list.yml",
                "maxmind_db_path": "config/GeoLite2-ASN.mmdb",
                "tor_exit_list": {
                    "enabled": True,
                    "refresh_interval_seconds": 3600,
                },
                "risk_contributions": RISK_SCORES,
            }
        }
        self.mock_redis = MagicMock()

    @patch("src.security.asn_classifier.asyncio")
    @patch(
        "builtins.open", new_callable=mock_open, read_data="asns:\n  15169: Google\n"
    )
    @patch("os.path.exists")
    def _create_classifier(
        self,
        mock_exists,
        mock_file,
        mock_asyncio,
        datacenter_asns=None,
        maxmind_result=None,
    ):
        mock_exists.return_value = True
        classifier = ASNClassifier(self.config, self.mock_redis)
        if datacenter_asns is not None:
            classifier._datacenter_asns = datacenter_asns
        if maxmind_result is not None:
            classifier._maxmind_reader = MagicMock()
            classifier._maxmind_reader.get.return_value = maxmind_result
        return classifier

    def test_tor_exit_ip(self):
        classifier = self._create_classifier()
        classifier._tor_exit_ips = {"1.2.3.4"}
        result = classifier.classify("1.2.3.4")
        self.assertEqual(result.category, "tor")

    def test_ipv6_tor_exit(self):
        classifier = self._create_classifier()
        classifier._tor_exit_ips = {"2001:db8::1"}
        result = classifier.classify("2001:db8::1")
        self.assertEqual(result.category, "tor")

    def test_datacenter_classification(self):
        classifier = self._create_classifier(
            maxmind_result={
                "autonomous_system_number": 15169,
                "autonomous_system_organization": "Google LLC",
            }
        )
        result = classifier.classify("1.2.3.4")
        self.assertEqual(result.category, "datacenter")
        self.assertEqual(result.asn, 15169)

    def test_vpn_pattern_matching(self):
        classifier = self._create_classifier(
            maxmind_result={
                "autonomous_system_number": 12345,
                "autonomous_system_organization": "NordVPN",
            }
        )
        result = classifier.classify("1.2.3.4")
        self.assertEqual(result.category, "vpn")

    def test_residential_pattern_matching(self):
        classifier = self._create_classifier(
            maxmind_result={
                "autonomous_system_number": 7922,
                "autonomous_system_organization": "Comcast Cable Communications",
            }
        )
        result = classifier.classify("1.2.3.4")
        self.assertEqual(result.category, "residential")

    def test_unknown_classification(self):
        classifier = self._create_classifier(
            maxmind_result={
                "autonomous_system_number": 99999,
                "autonomous_system_organization": "Some Random ISP",
            }
        )
        result = classifier.classify("1.2.3.4")
        self.assertEqual(result.category, "unknown")

    def test_tor_overrides_datacenter(self):
        classifier = self._create_classifier(
            datacenter_asns={16509: "Amazon AWS"},
            maxmind_result={
                "autonomous_system_number": 16509,
                "autonomous_system_organization": "Amazon.com",
            },
        )
        classifier._tor_exit_ips = {"1.2.3.4"}
        result = classifier.classify("1.2.3.4")
        self.assertEqual(result.category, "tor")

    def test_get_signal_datacenter(self):
        classifier = self._create_classifier(
            maxmind_result={
                "autonomous_system_number": 15169,
                "autonomous_system_organization": "Google LLC",
            }
        )
        signal = classifier.get_signal("1.2.3.4")
        self.assertIsNotNone(signal)
        self.assertEqual(signal.name, "asn_datacenter")
        self.assertEqual(signal.score, 20)

    def test_get_signal_tor(self):
        classifier = self._create_classifier()
        classifier._tor_exit_ips = {"1.2.3.4"}
        signal = classifier.get_signal("1.2.3.4")
        self.assertIsNotNone(signal)
        self.assertEqual(signal.name, "asn_tor")
        self.assertEqual(signal.score, 40)

    def test_get_signal_vpn(self):
        classifier = self._create_classifier(
            maxmind_result={
                "autonomous_system_number": 12345,
                "autonomous_system_organization": "NordVPN",
            }
        )
        signal = classifier.get_signal("1.2.3.4")
        self.assertIsNotNone(signal)
        self.assertEqual(signal.name, "asn_vpn")
        self.assertEqual(signal.score, 10)

    def test_get_signal_unknown(self):
        classifier = self._create_classifier(
            maxmind_result={
                "autonomous_system_number": 99999,
                "autonomous_system_organization": "Unknown",
            }
        )
        signal = classifier.get_signal("1.2.3.4")
        self.assertIsNone(signal)

    def test_no_signal_for_residential(self):
        classifier = self._create_classifier(
            maxmind_result={
                "autonomous_system_number": 7922,
                "autonomous_system_organization": "Comcast",
            }
        )
        signal = classifier.get_signal("1.2.3.4")
        self.assertIsNone(signal)

    def test_normalize_ipv4(self):
        classifier = self._create_classifier()
        result = classifier._normalize_ip("1.2.3.4")
        self.assertEqual(result, "1.2.3.4")

    def test_normalize_ipv6(self):
        classifier = self._create_classifier()
        result = classifier._normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        self.assertEqual(result, "2001:db8:85a3::8a2e:370:7334")

    @patch("src.security.asn_classifier.asyncio")
    def test_signals_method(self, mock_asyncio):
        classifier = self._create_classifier()
        classifier._tor_exit_ips = {"1.2.3.4"}
        ctx = ConnectionContext(client_ip="1.2.3.4")

        async def run_test():
            signals = await classifier.signals(ctx)
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0].name, "asn_tor")

        import asyncio

        asyncio.run(run_test())


class TestASNClassification(unittest.TestCase):
    """Test ASNClassification dataclass."""

    def test_dataclass_fields(self):
        classification = ASNClassification(
            asn=15169,
            asn_str="AS15169",
            org_name="Google Cloud",
            category="datacenter",
        )
        self.assertEqual(classification.asn, 15169)
        self.assertEqual(classification.asn_str, "AS15169")
        self.assertEqual(classification.org_name, "Google Cloud")
        self.assertEqual(classification.category, "datacenter")


if __name__ == "__main__":
    unittest.main()
