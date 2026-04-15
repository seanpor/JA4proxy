"""Tests for PHASE_101e: Regional endpoint support.

H9 — Recorded Future regional endpoint support
H10 — CrowdStrike regional / GovCloud endpoint support
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.analytics.ti_feeds.base import FeedConfig
from src.analytics.ti_feeds.crowdstrike import CrowdStrikeFalconClient, _resolve_falcon_urls
from src.analytics.ti_feeds.recorded_future import RecordedFutureClient, _resolve_rf_taxii_root


class TestRecordedFutureRegional:
    """Test RF regional endpoint selection from config.url."""

    @pytest.mark.parametrize(
        "config_url,expected_root",
        [
            ("https://api.eu.recordedfuture.com/taxii2/", "https://api.eu.recordedfuture.com/taxii2"),
            ("https://api.apac.recordedfuture.com/taxii2/", "https://api.apac.recordedfuture.com/taxii2"),
            ("https://api.eu.recordedfuture.com/taxii2", "https://api.eu.recordedfuture.com/taxii2"),
            ("", "https://api.recordedfuture.com/taxii2"),
            (None, "https://api.recordedfuture.com/taxii2"),
        ],
    )
    def test_rf_uses_config_url_or_fallback(self, config_url, expected_root):
        """RF client honours config.url for regional subdomains."""
        if config_url is not None:
            config = FeedConfig(id="rf_test", type="recorded_future", enabled=True, url=config_url)
        else:
            config = FeedConfig(id="rf_test", type="recorded_future", enabled=True)

        assert _resolve_rf_taxii_root(config) == expected_root


class TestCrowdStrikeRegional:
    """Test CrowdStrike regional endpoint selection."""

    @pytest.mark.parametrize(
        "config_url,expected_auth,expected_api",
        [
            (
                "https://api.us-2.crowdstrike.com",
                "https://api.us-2.crowdstrike.com/oauth2/token",
                "https://api.us-2.crowdstrike.com/intel/combined/indicators/v1",
            ),
            (
                "https://api.eu-1.crowdstrike.com",
                "https://api.eu-1.crowdstrike.com/oauth2/token",
                "https://api.eu-1.crowdstrike.com/intel/combined/indicators/v1",
            ),
            (
                "https://api.laggar.gcw.crowdstrike.com",
                "https://api.laggar.gcw.crowdstrike.com/oauth2/token",
                "https://api.laggar.gcw.crowdstrike.com/intel/combined/indicators/v1",
            ),
            (
                "",
                "https://api.crowdstrike.com/oauth2/token",
                "https://api.crowdstrike.com/intel/combined/indicators/v1",
            ),
            (
                None,
                "https://api.crowdstrike.com/oauth2/token",
                "https://api.crowdstrike.com/intel/combined/indicators/v1",
            ),
        ],
    )
    def test_cs_uses_config_url_or_fallback(self, config_url, expected_auth, expected_api):
        """CrowdStrike client supports US-2, EU-1, and GovCloud (laggar) endpoints."""
        if config_url is not None:
            config = FeedConfig(id="cs_test", type="crowdstrike", enabled=True, url=config_url)
        else:
            config = FeedConfig(id="cs_test", type="crowdstrike", enabled=True)

        auth_url, api_url = _resolve_falcon_urls(config)
        assert auth_url == expected_auth
        assert api_url == expected_api
