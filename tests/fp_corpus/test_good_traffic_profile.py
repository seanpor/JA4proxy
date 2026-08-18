"""Executable form of docs/reference/GOOD_TRAFFIC_PROFILE.md.

WHY THIS EXISTS
---------------
`CLAUDE.md` says a blocked real user costs far more than a missed bot. That
rule cannot be tested until "real user" is written down, so it never was, and
the analytics detectors were tuned against attack traffic alone.

The reference deployment is a public web form served to Irish consumers. Its
defining properties are awkward ones:

  * a session lasts up to 30 minutes (the person is typing), and
  * a whole visit is 1-3 connections.

Low volume is therefore the GOOD user's signature as much as the scanner's, and
Irish mobile networks put many unrelated subscribers behind one CGNAT address —
so a per-subnet penalty lands on a crowd.

`SlowScanDetector` fired on shape alone: >=20 unique IPs in a /24 averaging <=3
requests each. That is a verbatim description of a busy five minutes on a
consumer ISP subnet. And the finding is not cosmetic — it writes
`analytics:slowscan:<subnet>` with a 30-minute TTL, which
`internal/security/analytics_signals.go` reads back as **+30 on the risk score
of every connection from that /24** (thresholds: flag 20, rate_limit 35,
tarpit 55). The TTL matches the form session length exactly, so the penalty
outlives the interaction it interrupts.

The tests below are the acceptance criteria for detection tuning. A change that
makes them fail is wrong by default; do not relax them to make a detector fire.
"""

from __future__ import annotations

import time

import pytest

from src.analytics.correlation import CLIENT_IDENTITY_DIMENSIONS, correlate
from src.analytics.detection import CampaignDetector, SlowScanDetector

# Real fingerprints observed on the POC stack. Browsers differ by engine AND
# version — which is the entire reason twenty real people do not look alike.
BROWSER_JA4S = [
    "t13d1516h2_8daaf6152771_b0da82dd1658",  # Chrome-ish
    "t13d1517h2_8daaf6152771_b1ff8ab2d16f",  # Chrome, other version
    "t13d1715h2_5b57614c22b0_3d5424432f57",  # Firefox
    "t13d2014h2_a09f3c656075_14788d8d241b",  # Safari / iOS
    "t13d1212h2_eac1b15b5477_8e6e362c5eac",  # Edge
]
SCANNER_JA4 = "t13d091100_f91f431d341e_8e6e362c5eac"  # one tool, one fingerprint


def form_visit(ip: str, ja4: str, *, action: str = "allow", ts: float | None = None) -> dict:
    """One connection from the good-traffic profile (§1)."""
    return {
        "timestamp": ts if ts is not None else time.time(),
        "src_ip": ip,
        "ja4": ja4,
        "action": action,
        "score": 5,
        "proxy_id": "ja4proxy-1",
        # Uniform for legitimate traffic too — everyone visits one form, from
        # one ISP, in one country. Present precisely so the tests prove these
        # dimensions are NOT accepted as corroboration.
        "sni": "forms.example.ie",
        "country": "IE",
        "asn": "AS15502",
        "asn_org": "Vodafone Ireland",
        "alpn": "h2",
        "tls_version": "13",
    }


# A CGNAT pool: many unrelated subscribers sharing one /24. 25 of them happen
# to load the form in the same five minutes.
CGNAT_SUBNET = "86.40.7."
CGNAT_VISITORS = [f"{CGNAT_SUBNET}{host}" for host in range(10, 35)]


class TestCgnatCrowdIsNotAScan:
    """The headline false positive. See profile §4."""

    def _detector(self, **kw) -> SlowScanDetector:
        return SlowScanDetector(**kw)

    def test_twenty_five_real_people_on_one_cgnat_subnet_are_not_flagged(self):
        d = self._detector()
        for i, ip in enumerate(CGNAT_VISITORS):
            # Each person: load the form, then submit. Different browsers.
            for _ in range(2):
                d.update_with_event(form_visit(ip, BROWSER_JA4S[i % len(BROWSER_JA4S)]))

        assert d.detect_slow_scans() == [], (
            "25 unrelated people behind one carrier NAT, each loading a form "
            "twice, were reported as a slow scan. The finding adds +30 to the "
            "risk score of every connection from that /24 for 30 minutes — "
            "see GOOD_TRAFFIC_PROFILE.md §4"
        )

    def test_the_shape_gate_alone_would_have_flagged_them(self):
        """Guard against the test passing for the wrong reason.

        If someone raises min_unique_ips so high that this traffic no longer
        even reaches the corroboration gate, the test above would pass while
        proving nothing. This asserts the traffic really is scan-SHAPED, so the
        corroboration gate is what is doing the work.
        """
        d = self._detector(min_shared_share=0)  # gate disabled == old behaviour
        for i, ip in enumerate(CGNAT_VISITORS):
            for _ in range(2):
                d.update_with_event(form_visit(ip, BROWSER_JA4S[i % len(BROWSER_JA4S)]))

        assert d.detect_slow_scans(), (
            "this traffic no longer matches the slow-scan shape at all, so the "
            "regression test above is vacuous"
        )

    def test_a_real_slow_scan_from_the_same_subnet_is_still_caught(self):
        """The gate must not have simply switched the detector off."""
        d = self._detector()
        for ip in CGNAT_VISITORS:
            for _ in range(2):
                d.update_with_event(form_visit(ip, SCANNER_JA4, action="block"))

        found = d.detect_slow_scans()
        assert found, "one tool across 25 IPs must still be detected"
        assert found[0]["unique_ips"] == len(CGNAT_VISITORS)
        assert SCANNER_JA4 in found[0]["shared"], (
            "the finding must name the shared fingerprint — it is the only "
            "thing an operator can safely act on without hitting the crowd"
        )


class TestCorroborationUsesClientIdentityOnly:
    """Uniform network/site attributes must never count as agreement (§3)."""

    @pytest.mark.parametrize("dimension", ["country", "asn", "asn_org", "sni", "alpn", "tls_version"])
    def test_network_and_site_dimensions_are_not_corroboration(self, dimension):
        assert dimension not in CLIENT_IDENTITY_DIMENSIONS, (
            f"{dimension} is uniform for legitimate traffic within one subnet "
            "visiting one site; accepting it as corroboration re-opens the "
            "CGNAT false positive"
        )

    def test_legitimate_crowd_does_agree_on_those_dimensions(self):
        """Proves the exclusion above is load-bearing, not theoretical."""
        events = [
            form_visit(ip, BROWSER_JA4S[i % len(BROWSER_JA4S)])
            for i, ip in enumerate(CGNAT_VISITORS)
        ]
        corr = correlate(events)
        agreed = {c.dimension for c in corr.characteristics}
        assert {"country", "asn", "sni"} <= agreed, (
            "fixture no longer exercises the risk: legitimate traffic is "
            "supposed to look uniform in these dimensions"
        )
        assert not (agreed & set(CLIENT_IDENTITY_DIMENSIONS)), (
            "real browsers must not agree on a client fingerprint"
        )


class TestLowVolumeIsNotEvidence:
    """§5 rule 1: volume alone never convicts."""

    def test_a_handful_of_connections_from_one_person_is_never_a_finding(self):
        d = SlowScanDetector()
        for _ in range(3):
            d.update_with_event(form_visit("86.40.7.11", BROWSER_JA4S[0]))
        assert d.detect_slow_scans() == []

    def test_thirty_minute_session_does_not_age_into_suspicion(self):
        """§1: a 30-minute form session is the expected shape, not an anomaly."""
        d = SlowScanDetector()
        start = time.time()
        d.update_with_event(form_visit("86.40.7.11", BROWSER_JA4S[0], ts=start))
        d.update_with_event(
            form_visit("86.40.7.11", BROWSER_JA4S[0], ts=start + 30 * 60)
        )
        assert d.detect_slow_scans() == []


class TestCampaignDetectorStaysSafe:
    """The campaign detector was already corroborated, by block rate. Keep it."""

    def test_allowed_traffic_never_forms_a_campaign(self):
        d = CampaignDetector()
        # Dense enough to pass the density gate: 60 IPs in one /24.
        for i in range(60):
            for _ in range(3):
                d.update_with_event(
                    form_visit(f"86.40.7.{i + 10}", BROWSER_JA4S[i % len(BROWSER_JA4S)])
                )
        assert d.detect_campaigns() == [], (
            "legitimate traffic is allowed, so block_rate is 0 and the "
            "block-rate gate must keep this out"
        )


class TestAsnProvenanceReachesCorrelation:
    """§6 — the gap that made rule 5 (provenance) unenforceable.

    `ASNClassifier.Classify()` resolved the ASN number and organisation on every
    connection and discarded both, so `correlation.DIMENSIONS` declared `asn`
    and `asn_org` that nothing could populate. The Go side now emits the two
    standard ECS fields; these assert the Python side actually reads them, since
    a rename on either side would silently reopen the gap with no test failing.
    """

    ECS_KEYS = {"asn": "client.as.number", "asn_org": "client.as.organization.name"}

    def _ecs_event(self, ip: str, ja4: str, asn: int, org: str) -> dict:
        """An event in the proxy's ECS wire form, not the flattened form."""
        return {
            "@timestamp": "2026-08-18T10:00:00Z",
            "source.ip": ip,
            "ja4proxy.fingerprint.ja4": ja4,
            "client.geo.country_iso": "IE",
            "client.as.number": asn,
            "client.as.organization.name": org,
            "event.action": "allow",
        }

    @pytest.mark.parametrize("dimension,ecs_key", ECS_KEYS.items())
    def test_dimension_is_wired_to_the_ecs_field_the_proxy_emits(self, dimension, ecs_key):
        from src.analytics.correlation import DIMENSIONS

        assert ecs_key in DIMENSIONS[dimension], (
            f"{dimension} no longer reads {ecs_key}; cmd/ja4pd/main.go emits "
            "that exact key, so this dimension would go permanently empty"
        )

    def test_hosting_provider_group_is_identified_by_asn(self):
        events = [
            self._ecs_event(f"203.0.113.{i}", SCANNER_JA4, 16509, "Amazon.com, Inc.")
            for i in range(10, 35)
        ]
        corr = correlate(events)
        by_dim = {c.dimension: c for c in corr.characteristics}

        assert "asn" in by_dim, "ASN did not correlate from the ECS envelope"
        assert by_dim["asn"].value == "16509"
        assert by_dim["asn_org"].value == "Amazon.com, Inc."

    def test_consumer_isp_group_is_distinguishable_from_hosting(self):
        """The whole point of rule 5: these two groups must not look alike."""
        residential = [
            self._ecs_event(
                f"86.40.7.{i}", BROWSER_JA4S[i % len(BROWSER_JA4S)], 15502, "Vodafone Ireland"
            )
            for i in range(10, 35)
        ]
        hosting = [
            self._ecs_event(f"203.0.113.{i}", SCANNER_JA4, 16509, "Amazon.com, Inc.")
            for i in range(10, 35)
        ]

        res_org = correlate(residential).top("asn_org")
        host_org = correlate(hosting).top("asn_org")
        assert res_org is not None and host_org is not None
        assert res_org.value != host_org.value, (
            "consumer ISP and hosting provider must be distinguishable — this "
            "is the discriminator that keeps a busy CGNAT subnet from being "
            "treated like a scan"
        )
