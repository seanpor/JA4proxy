"""Find what a set of connections has in common.

WHY THIS EXISTS
---------------
The detectors bucketed events by /24 and counted IPs. A finding could therefore
say "45 IPs in 172.25.200.0/24" and nothing else — no fingerprint, no country,
no ASN. That failed the operator twice over:

1. It gave them no safe way to act. A slow scan is defined by its
   DISTRIBUTION: each individual IP makes two or three requests, which is
   indistinguishable from a person loading a page, so per-IP rate limiting
   cannot catch it by construction. The only precise lever is a characteristic
   the whole scan shares — typically one TLS stack. Blocking the /24 instead is
   the blunt alternative, and a /24 is plausibly a corporate NAT or a mobile
   carrier egress, where the cost of a false positive is exactly the cost this
   project treats as unacceptable.

2. Bucketing by subnet is itself the blind spot. 45 IPs in one /24 is detected;
   the same 45 IPs spread across 45 different /24s puts one IP in each bucket
   and is detected as nothing. Same attacker, same tooling, same fingerprint,
   invisible — and spreading costs an attacker with a botnet or a few cloud
   regions nothing at all. No threshold value fixes that, because the evidence
   is partitioned before it is counted.

So correlation here is deliberately dimension-agnostic. Group by any attribute,
measure concentration, and report what actually distinguishes the group. A
characteristic shared by 100% of a distributed scan is a precise instrument
regardless of which attribute it happens to be.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

# Attributes worth correlating on, in the order an operator would want them.
# JA4 leads because it identifies the CLIENT SOFTWARE, which is the thing a
# distributed attack cannot vary without changing tools, and the thing that can
# be blocked without collateral damage to everyone sharing a network.
#
# Each entry maps a display name to the event keys that may carry it. Several
# keys per dimension because events arrive in both the proxy's ECS form and the
# analytics node's flattened form.
DIMENSIONS: Dict[str, tuple[str, ...]] = {
    "ja4": ("ja4", "ja4proxy.fingerprint.ja4"),
    "country": ("country", "client.geo.country_iso"),
    "asn": ("asn", "client.as.number"),
    "asn_org": ("asn_org", "client.as.organization.name"),
    "alpn": ("alpn", "ja4proxy.alpn"),
    "sni": ("sni", "ja4proxy.sni"),
    "tls_version": ("tls_version", "ja4proxy.tls_version"),
    "ja4t": ("ja4t", "ja4proxy.fingerprint.ja4t"),
    "ja4x": ("ja4x", "ja4proxy.fingerprint.ja4x"),
    "user_agent": ("user_agent",),
}

# A characteristic is only worth reporting if it covers most of the group.
# Below this it is a coincidence, not a signature, and presenting it as one
# would invite an operator to act on weak evidence.
DEFAULT_MIN_SHARE = 0.80


@dataclass
class Characteristic:
    """One attribute value shared across a group of connections."""

    dimension: str
    value: str
    count: int
    total: int
    distinct_values: int

    @property
    def share(self) -> float:
        return self.count / self.total if self.total else 0.0

    @property
    def is_uniform(self) -> bool:
        """Every observation agrees — the strongest form of this evidence."""
        return self.distinct_values == 1 and self.count == self.total

    def describe(self) -> str:
        pct = f"{self.share:.0%}"
        if self.is_uniform:
            return f"all {self.total} share {self.dimension} {self.value}"
        return f"{pct} share {self.dimension} {self.value}"


@dataclass
class Correlation:
    """What a set of events has in common, strongest first."""

    total_events: int = 0
    characteristics: List[Characteristic] = field(default_factory=list)
    # Kept separately: high cardinality is itself a signal. One JA4 seen across
    # many countries or ASNs says "distributed", which is the opposite of, and
    # as interesting as, "uniform".
    spread: Dict[str, int] = field(default_factory=dict)

    def top(self, dimension: str) -> Optional[Characteristic]:
        for c in self.characteristics:
            if c.dimension == dimension:
                return c
        return None

    def summary(self, limit: int = 3) -> str:
        if not self.characteristics:
            return "no shared characteristics"
        return "; ".join(c.describe() for c in self.characteristics[:limit])


def _value(event: Dict[str, Any], keys: Iterable[str]) -> Optional[str]:
    for k in keys:
        v = event.get(k)
        # 0 and "" are "collected but empty", which is not a characteristic.
        if v not in (None, "", 0):
            return str(v)
    return None


def correlate(
    events: List[Dict[str, Any]],
    *,
    min_share: float = DEFAULT_MIN_SHARE,
    dimensions: Optional[Dict[str, tuple[str, ...]]] = None,
) -> Correlation:
    """Report attributes shared by at least `min_share` of `events`.

    Ordered by share, then by how much the dimension narrows things down: a
    characteristic shared by 100% of a group where only one value was ever seen
    is stronger evidence than one where the winner merely happens to lead.
    """
    dims = dimensions if dimensions is not None else DIMENSIONS
    result = Correlation(total_events=len(events))
    if not events:
        return result

    for name, keys in dims.items():
        counts: Counter[str] = Counter()
        for e in events:
            v = _value(e, keys)
            if v is not None:
                counts[v] += 1
        if not counts:
            continue  # dimension not present in these events at all

        result.spread[name] = len(counts)
        value, count = counts.most_common(1)[0]
        # Share is of the events that HAVE this attribute, not of all events:
        # a dimension the proxy did not populate (GeoIP unavailable) should not
        # dilute a genuine signature in another dimension.
        observed = sum(counts.values())
        if count / observed >= min_share:
            result.characteristics.append(
                Characteristic(
                    dimension=name,
                    value=value,
                    count=count,
                    total=observed,
                    distinct_values=len(counts),
                )
            )

    result.characteristics.sort(key=lambda c: (c.share, -c.distinct_values), reverse=True)
    return result
