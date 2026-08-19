"""Turn connection events into the things an operator actually needs.

Phase 828b/c/d. The console had every one of these facts in the event stream and
showed none of them:

* **Why a connection scored what it did.** The proxy computes a per-signal
  breakdown with a human-readable reason for each; 828a put it on the wire.
* **Whether an IP is one automated client or many real people.** A single
  fingerprint seen thousands of times at one address is a tool. Forty
  fingerprints seen a handful of times each is a CGNAT egress carrying
  subscribers. The console showed per-IP and per-JA4 totals separately and
  never joined them, so the distinction was unavailable.
* **What "Unknown" means.** One word covered "this address has no owner because
  it is not routable", "we could not look it up", and "we looked and found
  nothing". Those call for different actions.

Everything here is descriptive. Nothing in this module decides anything: the
shape verdict reports an observed distribution and the suggestion helper is
advisory and read-only. That is deliberate — `CLAUDE.md`'s core asymmetry says a
blocked real user costs far more than a missed bot, and a CGNAT egress is the
single easiest way to block several hundred real users with one click.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, Optional

# ── Event phase ───────────────────────────────────────────────────────────────

PROVISIONAL = "provisional"
FINAL = "final"


def is_provisional(parsed: Dict[str, Any]) -> bool:
    """True when this entry is the placeholder written before scoring ran.

    Phase 828 made the proxy emit two events for a connection scored on its
    async path. Both carry ``ja4proxy.connection_id``; the provisional one has
    ``event.risk_score`` 0 because nothing had been evaluated yet.

    Every consumer that counts connections or averages scores must skip these,
    or totals double and an unevaluated zero is averaged in as though it were a
    verdict. Matched exactly, with no case folding: an event from an older proxy
    carries no phase at all and must fall through as normal, not be discarded.
    """
    return parsed.get("ja4proxy.event_phase") == PROVISIONAL


# ── Why this score ────────────────────────────────────────────────────────────


def extract_explanation(parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Pull the signal breakdown and counterfactuals out of one event.

    Returns None only when the event carries no explanation at all — an event
    from a proxy older than 828a. The caller must render that as "not available"
    rather than as "no signals fired": those are different facts and only one of
    them is about the traffic.

    A **bypassed** connection does have an explanation, and it is not the signal
    list: it is the bypass reason. The scorer never ran, so an empty signal list
    is the correct and complete answer, and the rule that decided it is what the
    operator needs to see.
    """
    signals = parsed.get("ja4proxy.signals")
    counterfactuals = parsed.get("ja4proxy.counterfactuals")
    bypass = parsed.get("ja4proxy.bypass_reason") or ""

    # A bypassed connection has no signals BECAUSE the scorer never ran, and
    # the bypass reason is the complete explanation of what happened to it.
    # Returning None here sent the page down its "no explanation recorded --
    # events written before the proxy was upgraded" path, which is both wrong
    # and unhelpful for the single most likely thing an operator clicks: a
    # blacklisted fingerprint. The reason was in the event the whole time.
    if not signals and not counterfactuals and not bypass:
        return None

    clean: List[Dict[str, Any]] = []
    for s in signals or []:
        if not isinstance(s, dict):
            continue
        clean.append(
            {
                "name": str(s.get("name", "")),
                "score": s.get("score", 0),
                "weight": s.get("weight", 1.0),
                "reason": str(s.get("reason", "")),
            }
        )

    # Largest absolute contribution first. A signal arguing FOR allowing a
    # connection is as interesting as one arguing against, and sorting by raw
    # score would bury every negative one at the bottom of the panel.
    clean.sort(key=lambda s: abs(s.get("score") or 0), reverse=True)

    return {
        "signals": clean,
        "counterfactuals": counterfactuals or {},
        "bypass_reason": bypass,
    }


# ── Geo / ASN resolution status ───────────────────────────────────────────────

GEO_RESOLVED = "resolved"
GEO_NOT_ROUTABLE = "not-routable"
GEO_LOOKUP_FAILED = "lookup-failed"
GEO_UNALLOCATED = "unallocated"

_STATUS_TEXT = {
    GEO_RESOLVED: "",
    GEO_NOT_ROUTABLE: (
        "Private, carrier-internal or reserved address — no public owner "
        "exists. Nothing to look up."
    ),
    GEO_LOOKUP_FAILED: (
        "No GeoIP data available on this proxy. See "
        "docs/runbooks/geoip_databases.md."
    ),
    GEO_UNALLOCATED: "Public address with no GeoIP record — unallocated or very new.",
}


def geo_status(
    ip: str,
    country: str = "",
    asn: Any = 0,
    asn_org: str = "",
    *,
    db_appears_present: bool = True,
) -> Dict[str, Any]:
    """Classify why geo/ASN data is or is not available for ``ip``.

    The console previously rendered every empty case as the single word
    "Unknown", which collapsed three unrelated situations:

    * the address is private or CGNAT-internal, so **there is no owner** —
      the honest answer, and not a problem;
    * the GeoIP database is missing, so **we failed to look** — an ops problem
      with a runbook;
    * the address is public and genuinely has no record.

    ``db_appears_present`` is the caller's evidence, normally "did any public IP
    in this sample resolve at all". Without it a missing database and an
    unallocated block are indistinguishable from a single event.
    """
    resolved = bool(country) or bool(asn_org) or bool(asn)
    if resolved:
        status = GEO_RESOLVED
    else:
        try:
            addr = ipaddress.ip_address(ip)
            routable = addr.is_global
        except ValueError:
            # Not an address we can reason about; do not claim it is private.
            routable = True
        if not routable:
            status = GEO_NOT_ROUTABLE
        elif not db_appears_present:
            status = GEO_LOOKUP_FAILED
        else:
            status = GEO_UNALLOCATED

    return {
        "status": status,
        "country": country or "",
        "asn": asn or 0,
        "asn_org": asn_org or "",
        "explanation": _STATUS_TEXT[status],
    }


# ── IP × fingerprint shape ────────────────────────────────────────────────────

SHAPE_SINGLE_CLIENT = "single-client"
SHAPE_SHARED_EGRESS = "shared-egress"
SHAPE_MIXED = "mixed"

# One fingerprint accounting for essentially all of an address's traffic.
_DOMINANT_SHARE = 0.90
# Enough distinct stacks, none dominant, to look like many devices behind one
# address. Irish mobile CGNAT is the case this exists for.
_SHARED_MIN_FINGERPRINTS = 8
_SHARED_MAX_SHARE = 0.40

_SHAPE_TEXT = {
    SHAPE_SINGLE_CLIENT: (
        "Nearly all traffic from this address shares one TLS fingerprint, "
        "which is what a single automated client looks like."
    ),
    SHAPE_SHARED_EGRESS: (
        "Many distinct TLS fingerprints, none dominant — the pattern of a "
        "shared egress such as CGNAT, a corporate NAT or a VPN exit. Traffic "
        "from here is likely to include real users."
    ),
    SHAPE_MIXED: (
        "Neither clearly one client nor clearly a shared egress. Not enough "
        "of a pattern to say."
    ),
}


def shape_verdict(fingerprint_counts: Dict[str, int]) -> Dict[str, Any]:
    """Describe the fingerprint distribution at one address.

    This answers "how many times has this signature been seen at this IP", the
    question that separates one automated client from a CGNAT address carrying
    subscribers — and which no endpoint could answer before, because per-IP and
    per-JA4 totals were never joined.

    It is a **description of an observed distribution and nothing more**. The
    returned dict deliberately carries no action: `CLAUDE.md`'s core asymmetry
    means a shape reading that becomes a block recommendation is a machine for
    manufacturing false positives.
    """
    total = sum(fingerprint_counts.values())
    distinct = len(fingerprint_counts)
    if total == 0:
        return {
            "shape": SHAPE_MIXED,
            "distinct_fingerprints": 0,
            "total_events": 0,
            "top_share": 0.0,
            "explanation": "No traffic recorded for this address.",
        }

    top_share = max(fingerprint_counts.values()) / total

    if top_share >= _DOMINANT_SHARE:
        shape = SHAPE_SINGLE_CLIENT
    elif distinct >= _SHARED_MIN_FINGERPRINTS and top_share <= _SHARED_MAX_SHARE:
        shape = SHAPE_SHARED_EGRESS
    else:
        shape = SHAPE_MIXED

    return {
        "shape": shape,
        "distinct_fingerprints": distinct,
        "total_events": total,
        "top_share": round(top_share, 3),
        "explanation": _SHAPE_TEXT[shape],
    }


# ── Advisory suggestion ───────────────────────────────────────────────────────


def suggest_action(
    *,
    shape: Dict[str, Any],
    action_counts: Dict[str, int],
    is_banned: bool = False,
    is_allowlisted: bool = False,
) -> Dict[str, Any]:
    """Propose what an operator might do, with the cost of being wrong.

    Rules, in order:

    1. **Never suggest banning a shared egress.** One click on a CGNAT address
       can take out several hundred real subscribers. This is the core
       asymmetry expressed as code, and it takes precedence over every signal.
    2. Suggest a ban only for a single-client address whose traffic is already
       predominantly blocked — i.e. the proxy has already decided, repeatedly,
       and a ban only saves it from re-deciding.
    3. Otherwise suggest watching, which costs nothing.

    Always advisory. The endpoint exposing this is GET-only and nothing here
    applies anything.
    """
    total = sum(action_counts.values()) or 1
    blocked = action_counts.get("block", 0) + action_counts.get("ban", 0)
    blocked_share = blocked / total
    distinct = shape.get("distinct_fingerprints", 0)

    blast_radius = (
        f"{distinct} distinct TLS fingerprint(s) seen at this address in the "
        f"sample window."
    )

    if is_banned:
        return {
            "suggestion": "none",
            "rationale": "This address is already banned.",
            "blast_radius": blast_radius,
            "confidence": "n/a",
        }
    if is_allowlisted:
        return {
            "suggestion": "none",
            "rationale": "This address is allowlisted; review that entry before acting.",
            "blast_radius": blast_radius,
            "confidence": "n/a",
        }

    if shape.get("shape") == SHAPE_SHARED_EGRESS:
        return {
            "suggestion": "do-not-ban",
            "rationale": (
                "This address looks like a shared egress. Banning it would "
                "affect every user behind it, not just the traffic that "
                "triggered the score. Prefer blocking the specific fingerprint."
            ),
            "blast_radius": blast_radius,
            "confidence": "high",
        }

    if shape.get("shape") == SHAPE_SINGLE_CLIENT and blocked_share >= 0.70:
        return {
            "suggestion": "consider-ban",
            "rationale": (
                f"{blocked_share:.0%} of this address's traffic is already being "
                "blocked and it carries a single TLS fingerprint, so a ban is "
                "unlikely to affect anyone else."
            ),
            "blast_radius": blast_radius,
            "confidence": "medium",
        }

    return {
        "suggestion": "watch",
        "rationale": (
            "Not enough of a pattern to act on. The proxy is already scoring "
            "this traffic on every connection."
        ),
        "blast_radius": blast_radius,
        "confidence": "low",
    }


def crosstab(events: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Build per-fingerprint counts for one address.

    Returns ``{ja4: {count, first_seen, last_seen, actions}}``.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for parsed in events:
        ja4 = parsed.get("ja4proxy.fingerprint.ja4") or ""
        if not ja4:
            continue
        ts = parsed.get("@timestamp", "")
        action = parsed.get("event.action", "allow")
        row = out.setdefault(
            ja4,
            {"count": 0, "first_seen": ts, "last_seen": ts, "actions": {}},
        )
        row["count"] += 1
        row["actions"][action] = row["actions"].get(action, 0) + 1
        if ts:
            if not row["first_seen"] or ts < row["first_seen"]:
                row["first_seen"] = ts
            if not row["last_seen"] or ts > row["last_seen"]:
                row["last_seen"] = ts
    return out
