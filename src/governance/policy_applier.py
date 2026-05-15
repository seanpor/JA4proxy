"""Async aiohttp client that applies a validated policy dict to the Management API.

This module is the runtime counterpart to the offline validator.  It makes
real HTTP calls to the MFA/SSO Hardening Management API.

Exported symbols
----------------
ApplyResult           -- summary counts from an apply run
DriftEntry            -- single drift report entry
DiffResult            -- result of a diff run (.drift list of DriftEntry)
PendingApprovalError  -- raised when the API returns 202 pending_approval

apply_policy(policy_dict, api_url, token) -> ApplyResult
    Apply a validated policy dict to the Management API.

diff_policy(policy_dict, api_url, token) -> DiffResult
    Compare policy dict against live API state, report operator drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# aiohttp is imported lazily inside functions so that the CLI's ``validate``
# sub-command works even if aiohttp is not installed.


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ApplyResult:
    """Summary of a ``apply_policy`` run.

    Attributes:
        added: Number of resources that were created in the API.
        removed: Number of resources that were deleted from the API.
        unchanged: Number of resources that were already present and skipped.
        pending_approvals: Decision IDs for changes that require approval.
    """

    added: int = 0
    removed: int = 0
    unchanged: int = 0
    pending_approvals: list[str] = field(default_factory=list)


@dataclass
class DriftEntry:
    """Single entry in a drift report.

    Attributes:
        resource_type: ``"allowlist_fingerprint"``, ``"blocklist_fingerprint"``,
            or ``"allowlist_ip"``.
        identifier: JA4 string or CIDR.
        managed_by: Value of the ``managed_by`` field on the live resource
            (e.g. ``"operator"``).
        note: Optional human-readable context.
    """

    resource_type: str
    identifier: str
    managed_by: str
    note: str = ""


@dataclass
class DiffResult:
    """Result of a policy diff operation.

    Attributes:
        drift: Entries present in the live API that are not in the policy file
            and are not managed by policy (i.e. added via UI or direct API).
            Empty list means no drift.
    """

    drift: list[DriftEntry] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class PendingApprovalError(Exception):
    """A change requires four-eyes approval.

    Attributes:
        decision_id: The ``decision_id`` returned by the Management API.
    """

    def __init__(self, decision_id: str) -> None:
        self.decision_id = decision_id
        super().__init__(f"Change requires approval: decision_id={decision_id}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _auth_headers(token: str) -> dict[str, str]:
    """Return HTTP headers with a Bearer token.

    Args:
        token: API bearer token.

    Returns:
        Dict suitable for use as aiohttp request headers.
    """
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _check_pending(response_data: dict) -> None:
    """Raise ``PendingApprovalError`` if the API response indicates pending approval.

    Args:
        response_data: Parsed JSON response body.

    Raises:
        PendingApprovalError: when ``status == "pending_approval"``.
    """
    if response_data.get("status") == "pending_approval":
        decision_id = response_data.get("decision_id", "unknown")
        raise PendingApprovalError(decision_id)


async def _get_list(
    session: Any,  # aiohttp.ClientSession
    url: str,
    headers: dict[str, str],
) -> list[dict]:
    """Fetch a resource list from the Management API.

    Args:
        session: Active aiohttp ClientSession.
        url: Full URL for the GET request.
        headers: HTTP headers to include.

    Returns:
        List of resource dicts.

    Raises:
        RuntimeError: if the API returns a non-200 status (including 401/403),
            so that authentication failures are never silently treated as an
            empty list and mistaken for a successful apply.
    """
    async with session.get(url, headers=headers) as resp:
        if resp.status != 200:
            raise RuntimeError(
                f"GET {url} returned HTTP {resp.status} — "
                "check API URL and token validity"
            )
        data = await resp.json()
        # API may return {"items": [...]} or a plain list
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("items", data.get("data", []))
    return []


async def _post_entry(
    session: Any,
    url: str,
    headers: dict[str, str],
    payload: dict,
) -> dict:
    """POST a new resource entry to the Management API.

    Args:
        session: Active aiohttp ClientSession.
        url: Full URL for the POST request.
        headers: HTTP headers to include.
        payload: JSON-serialisable payload.

    Returns:
        Parsed JSON response body.
    """
    async with session.post(url, headers=headers, json=payload) as resp:
        return await resp.json()


async def _delete_entry(
    session: Any,
    url: str,
    headers: dict[str, str],
) -> None:
    """DELETE a resource from the Management API.

    Args:
        session: Active aiohttp ClientSession.
        url: Full URL for the DELETE request.
        headers: HTTP headers to include.
    """
    async with session.delete(url, headers=headers) as resp:
        _ = resp.status  # consume the response


# ---------------------------------------------------------------------------
# Core logic — fingerprints
# ---------------------------------------------------------------------------


async def _apply_fingerprints(
    session: Any,
    api_url: str,
    headers: dict[str, str],
    entries: list[dict],
    endpoint: str,
    result: ApplyResult,
) -> None:
    """Apply a list of fingerprint entries to an API endpoint.

    For each entry in *entries*:
    - If already present with ``managed_by=policy`` → skip (unchanged).
    - Otherwise POST, then check for pending approval.

    Also removes entries in the live list with ``managed_by=policy`` that are
    NOT in the policy file.

    Args:
        session: Active aiohttp ClientSession.
        api_url: Base API URL.
        headers: HTTP headers with auth.
        entries: List of fingerprint dicts from the policy YAML.
        endpoint: API path segment, e.g. ``"allowlist"`` or ``"blocklist"``.
        result: ``ApplyResult`` to update in place.
    """
    url = f"{api_url}/api/v1/{endpoint}"
    live_items = await _get_list(session, url, headers)

    # Build lookup: ja4 -> live item
    live_by_ja4: dict[str, dict] = {
        item["ja4"]: item for item in live_items if "ja4" in item
    }

    # Policy entries indexed by ja4
    policy_ja4s: set[str] = set()
    for entry in entries:
        ja4 = entry["ja4"]
        policy_ja4s.add(ja4)
        if ja4 in live_by_ja4 and live_by_ja4[ja4].get("managed_by") == "policy":
            result.unchanged += 1
        else:
            payload = {**entry, "managed_by": "policy"}
            resp_data = await _post_entry(session, url, headers, payload)
            _check_pending(resp_data)
            result.added += 1

    # Remove policy-managed entries NOT in the current policy file
    for ja4, live_item in live_by_ja4.items():
        if live_item.get("managed_by") == "policy" and ja4 not in policy_ja4s:
            entry_id = live_item.get("id", ja4)
            await _delete_entry(session, f"{url}/{entry_id}", headers)
            result.removed += 1


# ---------------------------------------------------------------------------
# Core logic — IPs / CIDRs
# ---------------------------------------------------------------------------


async def _apply_ips(
    session: Any,
    api_url: str,
    headers: dict[str, str],
    entries: list[dict],
    endpoint: str,
    result: ApplyResult,
) -> None:
    """Apply a list of CIDR/IP entries to an API endpoint.

    Args:
        session: Active aiohttp ClientSession.
        api_url: Base API URL.
        headers: HTTP headers with auth.
        entries: List of IP/CIDR dicts from the policy YAML.
        endpoint: API path segment, e.g. ``"allowlist/ips"``.
        result: ``ApplyResult`` to update in place.
    """
    url = f"{api_url}/api/v1/{endpoint}"
    live_items = await _get_list(session, url, headers)

    live_by_cidr: dict[str, dict] = {
        item.get("cidr", item.get("ip", "")): item for item in live_items
    }

    policy_cidrs: set[str] = set()
    for entry in entries:
        cidr = entry.get("cidr") or entry.get("ip", "")
        policy_cidrs.add(cidr)
        if cidr in live_by_cidr and live_by_cidr[cidr].get("managed_by") == "policy":
            result.unchanged += 1
        else:
            payload = {**entry, "managed_by": "policy"}
            resp_data = await _post_entry(session, url, headers, payload)
            _check_pending(resp_data)
            result.added += 1

    for cidr, live_item in live_by_cidr.items():
        if live_item.get("managed_by") == "policy" and cidr not in policy_cidrs:
            entry_id = live_item.get("id", cidr)
            await _delete_entry(session, f"{url}/{entry_id}", headers)
            result.removed += 1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def apply_policy(
    policy_dict: dict,
    api_url: str,
    token: str,
) -> ApplyResult:
    """Apply a validated policy dict to the Management API.

    Idempotent: entries already present with ``managed_by=policy`` and matching
    content are skipped (counted as *unchanged*).

    If any change requires four-eyes approval the API returns ``202 Accepted``
    with ``{"decision_id": ..., "status": "pending_approval"}``.  In that case
    this function raises ``PendingApprovalError`` immediately.

    Args:
        policy_dict: Validated policy dict (output of ``validate_policy``).
        api_url: Base URL of the Management API, e.g. ``"http://localhost:8090"``.
        token: API bearer token.

    Returns:
        ``ApplyResult`` with counts of added / removed / unchanged resources.

    Raises:
        PendingApprovalError: if any change requires approval.
        aiohttp.ClientError: on HTTP transport errors.
    """
    import aiohttp  # lazy import — only needed in apply/diff commands

    headers = _auth_headers(token)
    result = ApplyResult()

    async with aiohttp.ClientSession() as session:
        allowlist = policy_dict.get("allowlist") or {}
        blocklist = policy_dict.get("blocklist") or {}
        watchlist = policy_dict.get("watchlist") or {}
        dial = policy_dict.get("dial") or {}

        # Fingerprints — always call even when list is empty so stale
        # managed_by=policy entries in the live API get removed.
        await _apply_fingerprints(
            session,
            api_url,
            headers,
            allowlist.get("fingerprints") or [],
            "allowlist",
            result,
        )
        await _apply_fingerprints(
            session,
            api_url,
            headers,
            blocklist.get("fingerprints") or [],
            "blocklist",
            result,
        )

        # IPs / CIDRs — always call even when list is empty so stale
        # managed_by=policy entries in the live API get removed.
        await _apply_ips(
            session,
            api_url,
            headers,
            allowlist.get("ips") or [],
            "allowlist/ips",
            result,
        )
        await _apply_ips(
            session,
            api_url,
            headers,
            blocklist.get("ips") or [],
            "blocklist/ips",
            result,
        )
        await _apply_ips(
            session,
            api_url,
            headers,
            watchlist.get("ips") or [],
            "watchlist/ips",
            result,
        )

        # Dial
        if "setting" in dial:
            dial_url = f"{api_url}/api/v1/dial"
            async with session.patch(
                dial_url,
                headers=headers,
                json={"value": dial["setting"]},
            ) as resp:
                resp_data = await resp.json()
                _check_pending(resp_data)

        # Bypass toggles
        bypass_toggles = policy_dict.get("bypass_toggles") or {}
        if bypass_toggles:
            config_url = f"{api_url}/api/v1/config"
            async with session.patch(
                config_url,
                headers=headers,
                json={"bypass_toggles": bypass_toggles},
            ) as resp:
                resp_data = await resp.json()
                _check_pending(resp_data)

    return result


async def diff_policy(
    policy_dict: dict,
    api_url: str,
    token: str,
) -> DiffResult:
    """Compare policy dict against live API state and return operator drift.

    Returns entries present in the API with ``managed_by != 'policy'`` that
    are not present in the policy file.  Does NOT return entries the policy
    would add — only reports unexpected entries.

    Args:
        policy_dict: Validated policy dict (output of ``validate_policy``).
        api_url: Base URL of the Management API.
        token: API bearer token.

    Returns:
        ``DiffResult`` with a ``drift`` list.  Empty list means no drift.
    """
    import aiohttp  # lazy import

    headers = _auth_headers(token)
    drift: list[DriftEntry] = []

    async with aiohttp.ClientSession() as session:
        allowlist = policy_dict.get("allowlist") or {}
        blocklist = policy_dict.get("blocklist") or {}

        # ── Allowlist fingerprints ──────────────────────────────────────────
        policy_allow_fps = {fp["ja4"] for fp in (allowlist.get("fingerprints") or [])}
        live_allow_fps = await _get_list(
            session, f"{api_url}/api/v1/allowlist", headers
        )
        for item in live_allow_fps:
            ja4 = item.get("ja4", "")
            managed_by = item.get("managed_by", "")
            if managed_by != "policy" and ja4 not in policy_allow_fps:
                drift.append(
                    DriftEntry(
                        resource_type="allowlist_fingerprint",
                        identifier=ja4,
                        managed_by=managed_by,
                    )
                )

        # ── Blocklist fingerprints ──────────────────────────────────────────
        policy_block_fps = {fp["ja4"] for fp in (blocklist.get("fingerprints") or [])}
        live_block_fps = await _get_list(
            session, f"{api_url}/api/v1/blocklist", headers
        )
        for item in live_block_fps:
            ja4 = item.get("ja4", "")
            managed_by = item.get("managed_by", "")
            if managed_by != "policy" and ja4 not in policy_block_fps:
                drift.append(
                    DriftEntry(
                        resource_type="blocklist_fingerprint",
                        identifier=ja4,
                        managed_by=managed_by,
                    )
                )

        # ── Allowlist IPs ───────────────────────────────────────────────────
        policy_allow_ips = {
            ip_entry.get("cidr", ip_entry.get("ip", ""))
            for ip_entry in (allowlist.get("ips") or [])
        }
        live_allow_ips = await _get_list(
            session, f"{api_url}/api/v1/allowlist/ips", headers
        )
        for item in live_allow_ips:
            cidr = item.get("cidr", item.get("ip", ""))
            managed_by = item.get("managed_by", "")
            if managed_by != "policy" and cidr not in policy_allow_ips:
                drift.append(
                    DriftEntry(
                        resource_type="allowlist_ip",
                        identifier=cidr,
                        managed_by=managed_by,
                    )
                )

    return DiffResult(drift=drift)
