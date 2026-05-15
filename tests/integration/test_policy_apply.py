"""Integration tests for src/governance/policy_applier.py.

Tests use ManagementAPIMock — a real aiohttp HTTP server on a random port —
to verify the apply and diff operations against a simulated Management API.

Policy applier contract:
  async apply_policy(policy_dict: dict, api_url: str, token: str) -> ApplyResult
    Returns an ApplyResult with counts of added/removed/unchanged entries.
    Raises PendingApprovalError(decision_id) when the API returns 202.

  async diff_policy(policy_dict: dict, api_url: str, token: str) -> DiffResult
    Returns a DiffResult listing operator drift (entries in API not in policy).
    DiffResult.drift is a list of drift entries; empty list means no drift.

Every test asserts on specific values — none rely on "doesn't raise" alone.

JA4 fingerprint format: [a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}
"""

from __future__ import annotations

import textwrap

import pytest

from tests.mocks.management_api_mock import management_api_mock_server

# ---------------------------------------------------------------------------
# Lazy import helper — gives an explicit ImportError if the module is absent.
# Tests FAIL (not ERROR) at collection time until the implementation is written.
# ---------------------------------------------------------------------------


def _import_applier():
    """Import the policy applier module. Raises ImportError if not present."""
    from src.governance import policy_applier as pa  # type: ignore[import]

    return pa


# ---------------------------------------------------------------------------
# Valid JA4 fingerprints
# ---------------------------------------------------------------------------

_JA4_EXISTING = "t13d1516h2_aabbccddeeff_aabbccddeeff"
_JA4_NEW = "t13d1516h2_112233445566_aabbccddeeff"
_JA4_BLOCK = "t10d170900_9dc949161b6c_b64c0ad42cb7"


# ---------------------------------------------------------------------------
# Policy dict helpers
# ---------------------------------------------------------------------------


def _minimal_policy(*, dial: int = 30) -> dict:
    """Return a minimal valid policy dict with no list entries."""
    return {
        "meta": {
            "version": "1.0",
            "environment": "prod",
            "last_updated": "2026-04-01T00:00:00Z",
            "last_updated_by": "ops@example.com",
        },
        "dial": {
            "setting": dial,
            "changed_by": "ops@example.com",
        },
        "allowlist": {"fingerprints": [], "ips": []},
        "blocklist": {"fingerprints": []},
    }


def _policy_with_allowlist_entry(ja4: str = _JA4_EXISTING) -> dict:
    """Return a policy dict containing one allowlist fingerprint entry."""
    policy = _minimal_policy()
    policy["allowlist"]["fingerprints"] = [
        {
            "ja4": ja4,
            "reason": "Test entry",
            "added_by": "ops@example.com",
        }
    ]
    return policy


def _policy_with_blocklist_entry(ja4: str = _JA4_BLOCK) -> dict:
    """Return a policy dict containing one blocklist fingerprint entry."""
    policy = _minimal_policy()
    policy["blocklist"]["fingerprints"] = [
        {
            "ja4": ja4,
            "reason": "Known bad scanner",
            "added_by": "auto_feed",
        }
    ]
    return policy


def _policy_with_dial(setting: int) -> dict:
    """Return a policy dict with a specific dial setting."""
    return _minimal_policy(dial=setting)


# ===========================================================================
# 1. test_apply_idempotent_allowlist_entry
# ===========================================================================


async def test_apply_idempotent_allowlist_entry():
    """Entry already present in mock API response → POST /allowlist NOT called."""
    pa = _import_applier()

    existing_entry = {
        "id": "entry-001",
        "ja4": _JA4_EXISTING,
        "reason": "Test entry",
        "managed_by": "policy",
    }

    async with management_api_mock_server(
        allowlist_entries=[existing_entry],
    ) as (base_url, token, mock):
        policy = _policy_with_allowlist_entry(ja4=_JA4_EXISTING)
        result = await pa.apply_policy(policy, api_url=base_url, token=token)

    # The entry was already present — POST must never have been called.
    post_calls = [
        r
        for r in mock.requests_made
        if r["method"] == "POST" and r["path"] == "/api/v1/allowlist"
    ]
    assert (
        len(post_calls) == 0
    ), f"Expected 0 POST /api/v1/allowlist calls for idempotent entry, got {len(post_calls)}: {post_calls}"

    # The result must reflect that one entry was unchanged (not added).
    assert (
        result.unchanged >= 1
    ), f"Expected result.unchanged >= 1, got {result.unchanged!r} (full result: {result!r})"


# ===========================================================================
# 2. test_apply_adds_new_blocklist_entry
# ===========================================================================


async def test_apply_adds_new_blocklist_entry():
    """Entry in policy but absent from mock API → POST /blocklist called once with correct ja4."""
    pa = _import_applier()

    async with management_api_mock_server(
        blocklist_entries=[],  # API has nothing
    ) as (base_url, token, mock):
        policy = _policy_with_blocklist_entry(ja4=_JA4_BLOCK)
        result = await pa.apply_policy(policy, api_url=base_url, token=token)

    post_calls = [
        r
        for r in mock.requests_made
        if r["method"] == "POST" and r["path"] == "/api/v1/blocklist"
    ]
    assert (
        len(post_calls) == 1
    ), f"Expected exactly 1 POST /api/v1/blocklist call, got {len(post_calls)}: {post_calls}"

    sent_ja4 = post_calls[0]["body"].get("ja4")
    assert (
        sent_ja4 == _JA4_BLOCK
    ), f"Expected POST body to contain ja4={_JA4_BLOCK!r}, got {sent_ja4!r}"

    assert (
        result.added >= 1
    ), f"Expected result.added >= 1, got {result.added!r} (full result: {result!r})"


# ===========================================================================
# 3. test_apply_removes_entry_not_in_policy
# ===========================================================================


async def test_apply_removes_entry_not_in_policy():
    """Entry in mock API with managed_by=policy but absent from YAML → DELETE called with correct id."""
    pa = _import_applier()

    stale_entry = {
        "id": "stale-entry-007",
        "ja4": _JA4_EXISTING,
        "reason": "Old entry — no longer in policy",
        "managed_by": "policy",
    }

    # Policy has no allowlist entries — the stale one should be removed.
    async with management_api_mock_server(
        allowlist_entries=[stale_entry],
    ) as (base_url, token, mock):
        policy = _minimal_policy()  # empty allowlist
        result = await pa.apply_policy(policy, api_url=base_url, token=token)

    delete_calls = [
        r
        for r in mock.requests_made
        if r["method"] == "DELETE" and "/api/v1/allowlist/" in r["path"]
    ]
    assert (
        len(delete_calls) == 1
    ), f"Expected exactly 1 DELETE /api/v1/allowlist/{{id}} call, got {len(delete_calls)}: {delete_calls}"

    deleted_path = delete_calls[0]["path"]
    assert (
        "stale-entry-007" in deleted_path
    ), f"Expected DELETE path to contain 'stale-entry-007', got {deleted_path!r}"

    assert (
        result.removed >= 1
    ), f"Expected result.removed >= 1, got {result.removed!r} (full result: {result!r})"


# ===========================================================================
# 4. test_apply_operator_drift_not_removed
# ===========================================================================


async def test_apply_operator_drift_not_removed():
    """Entry in mock API with managed_by=operator but absent from YAML → no DELETE called."""
    pa = _import_applier()

    operator_entry = {
        "id": "operator-entry-999",
        "ja4": _JA4_EXISTING,
        "reason": "Added manually by ops — not in policy file",
        "managed_by": "operator",
    }

    # Policy has no allowlist entries, but operator entries must never be auto-removed.
    async with management_api_mock_server(
        allowlist_entries=[operator_entry],
    ) as (base_url, token, mock):
        policy = _minimal_policy()  # empty allowlist
        result = await pa.apply_policy(policy, api_url=base_url, token=token)

    delete_calls = [r for r in mock.requests_made if r["method"] == "DELETE"]
    assert (
        len(delete_calls) == 0
    ), f"Expected 0 DELETE calls for operator-managed entry, got {len(delete_calls)}: {delete_calls}"


# ===========================================================================
# 5. test_apply_sets_dial
# ===========================================================================


async def test_apply_sets_dial():
    """dial.setting: 70 in policy → PATCH /api/v1/dial called with {'value': 70}."""
    pa = _import_applier()

    async with management_api_mock_server() as (base_url, token, mock):
        policy = _policy_with_dial(70)
        await pa.apply_policy(policy, api_url=base_url, token=token)

    patch_calls = [
        r
        for r in mock.requests_made
        if r["method"] == "PATCH" and r["path"] == "/api/v1/dial"
    ]
    assert (
        len(patch_calls) == 1
    ), f"Expected exactly 1 PATCH /api/v1/dial call, got {len(patch_calls)}: {patch_calls}"

    sent_value = patch_calls[0]["body"].get("value")
    assert (
        sent_value == 70
    ), f"Expected PATCH body {{\"value\": 70}}, got body={patch_calls[0]['body']!r}"


# ===========================================================================
# 6. test_apply_pending_on_approval_required
# ===========================================================================


async def test_apply_pending_on_approval_required():
    """Mock returns 202 on PATCH /api/v1/dial → applier raises PendingApprovalError with decision_id."""
    pa = _import_applier()

    async with management_api_mock_server(
        dial_returns_pending=True,
    ) as (base_url, token, mock):
        policy = _policy_with_dial(80)

        with pytest.raises(pa.PendingApprovalError) as exc_info:
            await pa.apply_policy(policy, api_url=base_url, token=token)

    # The exception must carry the decision_id from the 202 response.
    assert (
        exc_info.value.decision_id == "dec-001"
    ), f"Expected PendingApprovalError.decision_id='dec-001', got {exc_info.value.decision_id!r}"


# ===========================================================================
# 7. test_diff_detects_operator_drift
# ===========================================================================


async def test_diff_detects_operator_drift():
    """Entry with managed_by=operator in API but not in policy → DiffResult.drift contains it."""
    pa = _import_applier()

    drift_entry = {
        "id": "drift-entry-111",
        "ja4": _JA4_NEW,
        "reason": "Added by operator directly — not in policy YAML",
        "managed_by": "operator",
    }

    async with management_api_mock_server(
        allowlist_entries=[drift_entry],
    ) as (base_url, token, mock):
        policy = _minimal_policy()  # empty allowlist — drift_entry is not in policy
        diff_result = await pa.diff_policy(policy, api_url=base_url, token=token)

    assert (
        len(diff_result.drift) >= 1
    ), f"Expected at least 1 drift entry, got {len(diff_result.drift)}: {diff_result.drift!r}"

    # The drift entry must reference the operator-added fingerprint.
    drift_identifiers = [d.identifier for d in diff_result.drift]
    assert any(
        _JA4_NEW in val or "drift-entry-111" in val for val in drift_identifiers
    ), (
        f"Expected drift entry with identifier containing ja4={_JA4_NEW!r} or "
        f"'drift-entry-111', got: {diff_result.drift!r}"
    )


# ===========================================================================
# 8. test_diff_clean_no_drift
# ===========================================================================


async def test_diff_clean_no_drift():
    """Policy matches API state exactly → DiffResult.drift is empty."""
    pa = _import_applier()

    # The API returns exactly the same entry that is in the policy — no drift.
    policy_entry = {
        "id": "entry-match-001",
        "ja4": _JA4_EXISTING,
        "reason": "Internal monitoring tool",
        "managed_by": "policy",
    }

    async with management_api_mock_server(
        allowlist_entries=[policy_entry],
    ) as (base_url, token, mock):
        policy = _policy_with_allowlist_entry(ja4=_JA4_EXISTING)
        diff_result = await pa.diff_policy(policy, api_url=base_url, token=token)

    assert (
        len(diff_result.drift) == 0
    ), f"Expected empty drift list when policy matches API state, got: {diff_result.drift!r}"


# ===========================================================================
# bypass_toggles apply path
# ===========================================================================


class TestApplyBypassToggles:

    async def test_apply_bypass_toggles(self):
        """bypass_toggles in policy → PATCH /api/v1/config called with correct body."""
        pa = _import_applier()
        async with management_api_mock_server() as (base_url, token, mock):
            policy = {
                "bypass_toggles": {
                    "alpn_browser_bypass": True,
                    "spamhaus_bypass": False,
                },
            }
            result = await pa.apply_policy(policy, api_url=base_url, token=token)

        config_calls = [
            r
            for r in mock.requests_made
            if r["method"] == "PATCH" and r["path"] == "/api/v1/config"
        ]
        assert len(config_calls) == 1, (
            f"Expected exactly 1 PATCH /api/v1/config, got {len(config_calls)}: "
            f"{config_calls!r}"
        )
        sent_body = config_calls[0]["body"]
        assert (
            "bypass_toggles" in sent_body
        ), f"Expected 'bypass_toggles' key in PATCH /api/v1/config body, got: {sent_body!r}"
        assert sent_body["bypass_toggles"]["alpn_browser_bypass"] is True
        assert sent_body["bypass_toggles"]["spamhaus_bypass"] is False
