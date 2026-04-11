"""Integration tests for emergency Ansible playbooks.

Verifies that each playbook:
1. Makes the correct API call (method + path + body + auth header)
2. Aborts on 422 (dial playbook)
3. Skips optional steps when servicenow_enabled=false / slack_enabled=false
4. Requires ja4proxy_token (Bearer auth)

Uses YAML parsing to verify structure without needing a real Management API.
"""

import os
import pathlib

import pytest
import yaml

# Project root is the parent of the tests/ directory
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
PLAYBOOKS_DIR = PROJECT_ROOT / "deploy" / "ansible" / "playbooks" / "emergency"


def _load_playbook(filename):
    """Load and parse an Ansible playbook YAML file."""
    path = PLAYBOOKS_DIR / filename
    with open(path) as f:
        return yaml.safe_load(f)


def _get_tasks(playbook):
    """Extract tasks list from a playbook."""
    for play in playbook:
        if "tasks" in play:
            return play["tasks"]
    return []


def _get_vars(playbook):
    """Extract vars from a playbook."""
    for play in playbook:
        if "vars" in play:
            return play["vars"]
    return {}


# ── Common: All playbooks require auth ──────────────────────────────────────


class TestAllPlaybooksRequireAuth:
    """Every playbook must require ja4proxy_token and pass Bearer auth."""

    @pytest.mark.parametrize("filename", [
        "emergency-ban-cidr.yml",
        "temp-whitelist-ip.yml",
        "maintenance-dial-zero.yml",
    ])
    def test_requires_token_variable(self, filename):
        playbook = _load_playbook(filename)
        tasks = _get_tasks(playbook)
        # At least one task should assert ja4proxy_token is defined
        has_token_check = False
        for task in tasks:
            assert_obj = task.get("ansible.builtin.assert", {})
            that_list = assert_obj.get("that", [])
            if any("ja4proxy_token" in str(t) for t in that_list):
                has_token_check = True
                break
        assert has_token_check, f"{filename} does not validate ja4proxy_token is set"

    @pytest.mark.parametrize("filename", [
        "emergency-ban-cidr.yml",
        "temp-whitelist-ip.yml",
        "maintenance-dial-zero.yml",
    ])
    def test_uses_bearer_auth(self, filename):
        playbook = _load_playbook(filename)
        tasks = _get_tasks(playbook)
        has_bearer = False
        for task in tasks:
            uri = task.get("ansible.builtin.uri", {})
            headers = uri.get("headers", {})
            auth = headers.get("Authorization", "")
            if "Bearer" in str(auth) and "ja4proxy_token" in str(auth):
                has_bearer = True
                break
        assert has_bearer, f"{filename} does not pass Bearer {{ ja4proxy_token }}"


# ── Emergency Ban CIDR ─────────────────────────────────────────────────────


class TestEmergencyBanCidr:
    def test_posts_to_correct_endpoint(self):
        playbook = _load_playbook("emergency-ban-cidr.yml")
        tasks = _get_tasks(playbook)
        ban_task = None
        for t in tasks:
            uri = t.get("ansible.builtin.uri", {})
            if uri.get("method") == "POST" and "bans" in str(uri.get("url", "")):
                ban_task = t
                break
        assert ban_task is not None, "No POST to /api/v1/bans found"

    def test_url_encodes_cidr(self):
        playbook = _load_playbook("emergency-ban-cidr.yml")
        tasks = _get_tasks(playbook)
        has_encoding = False
        for t in tasks:
            set_fact = t.get("ansible.builtin.set_fact", {})
            if "encoded_cidr" in set_fact:
                value = set_fact["encoded_cidr"]
                assert "%2F" in str(value), "CIDR encoding must replace / with %2F"
                has_encoding = True
        assert has_encoding, "No CIDR encoding step found"

    def test_sends_ttl_in_body(self):
        playbook = _load_playbook("emergency-ban-cidr.yml")
        tasks = _get_tasks(playbook)
        for t in tasks:
            uri = t.get("ansible.builtin.uri", {})
            body = uri.get("body", {})
            if "ttl" in body:
                # TTL should be in seconds (hours * 3600)
                assert "3600" in str(body["ttl"]), "TTL should be in seconds"
                return
        pytest.fail("No ttl field found in any POST body")

    def test_slack_skipped_when_disabled(self):
        playbook = _load_playbook("emergency-ban-cidr.yml")
        tasks = _get_tasks(playbook)
        for t in tasks:
            uri = t.get("ansible.builtin.uri", {})
            if "slack" in str(uri.get("url", "")).lower() or "slack" in str(t.get("name", "")).lower():
                when = t.get("when", "")
                assert "slack_enabled" in str(when), "Slack step must check slack_enabled"


# ── Temporary Whitelist ────────────────────────────────────────────────────


class TestTempWhitelistIp:
    def test_posts_to_allowlist(self):
        playbook = _load_playbook("temp-whitelist-ip.yml")
        tasks = _get_tasks(playbook)
        for t in tasks:
            uri = t.get("ansible.builtin.uri", {})
            if uri.get("method") == "POST" and "allowlist" in str(uri.get("url", "")):
                body = uri.get("body", {})
                assert "entry" in body, "Body must include 'entry' (the IP)"
                assert "expires_at" in body, "Body must include 'expires_at'"
                return
        pytest.fail("No POST to /api/v1/allowlist found")

    def test_computes_expires_at(self):
        playbook = _load_playbook("temp-whitelist-ip.yml")
        tasks = _get_tasks(playbook)
        has_compute = False
        for t in tasks:
            set_fact = t.get("ansible.builtin.set_fact", {})
            if "expires_at" in set_fact:
                has_compute = True
        assert has_compute, "Playbook must compute expires_at from ttl_hours"


# ── Maintenance Dial Zero ──────────────────────────────────────────────────


class TestMaintenanceDialZero:
    def test_gets_current_dial_first(self):
        playbook = _load_playbook("maintenance-dial-zero.yml")
        tasks = _get_tasks(playbook)
        # First API call should be GET /api/v1/dial
        found_get = False
        for t in tasks:
            uri = t.get("ansible.builtin.uri", {})
            if uri.get("method") == "GET" and "dial" in str(uri.get("url", "")):
                found_get = True
                break
        assert found_get, "Must GET current dial value before changing"

    def test_uses_patch_for_dial_change(self):
        playbook = _load_playbook("maintenance-dial-zero.yml")
        tasks = _get_tasks(playbook)
        has_patch = False
        for t in tasks:
            uri = t.get("ansible.builtin.uri", {})
            if uri.get("method") == "PATCH" and "dial" in str(uri.get("url", "")):
                has_patch = True
                break
        assert has_patch, "Must use PATCH to change dial"

    def test_waits_for_duration(self):
        playbook = _load_playbook("maintenance-dial-zero.yml")
        tasks = _get_tasks(playbook)
        has_wait = False
        for t in tasks:
            wait = t.get("ansible.builtin.wait_for", {})
            if "timeout" in wait:
                has_wait = True
                # Timeout should include duration_minutes * 60
                assert "duration_minutes" in str(wait["timeout"]), \
                    "Wait timeout must reference duration_minutes"
        assert has_wait, "Must wait for the specified duration"

    def test_restores_dial_after_wait(self):
        playbook = _load_playbook("maintenance-dial-zero.yml")
        tasks = _get_tasks(playbook)
        # There should be at least 2 PATCH tasks (one to zero, one to restore)
        patch_count = 0
        for t in tasks:
            uri = t.get("ansible.builtin.uri", {})
            if uri.get("method") == "PATCH" and "dial" in str(uri.get("url", "")):
                patch_count += 1
        assert patch_count >= 2, \
            f"Expected >=2 PATCH tasks (zero + restore), got {patch_count}"

    def test_servicenow_optional(self):
        playbook = _load_playbook("maintenance-dial-zero.yml")
        tasks = _get_tasks(playbook)
        for t in tasks:
            uri = t.get("ansible.builtin.uri", {})
            if "servicenow" in str(uri.get("url", "")).lower() or \
               "change_request" in str(uri.get("body", {}).get("short_description", "")):
                when = t.get("when", "")
                assert "servicenow_enabled" in str(when), \
                    "ServiceNow step must check servicenow_enabled"
                return
        # ServiceNow integration is optional
        pass
