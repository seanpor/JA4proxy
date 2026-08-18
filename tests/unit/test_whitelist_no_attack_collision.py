"""No whitelisted JA4 may also be an attack fingerprint.

WHY THIS EXISTS
---------------
A JA4 whitelist entry is an ALLOW BYPASS. Per CLAUDE.md it never reaches the
scorer and is *unaffected by the dial* — deliberately, so a real browser can
never be blocked. The cost of that guarantee is that one wrong entry is
unconditional: no threshold, no dial setting, and no signal can override it.

`t13d101100_61a7ad8aa9b6_d41ae481755e` sat in the whitelist labelled "Benchmark
Generator (Alternative)". Observed on the running stack, it is exactly what the
Sliver_C2 AND Evilginx_Phishing profiles emit — two different simulated tools
sharing a TLS stack share a fingerprint. So every Evilginx and Sliver connection
was allowed outright, at any dial, and a demo showed attack traffic connecting
while the operator raised the dial and nothing changed.

It was found by eye, in a demo. These tests make the class impossible to
reintroduce quietly.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WHITELIST_CSV = REPO_ROOT / "data" / "ja4_whitelist.csv"
PROXY_YML = REPO_ROOT / "config" / "proxy.yml"
KNOWN_BAD = REPO_ROOT / "config" / "known_bad_fingerprints.yml"

# Observed on the running POC stack (phase-827) by connecting with each profile
# in scripts/tls-traffic-generator.py and reading the resulting JA4 off
# events:connection. Note the two collisions — they are the point: a JA4
# identifies a TLS stack, not a tool.
ATTACK_PROFILE_JA4 = {
    "t13d101100_61a7ad8aa9b6_d41ae481755e": "Sliver_C2 and Evilginx_Phishing",
    "t12d030700_0f9cd282b7f5_e7e480e5a997": "CobaltStrike_Beacon and Credential_Stuffer",
    "t13d311100_e8f1e7e78f70_d41ae481755e": "Python_Requests_Bot",
    "t12d020500_a5878986a7c9_847bbcdea70d": "Masscan_Scanner",
}


def csv_whitelist() -> set[str]:
    out = set()
    for line in WHITELIST_CSV.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.add(line.split(",")[0].strip())
    return out


def yml_whitelist() -> set[str]:
    """The `whitelist:` block in proxy.yml — the list loaded into Redis."""
    text = PROXY_YML.read_text()
    m = re.search(r"^\s*whitelist:\s*$", text, re.M)
    if not m:
        return set()
    out = set()
    for line in text[m.end():].splitlines():
        if line.strip().startswith("#") or not line.strip():
            continue
        entry = re.match(r'^\s+-\s+"([^"]+)"', line)
        if entry:
            out.add(entry.group(1))
            continue
        if not line.startswith((" ", "\t")):
            break
    return out


def known_bad_ja4() -> set[str]:
    data = yaml.safe_load(KNOWN_BAD.read_text()) or {}
    return {
        str(e["ja4"]).strip()
        for e in (data.get("fingerprints") or [])
        if e.get("ja4")
    }


def test_whitelist_contains_no_attack_generator_fingerprint():
    for source, entries in (("proxy.yml", yml_whitelist()), ("ja4_whitelist.csv", csv_whitelist())):
        collisions = entries & set(ATTACK_PROFILE_JA4)
        assert not collisions, (
            f"{source} whitelists fingerprint(s) emitted by attack profiles:\n"
            + "\n".join(f"  {j}  <- {ATTACK_PROFILE_JA4[j]}" for j in sorted(collisions))
            + "\n\nA whitelist entry is an ALLOW BYPASS: it skips the scorer entirely "
            "and ignores the dial, so this traffic cannot be blocked by any setting."
        )


def test_whitelist_contains_no_known_bad_fingerprint():
    """The catalogue we ship as malicious must never also be bypassed."""
    bad = known_bad_ja4()
    assert bad, "known_bad_fingerprints.yml parsed empty — test would be vacuous"
    for source, entries in (("proxy.yml", yml_whitelist()), ("ja4_whitelist.csv", csv_whitelist())):
        collisions = entries & bad
        assert not collisions, (
            f"{source} whitelists {sorted(collisions)}, which config/"
            "known_bad_fingerprints.yml ships as known-malicious"
        )


def test_benchmark_whitelist_is_a_subset_of_the_operational_one():
    """The CSV is the benchmark whitelist; proxy.yml is what loads into Redis.

    Equality is NOT the invariant — proxy.yml legitimately carries many more
    entries, and an earlier version of this test asserted they must match, which
    was simply a wrong premise about two files that serve different purposes.

    Subset IS the invariant: a fingerprint the benchmark treats as whitelisted
    but the proxy does not would make the benchmark measure a policy the proxy
    never runs, and the number it reports would be for a different system.
    """
    only_csv = csv_whitelist() - yml_whitelist()
    assert not only_csv, (
        f"ja4_whitelist.csv whitelists {sorted(only_csv)}, which config/proxy.yml "
        "does not — the benchmark would measure a policy the proxy never applies"
    )


def test_fixture_is_not_vacuous():
    assert yml_whitelist(), "parsed no whitelist from proxy.yml — regex broken"
