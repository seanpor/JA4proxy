"""Tests for management.compliance.classifier.SignalClassifier.

Quality bar
-----------
- Every test verifies a specific resolution *rule*, not just "signal X → category Y".
- Multi-signal conflict resolution is explicitly tested.
- Custom weight overrides, unknown signals, empty inputs, and batch behaviour all covered.
- Mutation safety of classify_batch is verified.
"""

import copy

import pytest

from management.compliance.classifier import SignalClassifier

# ── classify() ───────────────────────────────────────────────────────────────


def test_highest_weight_wins():
    """When multiple signals fire, the one with the highest weight sets the category."""
    clf = SignalClassifier()
    # sni_missing weight=55, spamhaus_drop weight=100 → known_malicious_network
    result = clf.classify(["sni_missing", "spamhaus_drop"])
    assert result == "known_malicious_network"


def test_lower_weight_signal_alone():
    """A low-weight signal still classifies correctly when no heavier signal fires."""
    clf = SignalClassifier()
    result = clf.classify(["country_blacklist"])  # weight 40
    assert result == "geo_blocked"


def test_empty_signals_returns_fallback():
    """Empty signal list must return FALLBACK_CATEGORY, not raise."""
    clf = SignalClassifier()
    result = clf.classify([])
    assert result == SignalClassifier.FALLBACK_CATEGORY
    assert result == "high_risk_score"


def test_all_unknown_signals_returns_fallback():
    """Signal names not in the mapping are silently ignored; result is fallback."""
    clf = SignalClassifier()
    result = clf.classify(["made_up_signal", "also_fake"])
    assert result == "high_risk_score"


def test_unknown_signal_mixed_with_known():
    """Unknown signals are ignored; the known signal still determines the category."""
    clf = SignalClassifier()
    result = clf.classify(["this_does_not_exist", "tor_exit"])
    assert result == "tor_exit_node"


def test_tie_broken_alphabetically_by_category():
    """When two signals produce the same weight, the alphabetically earlier
    category name wins (deterministic)."""
    clf = SignalClassifier()
    # datacenter and asn_datacenter both map to "datacenter_scanner" weight=50.
    # They produce the same category, so this test also verifies no crash on tie.
    result = clf.classify(["datacenter", "asn_datacenter"])
    assert result == "datacenter_scanner"


def test_tie_between_different_categories_alphabetical():
    """Construct a case where two *different* categories have equal weight.
    The alphabetically earlier category must win."""
    # Override two signals to same weight but different categories
    clf = SignalClassifier(
        signal_categories={
            "signal_alpha": {"category": "zzz_category", "weight": 77},
            "signal_beta":  {"category": "aaa_category", "weight": 77},
        }
    )
    # aaa_category < zzz_category alphabetically → aaa_category must win
    result = clf.classify(["signal_alpha", "signal_beta"])
    assert result == "aaa_category"


def test_custom_weight_override_beats_default():
    """A custom weight override can promote a low-weight signal above a high-weight one."""
    clf = SignalClassifier(
        signal_categories={
            "sni_missing": {"category": "automation_tool", "weight": 200},
        }
    )
    # sni_missing now weight=200 > spamhaus_drop weight=100
    result = clf.classify(["sni_missing", "spamhaus_drop"])
    assert result == "automation_tool"


def test_custom_override_preserves_all_other_defaults():
    """Overriding one signal must not remove the other 11 default mappings."""
    clf = SignalClassifier(
        signal_categories={
            "sni_missing": {"category": "automation_tool", "weight": 200},
        }
    )
    # All defaults except the overridden one must still be present
    expected_defaults = set(SignalClassifier.DEFAULT_SIGNAL_CATEGORIES.keys())
    assert expected_defaults.issubset(clf.categories.keys())


def test_custom_new_signal_added():
    """A completely new signal name can be added via config."""
    clf = SignalClassifier(
        signal_categories={
            "my_custom_signal": {"category": "custom_category", "weight": 99},
        }
    )
    result = clf.classify(["my_custom_signal"])
    assert result == "custom_category"


# ── classify_batch() ─────────────────────────────────────────────────────────


def test_classify_batch_adds_category_field():
    """classify_batch adds a 'category' field to each event in the output."""
    clf = SignalClassifier()
    events = [
        {"ip": "1.2.3.4", "signals": ["spamhaus_drop"]},
        {"ip": "5.6.7.8", "signals": ["sni_missing"]},
        {"ip": "9.0.1.2", "signals": []},
    ]
    result = clf.classify_batch(events)

    assert result[0]["category"] == "known_malicious_network"
    assert result[1]["category"] == "automation_tool"
    assert result[2]["category"] == "high_risk_score"


def test_classify_batch_preserves_original_fields():
    """All original event fields must be present in the output, unchanged."""
    clf = SignalClassifier()
    event = {"ip": "1.2.3.4", "risk_score": "85", "ja4": "abc", "signals": ["tor_exit"]}
    result = clf.classify_batch([event])

    assert result[0]["ip"] == "1.2.3.4"
    assert result[0]["risk_score"] == "85"
    assert result[0]["ja4"] == "abc"
    assert result[0]["category"] == "tor_exit_node"


def test_classify_batch_missing_signals_key():
    """Events with no 'signals' key should get FALLBACK_CATEGORY, not raise."""
    clf = SignalClassifier()
    events = [{"ip": "1.2.3.4"}]  # no 'signals' key
    result = clf.classify_batch(events)
    assert result[0]["category"] == "high_risk_score"


def test_classify_batch_does_not_mutate_input():
    """Input event dicts must not be modified by classify_batch."""
    clf = SignalClassifier()
    original_event = {"ip": "1.2.3.4", "signals": ["spamhaus_drop"]}
    original_copy = copy.deepcopy(original_event)

    clf.classify_batch([original_event])

    assert original_event == original_copy, "Input event was mutated by classify_batch"


def test_classify_batch_empty_list():
    """classify_batch on an empty list returns an empty list without error."""
    clf = SignalClassifier()
    result = clf.classify_batch([])
    assert result == []


def test_classify_batch_mixed_known_and_unknown_signals():
    """Batch correctly handles events where some signals are known and some unknown."""
    clf = SignalClassifier()
    events = [
        {"signals": ["fake_signal_1", "beaconing_detected", "fake_signal_2"]},
    ]
    result = clf.classify_batch(events)
    # Only beaconing_detected is known → c2_beaconing
    assert result[0]["category"] == "c2_beaconing"


# ── categories property ───────────────────────────────────────────────────────


def test_categories_property_returns_all_defaults():
    """Default classifier has at least 12 signal mappings."""
    clf = SignalClassifier()
    assert len(clf.categories) >= 12


def test_categories_property_is_copy():
    """Mutating the returned categories dict must not affect the classifier.

    This test detects the bug where `categories` returns a direct reference.
    The mutation changes the CATEGORY NAME (not just the weight), so if the
    internal state is mutated the classifier's output would change.
    """
    clf = SignalClassifier()
    cats = clf.categories
    # Mutate the category name in the RETURNED dict — if it's a direct reference,
    # subsequent classify() calls would return "mutated_name" instead of
    # "known_malicious_network".
    cats["spamhaus_drop"]["category"] = "mutated_name"
    # Classifier must still use original category name.
    result = clf.classify(["spamhaus_drop"])
    assert result == "known_malicious_network", (
        f"categories property returned a reference (not copy): got {result!r}"
    )
