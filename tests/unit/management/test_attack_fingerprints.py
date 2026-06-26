"""CI-safe tests for Phase 250 botnet fingerprint detection."""

import pytest

try:
    from management.api.routes.attack import detect_botnet_signal  # noqa: F401
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


def test_botnet_signal_botnet():
    from management.api.routes.attack import detect_botnet_signal
    assert detect_botnet_signal(23, 82.0, False) == "botnet"


def test_botnet_signal_suspect():
    from management.api.routes.attack import detect_botnet_signal
    assert detect_botnet_signal(4, 61.0, False) == "suspect"


def test_botnet_signal_browser():
    from management.api.routes.attack import detect_botnet_signal
    assert detect_botnet_signal(100, 99.0, True) == "browser"


def test_botnet_signal_tool():
    from management.api.routes.attack import detect_botnet_signal
    assert detect_botnet_signal(2, 10.0, False) == "tool"


def test_botnet_signal_unknown():
    from management.api.routes.attack import detect_botnet_signal
    assert detect_botnet_signal(1, 30.0, False) == "unknown"


def test_botnet_signal_attack_mode():
    from management.api.routes.attack import detect_botnet_signal
    assert detect_botnet_signal(3, 55.0, False, attack_mode=True) == "botnet"


def test_corpus_loads():
    from management.api.ja4_corpus import corpus_size
    assert corpus_size() >= 10


def test_known_browser_true():
    from management.api.ja4_corpus import _CORPUS, is_known_browser
    for fp in list(_CORPUS)[:3]:
        assert is_known_browser(fp)


def test_known_browser_false_for_curl():
    from management.api.ja4_corpus import is_known_browser
    assert not is_known_browser("t13d190900_9dc949149365_97f8aa674fd9")
