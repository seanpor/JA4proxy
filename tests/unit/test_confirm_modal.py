"""Unit tests for the ConfirmModal and UndoToast Alpine.js components.

These tests verify the JavaScript logic (validation, state) by inspecting
the rendered modal template partial. The JS itself is exercised through
Playwright-style integration tests; here we validate that the HTML template
renders correctly and the modal partial is structurally sound.
"""
import pytest

try:
    from management.api.main import create_app
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


@pytest.mark.asyncio
async def test_confirm_modal_partial_includes_required_fields():
    """The confirm_modal.html partial contains all Decision-4 required elements."""
    app = create_app()
    # The modal partial doesn't have its own route — it's included in other templates.
    # Verify the template exists by checking the templates dir.
    import os
    from pathlib import Path

    modal_path = Path(__file__).parents[2] / "management" / "templates" / "partials" / "confirm_modal.html"
    assert modal_path.exists(), "confirm_modal.html partial must exist"

    content = modal_path.read_text()

    # Decision 4 requirements
    assert "x-data=\"confirmModal\"" in content, "Must use Alpine.js confirmModal component"
    assert "x-show=\"isOpen\"" in content, "Modal must be togglable via isOpen"
    assert "x-model=\"reason\"" in content, "Modal must have a reason field"
    assert "@input=\"onReasonInput()\"" in content, "Reason input must trigger validation"
    assert ":disabled=\"confirmDisabled\"" in content, "Confirm button must be disabled until reason is filled"
    assert "x-model=\"ticketId\"" in content, "Modal must have optional ticket ID field"
    assert "x-text=\"target\"" in content, "Modal must display the target"
    assert "x-text=\"currentState\"" in content, "Modal must display current state"
    assert "action === 'allow'" in content, "Modal must have danger warning for allowlist"


@pytest.mark.asyncio
async def test_confirm_modal_ttl_selector_offers_standard_durations():
    """The TTL dropdown offers the expected standard durations."""
    from pathlib import Path

    modal_path = Path(__file__).parents[2] / "management" / "templates" / "partials" / "confirm_modal.html"
    content = modal_path.read_text()

    assert "value=\"3600\"" in content, "Must offer 1 hour TTL"
    assert "value=\"86400\"" in content, "Must offer 1 day TTL"
    assert "value=\"604800\"" in content, "Must offer 7 day TTL"
    assert "value=\"2592000\"" in content, "Must offer 30 day TTL"


@pytest.mark.asyncio
async def test_undo_toast_js_exists():
    """undo-toast.js exists and registers the Alpine component."""
    from pathlib import Path

    js_path = Path(__file__).parents[2] / "management" / "static" / "undo-toast.js"
    assert js_path.exists(), "undo-toast.js must exist"

    content = js_path.read_text()
    assert "Alpine.data('undoToast'" in content, "Must register undoToast Alpine component"
    assert "action-completed" in content, "Must listen for action-completed custom event"
    assert "countdown" in content, "Must have countdown state variable"


@pytest.mark.asyncio
async def test_confirm_modal_js_exists():
    """confirm-modal.js exists and registers the Alpine component and window global."""
    from pathlib import Path

    js_path = Path(__file__).parents[2] / "management" / "static" / "confirm-modal.js"
    assert js_path.exists(), "confirm-modal.js must exist"

    content = js_path.read_text()
    assert "Alpine.data('confirmModal'" in content, "Must register confirmModal Alpine component"
    assert "window.ConfirmModal" in content, "Must expose window.ConfirmModal for Phase 234 triage queue compatibility"
    assert "open(config)" in content, "Must have an open() method"
    assert "reason.trim().length < 10" in content, "Must enforce 10-character minimum for reason"
