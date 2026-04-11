"""phase-85: expose the shared TI-feed stub fixture to adversarial tests.

The credential-leak suite needs ``stub_management_client`` to drive the
feed clients without making real HTTP calls. The fixture body lives in
``tests/_helpers/ti_feed_stubs.py`` so multiple test subtrees can share it.
"""

from __future__ import annotations

import pytest

from tests._helpers.ti_feed_stubs import StubManagementClient


@pytest.fixture
def stub_management_client() -> StubManagementClient:
    """Return a fresh in-memory stub for the Management API client."""
    return StubManagementClient()
