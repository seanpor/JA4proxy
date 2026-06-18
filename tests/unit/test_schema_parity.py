"""Verify the two FINDING_SCHEMA copies stay identical.

The schema is duplicated in analytics/output_writer.py (the authoritative
source) and management/api/routes/partials.py (the consumer). Both services
run in separate containers and cannot share code at runtime. This test catches
drift between the two copies at PR time.

If this test fails, update both copies in the same commit.
"""

import pytest

try:
    from analytics.output_writer import FINDING_SCHEMA

    from management.api.routes.partials import _FINDING_SCHEMA
except ImportError:
    pytest.skip("Analytics or Management API not importable", allow_module_level=True)


def test_finding_schema_parity():
    """Both copies of the finding schema must be identical."""
    assert FINDING_SCHEMA == _FINDING_SCHEMA, (
        "FINDING_SCHEMA in analytics/output_writer.py and _FINDING_SCHEMA in "
        "management/api/routes/partials.py have drifted. Update both in the "
        "same commit."
    )
