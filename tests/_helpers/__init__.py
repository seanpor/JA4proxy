"""Shared test helpers used across multiple test subtrees.

Helpers are kept here as a regular import package (not a conftest) so
files in ``tests/unit/``, ``tests/adversarial/``, ``tests/chaos/`` etc.
can all reach the same stub classes without conftest scope tricks.
"""
