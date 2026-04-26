"""Startup loader for ``config/known_bad_fingerprints.yml``.

PHASE_85.md §7.1 — the bundled seed file ships with vetted JA4 fingerprints
from public security research. Loaded once at startup if
``threat_intel.seed_file.enabled: true``; each entry is routed through the
Phase 79 Management API with ``managed_by=feed`` and
``note=feed:seed_file:{ja4}`` so the standard provenance and audit flow
applies.

This is *not* a polling feed — it runs once at startup, so we do not bother
with a :class:`FeedClient` subclass or circuit breaker. On hot-reload
(SIGHUP), the runner calls :func:`run_once` again; the first-writer-wins
semantics of the canonical list routes make repeat calls idempotent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

from .ja4_safety import ja4_safe_to_block
from .metrics import TI_FEED_FP_BLOCKED as _FP_BLOCKED
from .metrics import TI_SEED_ENTRIES as _SEED_ENTRIES_LOADED
from .mgmt_client import ManagementAPIError, ManagementClient
from .state import FeedState
from .stix_ja4 import is_valid_ja4

logger = logging.getLogger(__name__)

_SEED_FEED_ID = "seed_file"


@dataclass
class SeedFingerprint:
    """Parsed seed entry — all fields required."""

    ja4: str
    name: str
    category: str
    source: str
    confidence: int


def _parse_entries(raw: dict[str, Any]) -> list[SeedFingerprint]:
    """Extract + validate seed entries from a parsed YAML document.

    Rejects malformed entries by logging a WARN and skipping — we never
    crash the analytics container on a bad line in the seed file.
    """
    fingerprints_raw = raw.get("fingerprints", [])
    if not isinstance(fingerprints_raw, list):
        logger.warning(
            "ti_feed | event=seed_file_malformed | reason=fingerprints_not_list"
        )
        return []

    parsed: list[SeedFingerprint] = []
    for entry in fingerprints_raw:
        if not isinstance(entry, dict):
            logger.warning(
                "ti_feed | event=seed_entry_malformed | reason=not_dict"
            )
            continue
        ja4 = entry.get("ja4", "")
        name = entry.get("name", "")
        category = entry.get("category", "")
        source = entry.get("source", "")
        confidence = entry.get("confidence", 0)

        if not isinstance(ja4, str) or not is_valid_ja4(ja4):
            logger.warning(
                "ti_feed | event=seed_entry_rejected | reason=invalid_ja4 | ja4=%r",
                ja4,
            )
            continue
        if not all(isinstance(x, str) and x for x in (name, category, source)):
            logger.warning(
                "ti_feed | event=seed_entry_rejected | reason=missing_metadata | ja4=%s",
                ja4,
            )
            continue
        try:
            conf_int = int(confidence)
        except (TypeError, ValueError):
            logger.warning(
                "ti_feed | event=seed_entry_rejected | reason=bad_confidence | ja4=%s",
                ja4,
            )
            continue
        if not 0 <= conf_int <= 100:
            logger.warning(
                "ti_feed | event=seed_entry_rejected | reason=confidence_out_of_range | ja4=%s",
                ja4,
            )
            continue
        parsed.append(
            SeedFingerprint(
                ja4=ja4,
                name=name,
                category=category,
                source=source,
                confidence=conf_int,
            )
        )
    return parsed


class SeedFileLoader:
    """Strict YAML loader for ``config/known_bad_fingerprints.yml``.

    Unlike :func:`load_seed_file` (which logs-and-skips bad entries on the
    runtime hot-path), this loader **raises** ``ValueError`` on the first
    malformed entry. It is the surface tests use to assert the schema and
    is what the Phase 85 acceptance gate runs at startup.
    """

    def __init__(self, path: "str | Path") -> None:
        self._path = Path(path)

    def load(self) -> list[dict[str, Any]]:
        """Parse and validate the seed file. Returns a list of entry dicts.

        Raises:
            ValueError: On any malformed entry, missing required field,
                invalid JA4, out-of-range confidence, or empty
                ``fingerprints:`` section.
            FileNotFoundError: If the seed file is missing.
        """
        if yaml is None:  # pragma: no cover
            raise RuntimeError("pyyaml is required for the seed file loader")
        if not self._path.exists():
            raise FileNotFoundError(f"seed file not found: {self._path}")

        text = self._path.read_text(encoding="utf-8")
        raw = yaml.safe_load(text) or {}
        if not isinstance(raw, dict):
            raise ValueError(
                f"seed file root must be a mapping, got {type(raw).__name__}"
            )
        fingerprints = raw.get("fingerprints")
        if not isinstance(fingerprints, list) or not fingerprints:
            raise ValueError(
                "seed file 'fingerprints' must be a non-empty list"
            )

        out: list[dict[str, Any]] = []
        for idx, entry in enumerate(fingerprints):
            if not isinstance(entry, dict):
                raise ValueError(
                    f"seed entry #{idx} must be a mapping, got {type(entry).__name__}"
                )
            for required in ("ja4", "name", "category", "source", "confidence"):
                if required not in entry:
                    raise ValueError(
                        f"seed entry #{idx} missing required field {required!r}"
                    )
            ja4 = entry["ja4"]
            if not isinstance(ja4, str) or not is_valid_ja4(ja4):
                raise ValueError(
                    f"seed entry #{idx} has invalid JA4: {ja4!r}"
                )
            try:
                confidence = int(entry["confidence"])
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"seed entry #{idx} confidence is not an int: {entry['confidence']!r}"
                ) from exc
            if not 0 <= confidence <= 100:
                raise ValueError(
                    f"seed entry #{idx} confidence out of range [0,100]: {confidence}"
                )
            out.append(entry)
        return out


def load_seed_file(path: str | Path) -> list[SeedFingerprint]:
    """Read and validate the seed file. Returns `[]` if missing or empty.

    Raises:
        RuntimeError: If ``pyyaml`` is not installed — a hard dependency of
            the whole analytics container, so this should never fire in
            production.
    """
    if yaml is None:  # pragma: no cover
        raise RuntimeError("pyyaml is required for the seed file loader")
    p = Path(path)
    if not p.exists():
        logger.info(
            "ti_feed | event=seed_file_absent | path=%s",
            str(p),
        )
        return []
    text = p.read_text(encoding="utf-8")
    if not text.strip():
        return []
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        logger.warning(
            "ti_feed | event=seed_file_malformed | path=%s | reason=not_dict",
            str(p),
        )
        return []
    return _parse_entries(raw)


async def run_once(
    *,
    mgmt: ManagementClient,
    state: FeedState,
    path: str | Path = "config/known_bad_fingerprints.yml",
    min_entries: int = 10,
    instance_id: str | None = None,
) -> dict[str, int]:
    """Load the seed file and push every entry through the Management API.

    Args:
        mgmt: The feed runner's :class:`ManagementClient`.
        state: The feed runner's :class:`FeedState`. Each seed entry is
            recorded in the seed-file feed's sidecar index, the same way a
            regular feed would.
        path: Seed file path (relative paths are resolved against the
            current working directory).
        min_entries: Log a WARN if fewer than this many entries parsed —
            the acceptance criterion is ≥10 vetted entries.
        instance_id: When provided, the loader gates its work on the shared
            ``ti_feed:leader_lock`` (M13). Only the elected leader pushes
            seed entries; other replicas return an empty summary. Pass
            ``None`` to skip the gate (legacy / single-replica callers).

    Returns:
        A summary dict ``{loaded, created, rejected, errors}``. When the
        leader gate is enabled and this replica did not win the lock,
        every counter is zero and ``loaded`` reflects entries parsed
        before the gate was checked (i.e. zero — no parse is attempted).
    """
    if instance_id is not None:
        # M13 (PHASE_101): without this gate, every analytics replica would
        # POST every seed entry on startup. Mgmt API is first-writer-wins
        # so it's safe but wasteful; the lock collapses N startup loads
        # into one. Lock TTL is intentionally generous (60s) — the seed
        # file is bounded and applies in well under a second normally,
        # but a slow Mgmt API or large seed file should not race the
        # lock expiry.
        if not await state.try_acquire_leader(instance_id, ttl_seconds=60):
            logger.info(
                "ti_feed | event=seed_file_skipped_not_leader | instance=%s",
                instance_id,
            )
            return {"loaded": 0, "created": 0, "rejected": 0, "errors": 0}

    entries = load_seed_file(path)
    summary = {
        "loaded": len(entries),
        "created": 0,
        "rejected": 0,
        "errors": 0,
    }

    if len(entries) < min_entries:
        logger.warning(
            "ti_feed | event=seed_file_short | loaded=%d | expected_min=%d",
            len(entries),
            min_entries,
        )

    for entry in entries:
        # C6 (PHASE_101): FP corpus check — never seed a known-browser JA4.
        safe, _reason = ja4_safe_to_block(entry.ja4)
        if not safe:
            summary["rejected"] += 1
            _FP_BLOCKED.labels(feed_id=_SEED_FEED_ID).inc()
            logger.warning(
                "ti_feed | event=seed_entry_fp_blocked | ja4=%s", entry.ja4
            )
            continue
        note = f"feed:{_SEED_FEED_ID}:{entry.ja4}"
        try:
            resource = await mgmt.post_blocklist(
                feed_id=_SEED_FEED_ID,
                entry=entry.ja4,
                note=note,
            )
        except ManagementAPIError as exc:
            summary["errors"] += 1
            _SEED_ENTRIES_LOADED.labels(feed_id=_SEED_FEED_ID, outcome="error").inc()
            logger.warning(
                "ti_feed | event=seed_entry_api_error | ja4=%s | status=%d | error=%s",
                entry.ja4,
                exc.status_code,
                exc.message,
            )
            continue
        except Exception as exc:  # noqa: BLE001
            summary["errors"] += 1
            _SEED_ENTRIES_LOADED.labels(feed_id=_SEED_FEED_ID, outcome="error").inc()
            logger.warning(
                "ti_feed | event=seed_entry_error | ja4=%s | error=%s",
                entry.ja4,
                exc,
            )
            continue
        await state.mark(
            _SEED_FEED_ID,
            stix_id=entry.ja4,
            handle=resource.id,
            kind="blocklist",
        )
        summary["created"] += 1
        _SEED_ENTRIES_LOADED.labels(feed_id=_SEED_FEED_ID, outcome="created").inc()

    logger.info(
        "ti_feed | event=seed_file_applied | loaded=%d | created=%d | errors=%d",
        summary["loaded"],
        summary["created"],
        summary["errors"],
    )
    return summary
