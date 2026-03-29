# Phase 42 — Zero-Downtime Data Upgrades (GeoIP & Config)

Status: PROPOSED

## Goal

Enable instantaneous, zero-downtime upgrades and rollbacks for large data files (GeoIP databases) and system configurations without requiring a process restart or interrupting active connections.

## Background

Currently, updating the GeoIP database requires a full proxy restart (`make stop && make start`). This causes a several-second interruption in traffic. For enterprise environments, we need a "fraction of a second" swap mechanism that ensures consistency.

## Sub-Tasks

### 42a — Atomic File Swapping
- Implement a "versioned data" directory structure (e.g., `geoip/v1/`, `geoip/v2/`).
- Use a symbolic link (`geoip/current`) or atomic `os.rename()` to switch between versions.
- Ensure the proxy follows the symlink or re-opens the file handle upon a reload signal.

### 42b — GeoIP Hot-Reloading
- Update `GeoIPLookup` class to support re-opening the database file without losing state.
- Implement a file watcher (via `watchdog` or periodic `stat`) or a Redis PubSub signal to trigger the reload.
- **Validation:** Verify the new database is valid and readable BEFORE swapping it into production.

### 42c — Enhanced Config Hot-Reload
- Extend `ConfigLoader` to support atomic updates for all non-structural parameters.
- Ensure that reloading a large config doesn't block the event loop (async parsing).
- Implement a "dry-run" validation step for all reloads.

### 42d — Rollback Mechanism
- Maintain a `.prev` pointer or a 2-version buffer for all data files.
- Automatically roll back if the new file fails validation or causes an immediate spike in health-check failures.

## Acceptance Criteria

- [ ] GeoIP database can be updated while the proxy is under heavy load with zero dropped connections.
- [ ] Database swap takes < 100ms.
- [ ] Rollback to previous version works instantaneously via `ja4-admin.sh`.
- [ ] Proxy logs successful reloads with timestamps and version identifiers.
