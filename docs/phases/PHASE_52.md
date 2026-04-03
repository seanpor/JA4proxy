# Phase 52: Management UI - Phase 3: Administration Tools

Status: PROPOSED
Priority: MEDIUM (Post-Phase 51)

## Goal
Implement interactive administrative tools for managing allowlists, bans, and system configuration directly from the dashboard.

## Sub-Tasks

### 52a — List Management UI
- [ ] **Allowlist:** CRUD interface for the `static:allowlist` in Redis.
- [ ] **JA4 Management:** Search and manage entries in `ja4:whitelist` and `ja4:blacklist`.
- [ ] **Audit Integration:** All UI actions must produce entries in `management:audit_log`.

### 52b — CIDR Ban & Incident Response
- [ ] **CIDR UI:** Visual tool for applying subnet-level blocks (`ban_cidr:{cidr}`) with duration controls.
- [ ] **Search:** Quick-search connections by IP or JA4 to identify active attacks.
- [ ] **Action:** "Kill Connection" button to immediately blacklist an IP from the live feed.

### 52c — System Health & Status
- [ ] **Component View:** Visual indicators for Redis, GeoIP, and Worker health (powered by Phase 41 Health API).
- [ ] **Log Viewer:** Log streaming component for debugging proxy issues in real-time.

## Acceptance Criteria
- [ ] Administrators can add/remove IPs from allowlists via UI.
- [ ] CIDR bans applied via UI are correctly synchronized to all proxy workers.
- [ ] Audit log correctly records which user took which action.
- [ ] Health indicators correctly reflect the status of underlying components.
