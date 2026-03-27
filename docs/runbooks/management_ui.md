<!--
title: Management_Ui
audience: Operators, Security Teams
last_reviewed: 2026-03-27
phase: 21
-->

# Management UI Operations Runbook

> **[DEPRECATED — Phase 13 Management UI was removed in v13.2.0]**
>
> The Management UI will be re-implemented after the Go rewrite (Phase 15) completes.
> See `docs/phases/PHASE_13b.md` for the deferred implementation plan.
> This runbook is retained as a reference for the planned future implementation.
> **Do not follow these instructions against a running proxy — the endpoints do not exist.**

---

## Original Content (Retained for Reference)

The Management UI provided a web interface for:
- Viewing active connections
- Managing bans and whitelists
- Adjusting the risk dial
- Viewing analytics dashboards

### Planned Features for Future Implementation

When re-implemented, the Management UI will include:
- Real-time connection feed via Server-Sent Events
- Redis-backed configuration with hot-reload
- Role-based access control
- Audit logging for all administrative actions

### Configuration Reference

The planned configuration structure:

```yaml
management_ui:
  enabled: true
  allowed_cidr: "10.0.0.0/8"
  api_key: "${UI_API_KEY}"
  port: 8080
```

### Security Considerations

- API key authentication required for all endpoints
- CIDR-based IP restrictions
- Rate limiting on all write operations
- All sensitive operations logged to audit trail

### Migration Notes

When the Management UI is re-implemented:
1. Generate a new `UI_API_KEY` and add to secrets
2. Configure `allowed_cidr` to restrict access
3. Enable the UI in `config/proxy.yml`
4. Restart the proxy service

For current operations, use the Redis CLI and direct configuration file edits as documented in the main operations guides.