### Added
- `POST /api/v1/dial/emergency` — bypasses ±10 step limit for incident response (admin + MFA required, auto-reverts after 1-4 hours)
- Emergency dial presets: `block_known_bad` (50), `active_defense` (75), `lockdown` (90)
- `ja4-admin.sh dial` commands — show current value, set with ±10 limit, or `--emergency` override with auto-revert
- `make admin` target for running the incident response CLI
- `docs/operations/DEPLOYMENT_MODES.md` — deployment guides for direct, HAProxy, nginx, AWS NLB, and Cloudflare
