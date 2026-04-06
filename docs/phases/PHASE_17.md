# PHASE 17 — Fix Docker Test Container Hang

All fixes are applied in `tests/conftest.py`.

| Fix | File(s) | Status |
|-----|---------|--------|
| Add `PYTHONUNBUFFERED=1` | `docker/Dockerfile.test`, `docker/docker-compose.poc.yml` | ✅ Done |
| Patch `_tor_refresh_loop` in `_no_real_network` | `tests/conftest.py` | ✅ Done |
| Change `pytest_sessionfinish` to `tryfirst=True` | `tests/conftest.py` | ✅ Done |

---

## Which document do you need?

### → [PHASE_17_JUNIOR.md](details/PHASE_17_JUNIOR.md)
Step-by-step implementation guide. You do not need to understand the internals —
just follow the steps, run the verification commands, and commit.

### → [PHASE_17_SENIOR.md](details/PHASE_17_SENIOR.md)
Technical root cause analysis, explanation of why each fix works, versioning
constraints, and notes for future maintainers.
