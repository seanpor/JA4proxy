# PHASE 17 — Fix Docker Test Container Hang

All fixes are applied in `tests/conftest.py`.

| Fix | File(s) | Status |
|-----|---------|--------|
| Add `PYTHONUNBUFFERED=1` | `docker/Dockerfile.test`, `docker/docker-compose.poc.yml` | ✅ Done |
| Patch `_tor_refresh_loop` in `_no_real_network` | `tests/conftest.py` | ✅ Done |
| Change `pytest_sessionfinish` to `tryfirst=True` | `tests/conftest.py` | ✅ Done |

---

All implementation details are contained directly in this document and in the
referenced files above.
