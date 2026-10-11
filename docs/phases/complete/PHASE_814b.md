# Reconnaissance, Attack-Surface Baseline, and Durable-Content Lift

## Goal
Automate the discovery and continuous inventory of JA4proxy's complete attack surface using static AST parsing and zero-runtime reflection, generating a single canonical markdown artifact (`docs/security/ATTACK_SURFACE.md`) backed by a strict CI drift check (`make lint`). Perform the durable-content lift by reorganizing historic threat models, methodology documents, and pentest finding specifications into the standard `docs/security/pentest/` structure.

## Scope
- **AST Inventory Script:** Create `scripts/surface_inventory.py` to statically inspect Python FastAPI routes in `management/api/routes/*.py` using Python's `ast` standard library module.
  - Parse route decorators (`@router.get`, `@router.post`, etc.).
  - Identify required authorization roles from `Depends(require_role(...))` calls or router defaults.
  - Enumerate listening ports/sockets across Docker Compose files (`deploy/docker/docker-compose*.yml`) and Helm templates (`deploy/helm/`).
  - Catalog Redis key patterns from Go state store implementation (`internal/redis/`) and Lua scripts (`scripts/*.lua`).
  - Extract external outbound endpoints and background workflow triggers.
- **Attack Surface Documentation Generator:** Merge automated AST inventory output with curated human metadata (`docs/security/attack-surface.yaml`) to generate `docs/security/ATTACK_SURFACE.md`.
- **CI Drift Check & Makefile Targets:** Add `make surface-inventory` and a `make lint` check enforcing that `ATTACK_SURFACE.md` remains strictly in sync with the codebase.
- **Durable-Content Lift:** Reorganize historic threat model documents, test methodologies, and pentest finding specs into `docs/security/pentest/`.

## Implementation Plan

### Step 1: Create `scripts/surface_inventory.py` (AST Parser & Generator)
1. Use `ast.parse` to traverse files in `management/api/routes/*.py`.
2. Extract all HTTP methods, path strings, function names, and security role requirements (`admin`, `operator`, `analyst`, `public`).
3. Parse Compose (`deploy/docker/docker-compose*.yml`) and Helm templates (`deploy/helm/`) for exposed TCP/UDP ports and internal socket listeners.
4. Scan `internal/redis/` and `.lua` files for Redis key patterns (e.g. `ja4:blocklist:*`, `ja4:rate:*`, `ja4:session:*`).
5. Output structured YAML/JSON representing the measured live attack surface.

### Step 2: Integrate `docs/security/attack-surface.yaml` and Generate `ATTACK_SURFACE.md`
1. Merge measured technical data with hand-maintained business risk context in `docs/security/attack-surface.yaml`.
2. Render formatted `docs/security/ATTACK_SURFACE.md` containing full endpoint matrices, role requirements, network listener topologies, and Redis key specs.

### Step 3: Add `make surface-inventory` & CI Drift Check
1. Add `surface-inventory` target to `Makefile` invoking `python3 scripts/surface_inventory.py`.
2. Add `--check` mode to `scripts/surface_inventory.py` that exits non-zero if `ATTACK_SURFACE.md` differs from the generated inventory.
3. Wire `--check` into `make lint` (or `test_sync_reference_docs.py` / CI gate).

### Step 4: Reorganize Pentest Documentation (Durable-Content Lift)
1. Move historic threat models and methodology files into `docs/security/pentest/`.
2. Verify all markdown relative links remain unbroken (`make lint-docs`).

## Test Strategy
1. **Unit & AST Parser Tests:**
   - Create `tests/unit/test_surface_inventory.py` to verify AST parser accurately extracts all routes, methods, and role requirements from mock and real route files.
   - Verify parser handles all FastAPI decorator syntax patterns and nested router inclusions.
2. **Drift Enforcement Test:**
   - Test `scripts/surface_inventory.py --check` returns exit code 0 when `ATTACK_SURFACE.md` is up-to-date and non-zero when modified or out-of-sync.
3. **Preflight Gate:**
   - Run `make preflight` to confirm linting, security scans, unit tests, and race detector pass cleanly.

## Acceptance Criteria
- `scripts/surface_inventory.py` executes in < 0.2s with zero external dependencies (pure stdlib AST parsing).
- `docs/security/ATTACK_SURFACE.md` contains an accurate, formatted table of all 105+ management endpoints, role requirements, network listeners, and Redis key schemas.
- `make surface-inventory` successfully updates `docs/security/ATTACK_SURFACE.md`.
- `make lint` catches any uncommitted changes to `ATTACK_SURFACE.md`.
- All historic pentest docs and specs are clean and properly filed under `docs/security/pentest/`.
- All tests in `make preflight` pass with 0 errors/warnings.

## Out of Scope
- Runtime endpoint reflection (using FastAPI `app.routes` at runtime is excluded in favor of static AST parsing to prevent boot side-effects and complex dependencies).
- Implementing new management API endpoints or changing API authorization logic.
