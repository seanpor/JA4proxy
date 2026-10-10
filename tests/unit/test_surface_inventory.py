"""Unit tests for scripts/surface_inventory.py — Attack-Surface Inventory Parser & Generator."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "surface_inventory.py"

# Import helper functions directly from scripts/surface_inventory.py if available
sys.path.insert(0, str(REPO_ROOT / "scripts"))
try:
    import surface_inventory
except ImportError:
    surface_inventory = None


def test_script_file_exists():
    """Verify scripts/surface_inventory.py exists and is executable."""
    assert SCRIPT_PATH.exists(), "scripts/surface_inventory.py must exist"


@pytest.mark.skipif(surface_inventory is None, reason="surface_inventory module not loaded")
def test_parse_fastapi_routes_ast(tmp_path):
    """Verify AST parser extracts FastAPI routes, methods, and role dependencies accurately."""
    sample_code = '''
from fastapi import APIRouter, Depends
from management.api.auth import require_role

router = APIRouter(prefix="/api/v1/test")

@router.get("/status")
def get_status():
    """Get system status."""
    return {"status": "ok"}

@router.post("/update", dependencies=[Depends(require_role("admin"))])
def update_system():
    """Update system config."""
    return {"updated": True}

@router.delete("/reset")
def reset_system(user = Depends(require_role("operator"))):
    """Reset system state."""
    return {"reset": True}
'''
    route_file = tmp_path / "sample_routes.py"
    route_file.write_text(sample_code, encoding="utf-8")

    routes = surface_inventory.parse_fastapi_routes_from_file(route_file)

    assert len(routes) == 3
    paths = {r["path"]: r for r in routes}

    assert "/api/v1/test/status" in paths
    assert paths["/api/v1/test/status"]["method"] == "GET"
    assert paths["/api/v1/test/status"]["role"] == "public"

    assert "/api/v1/test/update" in paths
    assert paths["/api/v1/test/update"]["method"] == "POST"
    assert paths["/api/v1/test/update"]["role"] == "admin"

    assert "/api/v1/test/reset" in paths
    assert paths["/api/v1/test/reset"]["method"] == "DELETE"
    assert paths["/api/v1/test/reset"]["role"] == "operator"


@pytest.mark.skipif(surface_inventory is None, reason="surface_inventory module not loaded")
def test_parse_management_routes_live():
    """Verify AST parser extracts all live routes in management/api/routes/."""
    routes_dir = REPO_ROOT / "management" / "api" / "routes"
    if not routes_dir.exists():
        pytest.skip("management/api/routes directory not found")

    all_routes = surface_inventory.collect_all_management_routes(routes_dir)
    assert len(all_routes) >= 50, f"Expected at least 50 management routes, found {len(all_routes)}"

    # Check known routes exist
    path_set = {r["path"] for r in all_routes}
    assert any("/api/v1" in p or "/health" in p for p in path_set)


def test_surface_inventory_cli_json():
    """Verify running surface_inventory.py --json produces valid JSON output."""
    cmd = [sys.executable, str(SCRIPT_PATH), "--json"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"Script failed with stderr:\n{res.stderr}"

    data = json.loads(res.stdout)
    assert "routes" in data
    assert "listeners" in data
    assert "redis_keys" in data
    assert len(data["routes"]) > 0


def test_surface_inventory_cli_check():
    """Verify running surface_inventory.py --check exits cleanly when ATTACK_SURFACE.md is in sync."""
    cmd = [sys.executable, str(SCRIPT_PATH), "--check"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, f"--check failed with output:\n{res.stdout}\n{res.stderr}"
