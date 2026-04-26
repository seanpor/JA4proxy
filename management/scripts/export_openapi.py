#!/usr/bin/env python3
"""Export the management API OpenAPI spec to docs/api/.

Generates both openapi.yaml (canonical, required by MFA/SSO Hardening acceptance criteria)
and openapi.json (convenience copy for tooling that prefers JSON).

Usage:
    # From the repo root:
    MANAGEMENT_TEST_MODE=1 python management/scripts/export_openapi.py

    # Or via make:
    make openapi-spec
"""

import json
import os
import sys
from pathlib import Path

# Ensure the repo root is importable
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

import yaml  # noqa: E402 — after sys.path manipulation

from management.api.main import app  # noqa: E402

schema = app.openapi()

# FastAPI 0.100+ already emits "3.1.0" — this is a no-op guard
schema["openapi"] = "3.1.0"

docs_api_dir = REPO_ROOT / "docs" / "api"
docs_api_dir.mkdir(parents=True, exist_ok=True)

yaml_path = docs_api_dir / "openapi.yaml"
json_path = docs_api_dir / "openapi.json"

with open(yaml_path, "w", encoding="utf-8") as f:
    yaml.dump(schema, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

with open(json_path, "w", encoding="utf-8") as f:
    json.dump(schema, f, indent=2, ensure_ascii=False)
    f.write("\n")

path_count = len(schema.get("paths", {}))
print(f"openapi: {schema['openapi']}")
print(f"paths:   {path_count}")
print(f"written: {yaml_path}")
print(f"written: {json_path}")
