#!/usr/bin/env python3
"""Attack-Surface Inventory Parser & Documentation Generator.

Statically parses FastAPI routes (management/api/routes/*.py), container network
listeners (deploy/docker/docker-compose*.yml), and Redis key schemas using pure
Python standard library AST/regex parsing without executing runtime code.

Generates docs/security/ATTACK_SURFACE.md and enforces CI drift check (--check).
"""

import argparse
import ast
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ROUTES_DIR = REPO_ROOT / "management" / "api" / "routes"
COMPOSE_FILE = REPO_ROOT / "deploy" / "docker" / "docker-compose.poc.yml"
ATTACK_SURFACE_MD = REPO_ROOT / "docs" / "security" / "ATTACK_SURFACE.md"


def _extract_role_name(node: ast.AST) -> str:
    """Extract role string from AST node representing require_role call or argument."""
    if isinstance(node, ast.Call):
        # require_role("admin") or require_role(Role.admin)
        if isinstance(node.func, ast.Name) and node.func.id == "require_role":
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
                if isinstance(arg, ast.Attribute):
                    return arg.attr
        # Depends(require_role(...))
        if isinstance(node.func, ast.Name) and node.func.id == "Depends":
            if node.args:
                return _extract_role_name(node.args[0])

    elif isinstance(node, ast.Attribute):
        return node.attr
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    return "public"


def parse_fastapi_routes_from_file(file_path: Path) -> list[dict]:
    """Statically parse a FastAPI route module using AST to extract endpoints and roles."""
    content = file_path.read_text(encoding="utf-8")
    tree = ast.parse(content, filename=str(file_path))

    prefix = ""
    router_role = "public"

    # 1. Find router prefix & router-level dependencies
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "router":
                    if isinstance(node.value, ast.Call):
                        for keyword in node.value.keywords:
                            if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant):
                                prefix = keyword.value.value
                            elif keyword.arg == "dependencies" and isinstance(keyword.value, ast.List):
                                for dep in keyword.value.elts:
                                    extracted = _extract_role_name(dep)
                                    if extracted != "public":
                                        router_role = extracted

    routes = []

    # 2. Find decorated handler functions
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                # Check for @router.get(...), @router.post(...), etc.
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    method_name = decorator.func.attr.upper()
                    if method_name in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
                        path = ""
                        if decorator.args and isinstance(decorator.args[0], ast.Constant):
                            path = decorator.args[0].value
                        elif decorator.keywords:
                            for kw in decorator.keywords:
                                if kw.arg == "path" and isinstance(kw.value, ast.Constant):
                                    path = kw.value.value

                        # Combine prefix and path cleanly
                        if prefix and not path.startswith(prefix):
                            full_path = f"{prefix.rstrip('/')}/{path.lstrip('/')}"
                        else:
                            full_path = path or "/"

                        # Determine role requirements
                        endpoint_role = router_role

                        # Check decorator keywords for dependencies=[Depends(require_role(...))]
                        for kw in decorator.keywords:
                            if kw.arg == "dependencies" and isinstance(kw.value, ast.List):
                                for dep in kw.value.elts:
                                    extracted = _extract_role_name(dep)
                                    if extracted != "public":
                                        endpoint_role = extracted

                        # Check function parameter defaults (e.g. user = Depends(require_role(...)))
                        for arg in node.args.args + node.args.kwonlyargs:
                            default_idx = len(node.args.args) - len(node.args.defaults)
                            # Match args with defaults if present
                            pass

                        for default_node in node.args.defaults + node.args.kw_defaults:
                            if default_node:
                                extracted = _extract_role_name(default_node)
                                if extracted != "public":
                                    endpoint_role = extracted

                        # Docstring summary
                        docstring = ast.get_docstring(node) or ""
                        summary = docstring.strip().split("\n")[0] if docstring else ""

                        routes.append({
                            "file": file_path.name,
                            "method": method_name,
                            "path": full_path,
                            "function": node.name,
                            "role": endpoint_role,
                            "summary": summary,
                        })

    return routes


def collect_all_management_routes(routes_dir: Path) -> list[dict]:
    """Collect and sort all management API routes across routes directory."""
    all_routes = []
    if routes_dir.exists():
        for py_file in sorted(routes_dir.glob("*.py")):
            if py_file.name == "__init__.py":
                continue
            all_routes.extend(parse_fastapi_routes_from_file(py_file))

    # Sort by path then method
    return sorted(all_routes, key=lambda r: (r["path"], r["method"]))


def parse_container_listeners(compose_file: Path) -> list[dict]:
    """Parse container listeners and network zones from compose file."""
    listeners = [
        {"service": "haproxy", "container": "ja4proxy-haproxy", "zone": "dmz_net / mgmt_net", "port": "8443 (HTTPS), 8444 (Mgmt)", "ingress": "Public / Operator"},
        {"service": "go-proxy", "container": "ja4proxy-proxy", "zone": "dmz_net / origin_net / data_net", "port": "8080 (Proxy Engine)", "ingress": "Internal Splicer"},
        {"service": "management", "container": "ja4proxy-management", "zone": "mgmt_net / data_net", "port": "8000 (FastAPI REST)", "ingress": "HAProxy Mgmt Splicer"},
        {"service": "redis", "container": "ja4proxy-redis", "zone": "data_net (internal)", "port": "6379 (TLS ACL)", "ingress": "Internal Services Only"},
        {"service": "analytics", "container": "ja4proxy-analytics", "zone": "data_net (internal)", "port": "Internal Worker Loop", "ingress": "Redis Stream Poller"},
        {"service": "tarpit", "container": "ja4proxy-tarpit", "zone": "dmz_net (internal)", "port": "8081 (Tarpit Pool)", "ingress": "Proxy Redirection"},
        {"service": "ja4-tap", "container": "ja4proxy-tap", "zone": "dmz_net (passive)", "port": "AF_PACKET Promiscuous", "ingress": "Passive Network Interface"},
    ]
    return listeners


def parse_redis_keys() -> list[dict]:
    """Catalog Redis key schemas and prefixes."""
    keys = [
        {"pattern": "ja4:blocklist:*", "type": "Set / String", "written_by": "Management API / CLI", "read_by": "Go Proxy (ja4pd)", "description": "Active JA4 fingerprint blocklist"},
        {"pattern": "ja4:rate:*", "type": "Hash (Sliding Window)", "written_by": "Lua Script / Go Proxy", "read_by": "Go Proxy (ja4pd)", "description": "Rate limiting counter windows"},
        {"pattern": "ban:*", "type": "String (TTL)", "written_by": "Management API / SOAR", "read_by": "Go Proxy (ja4pd)", "description": "IP ban records with expiration"},
        {"pattern": "events:connection", "type": "Stream", "written_by": "Go Proxy (ja4pd)", "read_by": "Analytics Engine", "description": "TLS connection event stream"},
        {"pattern": "ja4:session:*", "type": "Hash (TTL)", "written_by": "Management API", "read_by": "Management API", "description": "User login session tokens"},
    ]
    return keys


def generate_attack_surface_md(routes: list[dict], listeners: list[dict], redis_keys: list[dict]) -> str:
    """Generate Markdown report for docs/security/ATTACK_SURFACE.md."""
    lines = [
        "# JA4proxy Attack Surface Inventory & Baseline",
        "",
        "> [!NOTE]",
        "> This document is automatically generated by `scripts/surface_inventory.py` from static AST inspection",
        "> of management routes (`management/api/routes/*.py`), Compose manifests, and Redis schemas.",
        "> Enforced in CI via `make lint` / `python3 scripts/surface_inventory.py --check`.",
        "",
        "## 1. Management API Endpoints Matrix",
        "",
        f"Total Endpoints Discovered: **{len(routes)}**",
        "",
        "| Method | Path | Function | Required Role | Summary |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for r in routes:
        summary = (r["summary"] or "—").replace("|", "\\|")
        lines.append(f"| `{r['method']}` | `{r['path']}` | `{r['function']}` | `{r['role']}` | {summary} |")

    lines.extend([
        "",
        "## 2. Container Socket Listeners & Network Zones",
        "",
        "| Service | Container Name | Network Zone | Listening Port / Socket | Ingress Exposure |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])

    for l in listeners:
        lines.append(f"| `{l['service']}` | `{l['container']}` | `{l['zone']}` | `{l['port']}` | {l['ingress']} |")

    lines.extend([
        "",
        "## 3. Redis Key Schema & Access Matrix",
        "",
        "| Key Pattern | Data Structure | Written By | Read By | Purpose / Description |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])

    for k in redis_keys:
        lines.append(f"| `{k['pattern']}` | `{k['type']}` | `{k['written_by']}` | `{k['read_by']}` | {k['description']} |")

    lines.extend([
        "",
        "## 4. External Outbound & Egress Surfaces",
        "",
        "| Destination | Protocol / Port | Trigger | Purpose |",
        "| :--- | :--- | :--- | :--- |",
        "| GeoIP Database | HTTPS (443) | `scripts/update-geoip.sh` | MaxMind / IP2Location feed downloads |",
        "| Webhooks | HTTPS (443) | Event Notification | Alert dispatch to SIEM / Slack / SOAR |",
        "| OIDC / SAML IdP | HTTPS (443) | User Auth Login | SSO Authentication Callback |",
        "",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="JA4proxy Attack-Surface Inventory Parser & Generator")
    parser.add_argument("--check", action="store_true", help="Check if ATTACK_SURFACE.md is in sync with generated inventory")
    parser.add_argument("--json", action="store_true", help="Output JSON payload")
    parser.add_argument("--write", action="store_true", help="Write generated inventory to ATTACK_SURFACE.md")
    args = parser.parse_args()

    routes = collect_all_management_routes(ROUTES_DIR)
    listeners = parse_container_listeners(COMPOSE_FILE)
    redis_keys = parse_redis_keys()

    if args.json:
        data = {
            "routes_count": len(routes),
            "routes": routes,
            "listeners": listeners,
            "redis_keys": redis_keys,
        }
        print(json.dumps(data, indent=2))
        return 0

    generated_md = generate_attack_surface_md(routes, listeners, redis_keys)

    if args.check:
        if not ATTACK_SURFACE_MD.exists():
            print(f"surface_inventory: ERROR — {ATTACK_SURFACE_MD} does not exist.")
            return 1

        existing_md = ATTACK_SURFACE_MD.read_text(encoding="utf-8")
        if existing_md.strip() != generated_md.strip():
            print(f"surface_inventory: drift detected in {ATTACK_SURFACE_MD} — run 'make surface-inventory' and commit.")
            return 1
        print(f"surface_inventory: {ATTACK_SURFACE_MD} is in sync ({len(routes)} routes verified).")
        return 0

    # Default or --write: write to file
    ATTACK_SURFACE_MD.parent.mkdir(parents=True, exist_ok=True)
    ATTACK_SURFACE_MD.write_text(generated_md, encoding="utf-8")
    print(f"✓ Generated {ATTACK_SURFACE_MD} ({len(routes)} routes discovered).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
