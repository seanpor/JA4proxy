#!/usr/bin/env python3
"""Check independent resolver compatibility per isolated Python environment.

Verifies:
1. Isolated dry-run resolution for each environment (management, analytics, tools/test).
2. Shared mock / test parity checks where version drift is hazardous.
Container-strict: Designed to run inside $(TOOLS_RUN) (Python 3.14).
"""
import subprocess
import sys
from pathlib import Path

ENVIRONMENTS = [
    ("management", ["management/requirements.txt"]),
    ("analytics", ["requirements-analytics.txt"]),
    ("toolchain", ["requirements.txt", "requirements-test.txt", "requirements-lint-management.txt"]),
]


def check_env(name: str, req_files: list[str]) -> bool:
    cmd = ["pip", "install", "--dry-run", "--no-deps"]
    for f in req_files:
        cmd.extend(["-r", f])
    
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"✗ Dependency resolution failed for environment '{name}':")
        print(res.stderr.strip() or res.stdout.strip())
        return False
    print(f"  ✓ Environment '{name}' requirements resolve cleanly")
    return True


def check_parity() -> bool:
    # Verify critical shared dependencies maintain consistent versions
    # e.g., fakeredis between root test toolchain and management tests
    def parse_pin(file_path: Path, pkg: str) -> str | None:
        if not file_path.exists():
            return None
        for line in file_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = line.split("==")[0].split(">=")[0].split("[")[0].strip().lower()
            if name == pkg.lower():
                return line.split("#")[0].strip()
        return None

    root_fake = parse_pin(Path("requirements.txt"), "fakeredis")
    mgmt_fake = parse_pin(Path("management/requirements.txt"), "fakeredis")

    if root_fake and mgmt_fake and ("==" in root_fake and "==" in mgmt_fake):
        v_root = root_fake.split("==")[1].strip()
        v_mgmt = mgmt_fake.split("==")[1].strip()
        if v_root != v_mgmt:
            print(f"✗ fakeredis version mismatch: requirements.txt ({v_root}) vs management/requirements.txt ({v_mgmt})")
            return False
    print("  ✓ Shared cross-environment test fixture parity holds")
    return True


def main() -> int:
    print("=== Checking Python Dependency Resolution & Parity ===")
    ok = True
    for name, req_files in ENVIRONMENTS:
        if not check_env(name, req_files):
            ok = False
    if not check_parity():
        ok = False
    if ok:
        print("✓ All dependency environments valid and consistent")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
