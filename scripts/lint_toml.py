"""TOML syntax + parse validation.

Validates all TOML files in the repository. tomllib (built-in since 3.11) or
the tomli backport validates structure and types, not just character encoding.
"""

import sys

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        print("  ERROR: neither tomllib nor tomli is available", file=sys.stderr)
        sys.exit(1)

files = ["pyproject.toml", ".gitleaks.toml"]
ok = True
for f in files:
    try:
        with open(f, "rb") as fh:
            tomllib.load(fh)
        print(f"  {f:<50} OK")
    except Exception as e:  # noqa: BLE001
        print(f"  {f:<50} FAIL: {e}")
        ok = False

sys.exit(0 if ok else 1)
