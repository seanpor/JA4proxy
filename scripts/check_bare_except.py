#!/usr/bin/env python3
"""Fail if any file contains a bare except: or a bare except Exception: pass.

These patterns silently swallow unexpected exceptions and make debugging
in production nearly impossible.  See docs/phases/PHASE_17b.md §17b-1.

Exit codes:
  0 — no violations found
  1 — one or more violations found
"""
import ast
import sys
from pathlib import Path


def check_file(path: Path) -> list[tuple[int, str]]:
    """Return (lineno, message) for every violation in *path*."""
    violations: list[tuple[int, str]] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return violations  # broken files are caught by the linter

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue

        # bare except: — catches BaseException including KeyboardInterrupt
        if node.type is None:
            violations.append((node.lineno, "bare except:"))
            continue

        # except Exception: pass — silently discards all exceptions
        if (
            isinstance(node.type, ast.Name)
            and node.type.id == "Exception"
            and len(node.body) == 1
            and isinstance(node.body[0], ast.Pass)
        ):
            violations.append((node.lineno, "except Exception: pass"))

    return violations


def main(roots: list[str]) -> int:
    errors: list[str] = []
    for root in roots:
        for path in sorted(Path(root).rglob("*.py")):
            for lineno, msg in check_file(path):
                errors.append(f"{path}:{lineno}: {msg}")

    if errors:
        print("check_bare_except: violations found", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        return 1

    print(f"check_bare_except: OK (checked {len(roots)} root(s))")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dir> [<dir> ...]", file=sys.stderr)
        sys.exit(1)
    sys.exit(main(sys.argv[1:]))
