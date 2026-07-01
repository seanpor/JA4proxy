"""Container entrypoint security regression test.

Closes gap JA4PROXY-2026-0078:
  0078 — Dockerfile entrypoints must not leak commands or credentials into logs/args
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_DIR = REPO_ROOT / "deploy" / "docker"

_DANGEROUS_PATTERNS = [
    r"echo\s+\$[A-Z_]*PASSWORD",
    r"echo\s+\$[A-Z_]*SECRET",
    r"echo\s+\$[A-Z_]*TOKEN",
    r"set\s+-x",      # set -x causes every command + args to be echoed, leaking secrets
    r"env\s*\|",       # piping env output (leaks all env vars including secrets)
    r"printenv",       # prints all env vars
]
_COMPILED = [re.compile(p, re.IGNORECASE) for p in _DANGEROUS_PATTERNS]


def test_entrypoint_no_command_leak():
    """Dockerfile entrypoints must not echo secrets or use set -x.

    Patterns like 'echo $REDIS_PASSWORD', 'set -x', or 'printenv' cause
    credentials to appear in container logs, which are often shipped to
    log aggregators and stored unencrypted.
    """
    if not DOCKERFILE_DIR.exists():
        return  # skip if dockerfiles absent (non-blocking)

    dockerfiles = list(DOCKERFILE_DIR.glob("Dockerfile*"))
    assert dockerfiles, f"No Dockerfiles found under {DOCKERFILE_DIR}"

    offenders: list[str] = []
    for df in dockerfiles:
        content = df.read_text()
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern in _COMPILED:
                if pattern.search(stripped):
                    offenders.append(f"{df.name}:{i}: {stripped!r}")

    assert not offenders, (
        "Dockerfile(s) contain patterns that may leak credentials into logs:\n"
        + "\n".join(f"  {o}" for o in offenders)
        + "\n\nFix: remove 'set -x', 'printenv', and 'echo $SECRET_VAR' calls "
        "from entrypoint scripts and Dockerfiles."
    )
