"""
Phase 825 — Promtail is gone and Alloy is wired correctly.

Removing an image without a guard leaves nothing to stop it returning, and the
log pipeline has an unusually quiet failure mode: an empty Loki looks exactly
like a quiet system. Phase 825 found prod's promtail had been pointing at a
`docker-socket-proxy` service that does not exist in the prod stack, so prod had
been shipping no logs at all, undetected.

Behavioural proof of delivery lives in
tests/integration/infra-monitoring/check_alloy_log_delivery.sh (needs a running
stack). These are the static guards.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "deploy" / "docker"
ALLOY_DIR = REPO / "deploy" / "monitoring" / "alloy"

COMPOSE_FILES = sorted(COMPOSE.glob("docker-compose*.yml"))


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_promtail_does_not_return(path: Path):
    """grafana/promtail is EOL (29 HIGH/CRITICAL); Alloy replaced it."""
    pattern = re.compile(r"^\s*image:\s*['\"]?grafana/promtail", re.M)
    assert not pattern.search(path.read_text(encoding="utf-8")), (
        f"{path.name} reintroduces grafana/promtail — EOL upstream and replaced "
        "by grafana/alloy in phase-825"
    )


def test_alloy_present_in_both_stacks():
    for name in ("docker-compose.monitoring.yml", "docker-compose.prod.yml"):
        services = yaml.safe_load((COMPOSE / name).read_text())["services"]
        assert "alloy" in services, f"{name} has no alloy service"
        assert "promtail" not in services, f"{name} still defines promtail"


def test_prod_uses_the_file_discovery_config():
    """Prod has no docker-socket-proxy, so it must NOT use the docker-SD config.

    This is the bug phase-825 found: prod mounted the shared promtail config
    whose discovery targeted `docker-socket-proxy:2375`, a service absent from
    the prod stack, so discovery silently returned nothing.
    """
    prod = yaml.safe_load((COMPOSE / "docker-compose.prod.yml").read_text())
    services = prod["services"]
    assert "docker-socket-proxy" not in services, (
        "prod gained a docker-socket-proxy — if intentional, this test and the "
        "split configs can be simplified"
    )
    mounts = " ".join(services["alloy"]["volumes"])
    assert "config.prod.alloy" in mounts, (
        "prod's alloy must mount config.prod.alloy (file discovery), not the "
        "docker-SD config — otherwise it discovers nothing, exactly as promtail did"
    )


def test_monitoring_uses_the_docker_sd_config():
    mon = yaml.safe_load((COMPOSE / "docker-compose.monitoring.yml").read_text())
    mounts = " ".join(mon["services"]["alloy"]["volumes"])
    assert "config.alloy" in mounts and "config.prod.alloy" not in mounts


@pytest.mark.parametrize("cfg", ["config.alloy", "config.prod.alloy"])
def test_label_contract_preserved(cfg: str):
    """Dashboards and saved queries key on these labels."""
    text = (ALLOY_DIR / cfg).read_text(encoding="utf-8")
    for label in ("level", "action"):
        assert label in text, f"{cfg} lost the '{label}' label from the promtail pipeline"
    assert 'service=\\"proxy\\"' in text or 'service=\"proxy\"' in text, (
        f"{cfg} lost the proxy-only match that gates security-event tagging"
    )


def test_alloy_is_scraped_by_prometheus():
    """Promtail was never scraped, so a broken pipeline had no metric to alert on."""
    prom = (REPO / "deploy/monitoring/prometheus/prometheus.yml").read_text()
    assert "job_name: 'alloy'" in prom or 'job_name: "alloy"' in prom, (
        "prometheus does not scrape alloy — without it there is no signal that "
        "log delivery has stopped"
    )


def _strip_comments(text: str) -> str:
    """Drop `#` and `//` comment lines.

    The migration deliberately documents what promtail did and why it was
    replaced, so a naive substring scan flags the explanation as a defect.
    Earlier revisions of this test did exactly that, twice.
    """
    return "\n".join(
        l for l in text.splitlines() if not l.lstrip().startswith(("#", "//"))
    )


def test_no_functional_promtail_references():
    """A dashboard panel or config pointing at a dead container renders nothing.

    Matches FUNCTIONAL references only — an image directive, a mount of the
    retired config, a scrape target, or a selector naming the container.
    """
    functional = re.compile(
        r"image:\s*['\"]?grafana/promtail"
        r"|promtail-config\.yml"
        r"|['\"]promtail:[0-9]"
        r"|name=\\?['\"]promtail"
    )
    stale = []
    for d in (REPO / "deploy" / "monitoring", COMPOSE):
        for f in d.rglob("*"):
            if f.is_file() and f.suffix in {".json", ".yml", ".yaml", ".alloy"}:
                body = _strip_comments(f.read_text(encoding="utf-8", errors="ignore"))
                if functional.search(body):
                    stale.append(str(f.relative_to(REPO)))
    assert not stale, f"functional promtail references remain: {stale}"
