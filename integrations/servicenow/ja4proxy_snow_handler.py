"""ServiceNow Security Incident Response (SIR) handler for JA4proxy.

Receives JA4proxy ECS event dicts (from webhook or XSOAR/Splunk SOAR trigger)
and creates ServiceNow SIR incidents via the REST Table API.

Environment variables required at runtime:
    SNOW_INSTANCE  — ServiceNow instance hostname, e.g. "company.service-now.com"
    SNOW_USER      — ServiceNow username with write access to sn_si_incident
    SNOW_PASS      — ServiceNow password

Usage::

    from integrations.servicenow.ja4proxy_snow_handler import create_sir_incident
    sys_id = create_sir_incident(ecs_event)
"""

from __future__ import annotations

import json
import os

import requests

# Credentials are read from os.environ at call time inside create_sir_incident()
# so that tests can patch os.environ without reloading the module.


def ecs_to_sir(event: dict) -> dict:
    """Build a ServiceNow SIR payload from a JA4proxy ECS event dict.

    Severity thresholds:
        risk_score >= 85 → severity "1" (Critical)
        risk_score <  85 → severity "2" (High)

    Args:
        event: JA4proxy ECS event dict with fields such as
               ``source.ip``, ``event.risk_score``, ``ja4proxy.signals``, etc.

    Returns:
        A dict ready to be POST-ed to the ServiceNow SIR table API.
    """
    risk_score = event.get("event.risk_score", 0)
    signals = event.get("ja4proxy.signals", [])

    # Build signal description
    if signals:
        signal_txt = "; ".join(
            f"{s['name']}(+{s['score']}): {s['reason']}" for s in signals
        )
    else:
        signal_txt = "No signals recorded."

    # SIR severity: 1=Critical, 2=High, 3=Moderate, 4=Low, 5=Planning
    severity = "1" if risk_score >= 85 else "2"

    source_ip = event.get("source.ip", "unknown")

    return {
        "short_description": (
            f"JA4proxy ban: {source_ip} (score={risk_score})"
        ),
        "description": signal_txt,
        "category": "network_intrusion",
        "severity": severity,
        "u_source_ip": event.get("source.ip", ""),
        "u_ja4_fingerprint": event.get("ja4proxy.fingerprint.ja4", ""),
        "u_ja4proxy_ban_id": event.get("ja4proxy.ban_id", ""),
    }


def create_sir_incident(event: dict) -> str:
    """POST to the ServiceNow SIR table. Returns the created incident sys_id.

    Args:
        event: JA4proxy ECS event dict.

    Returns:
        The ``sys_id`` string of the created ServiceNow incident.

    Raises:
        requests.HTTPError: if the ServiceNow API returns a non-2xx status.
    """
    snow_instance = os.environ.get("SNOW_INSTANCE", "")
    snow_user = os.environ.get("SNOW_USER", "")
    snow_pass = os.environ.get("SNOW_PASS", "")
    sir_url = f"https://{snow_instance}/api/now/table/sn_si_incident"

    payload = ecs_to_sir(event)
    resp = requests.post(
        sir_url,
        auth=(snow_user, snow_pass),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        data=json.dumps(payload),
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["result"]["sys_id"]
