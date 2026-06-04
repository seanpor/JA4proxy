# JA4proxy — MITRE ATT&CK Signal Mapping

This document maps JA4proxy security signals to the **MITRE ATT&CK** framework to assist SecOps teams in incident triage and threat hunting.

## 1. Discovery (TA0007)

| Signal | Technique | Description |
| :--- | :--- | :--- |
| **SNI Mismatch** | [T1590](https://attack.mitre.org/techniques/T1590/) | Attacker probing for valid hostnames. |
| **Malformed ClientHello** | [T1595](https://attack.mitre.org/techniques/T1595/) | Automated scanning and reconnaissance tools. |
| **DGA Hostname** | [T1568](https://attack.mitre.org/techniques/T1568/) | Domain Generation Algorithms used for C2 discovery. |

## 2. Command and Control (TA0011)

| Signal | Technique | Description |
| :--- | :--- | :--- |
| **JA4 Fingerprint Match** | [T1573](https://attack.mitre.org/techniques/T1573/) | Known C2 agent (e.g., Cobalt Strike, Sliver) fingerprint match. |
| **Beaconing Pattern** | [T1071](https://attack.mitre.org/techniques/T1071/) | Regular interval connections characteristic of C2 heartbeat. |
| **Non-TLS over 443** | [T1571](https://attack.mitre.org/techniques/T1571/) | Protocol smuggling (e.g., SSH or HTTP over TLS ports). |

## 3. Resource Development (TA0042)

| Signal | Technique | Description |
| :--- | :--- | :--- |
| **Data Center IP** | [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | Connections originating from cloud/VPS infra rather than eyeballs. |
| **VPN/Tor Origin** | [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | Proxy-based evasion and identity concealment. |

## 4. Initial Access (TA0001)

| Signal | Technique | Description |
| :--- | :--- | :--- |
| **Blacklisted IP** | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploitation of public-facing applications by known-bad actors. |
| **AbuseIPDB Confidence** | [T1595](https://attack.mitre.org/techniques/T1595/) | IP addresses with high historical report counts for exploitation. |

---

## Remediation Playbooks

| Alert Type | Suggested Action | Playbook Link |
| :--- | :--- | :--- |
| **Critical JA4 Match** | Increase Dial to 100; Verify JA4 in TI feeds. | [High Block Rate](runbooks/ja4proxy_block_rate_high.md) |
| **Mesh Drift Alert** | Check configuration consistency; Inspect Redis health. | [Unexpected Dial Change](runbooks/ja4proxy_dial_change_unexpected.md) |
| **Tarpit Overflow** | Scale proxy instances; Inspect for Slowloris attack. | [Tarpit Pool Full](runbooks/ja4proxy_tarpit_pool_full.md) |
