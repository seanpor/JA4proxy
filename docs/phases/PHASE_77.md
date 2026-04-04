# Phase 77: Enterprise Security Stack & SIEM Integration

## 1. Overview
JA4Proxy2 is designed to be a high-signal "sensor" in an enterprise security ecosystem. This phase provides the standard integration patterns for both Open Source (Wazuh, CrowdSec) and Commercial (Splunk, QRadar, Sentinel, Chronicle) security platforms.

**The "Clean Option" Principle:** Deployers can choose their stack by enabling specific "Integrator Sidecars" or configuring the "Universal Log Forwarder."

---

## 2. Open Source Stack Options (Active Defense)

### 2.1 Wazuh (HIDS/SIEM)
- **Role:** Host security, FIM, and automated response.
- **Integration:** Wazuh agent on RHEL reads the JSON `journald` logs.
- **Deployment:** 
  - Install `wazuh-agent` on the proxy host.
  - Apply the custom **JA4 Decoder** and **Rule 100201** (High Threat JA4 Fingerprint).
  - **Active Response:** Wazuh triggers a script to add the IP to the JA4Proxy2 Redis blacklist.

### 2.2 CrowdSec (Collaborative Firewall)
- **Role:** Behavior-based blocking and community threat intelligence.
- **Integration:** CrowdSec `acquis.yaml` points to the proxy logs.
- **Deployment:** 
  - Install `crowdsec` and the `ja4proxy-scenario`.
  - Use the `cs-firewall-bouncer` to block IPs at the `nftables` level.

---

## 3. Commercial SIEM/SOAR Options (Observability)

Most enterprise SIEMs prefer logs in **HEC (HTTP Event Collector)** or **Syslog (TLS)** format.

### 3.1 Splunk (The Gold Standard)
- **Method:** Splunk Universal Forwarder (UF) or Vector.
- **Format:** Native JSON with `sourcetype=ja4proxy:telemetry`.
- **Value:** Deep forensic search and correlation with VPC Flow Logs.

### 3.2 IBM QRadar
- **Method:** Syslog (RFC5424) over TLS.
- **Format:** LEEF (Log Event Extended Format) or JSON.
- **Value:** Integration into QRadar's "Offense" workflow based on JA4 reputation.

### 3.3 Microsoft Sentinel / Google Chronicle
- **Method:** Azure Log Analytics Agent (AMA) or Chronicle Forwarder.
- **Format:** CEF (Common Event Format).
- **Value:** Cloud-native correlation with Entra ID (Azure AD) or Google Workspace logs.

---

## 4. The Universal Integration Pattern (For "Unknown" Options)

If an enterprise uses a tool not listed above (e.g., Devo, Sumo Logic, or a custom in-house SOC tool), use the **Vector Sidecar Pattern**.

**Vector** (vector.dev) acts as the "Universal Translator" for JA4Proxy2:
1. **Source:** Reads from `journald` or `stdout` (JSON).
2. **Transform:** Re-maps fields (e.g., rename `client_ip` to `src_ip` for QRadar).
3. **Sink:** Ships to *any* destination (S3, Kafka, HEC, Syslog, Webhooks).

**Configuration Strategy:**
- Use the provided `config/integrations/vector.yaml` as a template.
- Simply change the `sinks` section to match the enterprise's "Unknown" tool requirements.

---

## 5. Deployment Selection Matrix

| Tool Category | Recommended Tool | Integration Level | Primary Benefit |
| :--- | :--- | :--- | :--- |
| **Active Defense** | Wazuh / CrowdSec | High (Bi-directional) | Automated Blocking |
| **Compliance** | Splunk / QRadar | Medium (Forwarding) | Audit Trails & Forensics |
| **Cloud Native** | Sentinel / Chronicle | Medium (Forwarding) | Zero-infra Monitoring |
| **Custom/Other** | Vector | Low (Translation) | Flexibility |

---

## 6. Verification of Integration

Regardless of the tool chosen, the verification process is standardized:

1. **Synthetic Attack:** Generate a request with a known "malicious" JA4 fingerprint (e.g., `t13d1516h2_...` associated with Cobalt Strike).
2. **Log Transit:** Verify the log entry exists in the Proxy's local `journalctl`.
3. **Ingestion Check:** Log into the SIEM (Splunk/Wazuh) and search for the specific Trace ID.
4. **Action Check (If Active):** Confirm the source IP was automatically added to the Redis blacklist:
   ```bash
   redis-cli SISMEMBER blacklist:ips <attacker_ip>
   ```
