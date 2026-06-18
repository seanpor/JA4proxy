# Network Architecture

## Zone Model

JA4proxy uses a three-zone network model to isolate external traffic from internal
management and data-plane services.

```mermaid
graph TB
    subgraph Internet["Internet"]
        U[("Operator Browser")]
        A[("Attacker")]
    end

    subgraph DMZ["DMZ Zone (dmz_net)"]
        HA[HAProxy<br/>port 443/80<br/>TLS termination<br/>mode tcp for proxy backend]
    end

    subgraph Internal["Internal / Data Zone (data_net)"]
        P[JA4 Proxy<br/>port 8080<br/>TCP passthrough<br/>JA4 fingerprinting]
        T[Tarpit<br/>slow response]
    end

    subgraph Mgmt["Management Zone (ja4proxy-mgmt / ja4proxy-monitoring)"]
        MA["Management API<br/>FastAPI + Jinja2<br/>port 8090<br/>HTTPS (self-signed)"]
        G["Grafana<br/>port 3000<br/>HTTPS (self-signed)<br/>GF_SECURITY_COOKIE_SECURE=true<br/>GF_SERVER_STRICT_TRANSPORT_SECURITY=true"]
        R[(Redis<br/>port 6379<br/>ACL + TLS)]
        ANA[Analytics<br/>port 9090]
        CAD[cAdvisor<br/>hostfs:ro<br/>SYS_PTRACE]
        P8[Prometheus<br/>port 9090]
        AL[Alertmanager<br/>port 9093]
    end

    U -->|HTTPS 443| HA
    A -->|HTTP/S| HA
    HA -->|TCP passthrough<br/>send-proxy-v2| P
    P -->|Tarpit trigger| T
    P -->|Events stream<br/>hset/xadd| R
    P -->|Metrics /prometheus| P8
    MA -->|Config + queries| R
    MA -->|HTTPS 8090| U
    G -->|PromQL| P8
    G -->|Dashboards 3000| U
    CAD -->|Container metrics| P8
    CAD -->|read-only hostfs| P
```

## TLS Termination Boundaries

| Service | TLS | Cert | Port | Zone |
|---------|-----|------|------|------|
| HAProxy | External TLS termination (terminates browser TLS, forwards via TCP) | Public or Let's Encrypt | 443 | DMZ |
| Management API | Self-signed HTTPS | Generated per-install | 8090 | Management |
| Grafana | Self-signed HTTPS | `deploy/docker/certs/grafana/` | 3000 | Management |
| Redis | Optional TLS (ACL-enforced) | Config-dependent | 6379 | Data / Management |

## Key Design Decisions

### HAProxy TCP Mode
HAProxy uses `mode tcp` (not `mode http`) when forwarding to the JA4 proxy backend.
This preserves the raw TLS ClientHello record so the proxy can compute JA4, JA4S,
and JA4X fingerprints. If HAProxy terminated TLS, the proxy would see only encrypted
bytes and all TLS fingerprinting would be blind.

Grafana and the Management API serve HTTPS directly with self-signed certificates —
they are on the management network and must not route through the DMZ HAProxy.

### cAdvisor Isolation
cAdvisor mounts `/:/rootfs:ro` and uses `SYS_PTRACE` + `DAC_READ_SEARCH` capabilities.
It is isolated on the internal monitoring bridge network with `no-new-privileges:true`
and all other capabilities dropped. See `docs/security/CONTAINER_THREAT_MODEL.md`.
