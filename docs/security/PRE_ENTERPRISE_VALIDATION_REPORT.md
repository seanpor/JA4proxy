# JA4proxy — Pre-Enterprise Validation Report

_Generated: 2026-04-09 11:48:18 UTC_

This report summarises the Go production proxy's defensive test
surface as enumerated by Phase 62. The Python proxy is experimental
and intentionally excluded.

## Go test surface

- Unit tests:        **274**
- Fuzz targets:      **3**
- Benchmarks:        **8**
- Property tests:    **4**
- Chaos tests:       **3**

## Go security findings (Phase 200-203 commits)

```
79704d4 Merge branch 'feat/phase-200-critical-remediation'
```

## govulncheck

Status: **FAIL (exit 1)**

```
govulncheck: loading packages: err: exit status 1: stderr: package unsafe is not in std (/usr/share/go/src/unsafe)
```

## pip-audit (production Python services)

Status: **FAIL (exit 1)**

```
ERROR:pip_audit._cli:bcc: Dependency not found on PyPI and could not be audited: bcc (0.18.0)
```

## Fuzz smoke (1s per target — new-crash check only)

- `FuzzClientHello`: **PASS**
- `FuzzReadProxyProtocol`: **PASS**
- `FuzzReadProxyProtocolV2`: **PASS**

