# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-04

### Added
- **High-Performance Go Core**: Complete rewrite of the proxy logic in Go, achieving sub-microsecond latency.
- **Advanced CLI (ja4p)**: New operational subcommands:
    - `ja4p config validate`: Validates proxy configuration and security feeds.
    - `ja4p test ip`: Simulates pipeline decisions for specific IP addresses.
- **Zero-Copy Parsing**: Optimized TLS ClientHello and SNI extraction using zero-copy memory patterns.
- **Mesh Drift Detection**: Asynchronous decision auditing across proxy instances via Redis.
- **MITRE ATT&CK Mapping**: Formal mapping of JA4proxy signals to adversary techniques in `docs/OPERATIONS_MAPPING.md`.
- **OpenSSF Scorecard**: Integrated automated security auditing (Achieved 10/10 score).
- **SLSA Level 3**: Build provenance and supply chain hardening.
- **Prometheus Instrumentation**: Per-signal latency histograms for deep observability.
- **Maturity Badges**: Codecov, Go Reference, and Release status badges.

### Changed
- **Production Standard**: Go implementation is now the primary production runtime.
- **Repository Pruning**: Removed 150,000+ lines of legacy Python code and obsolete documentation.
- **Documentation Consolidation**: Centralized operational procedures into `docs/OPERATIONS_GUIDE.md`.
- **Helm Chart v2**: Relocated and upgraded Helm charts for Kubernetes-native scaling.

### Removed
- **Legacy Python Proxy**: Python proxy prototype archived to `legacy-v1` branch.
- **Obsolete Docs**: Hundreds of historical research and dev-heavy documents pruned for clarity.

## [1.x.x] - Historical
- Legacy Python prototype implementation (see `legacy-v1` branch for details).
