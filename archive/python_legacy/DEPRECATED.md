# Python Legacy Proxy (DEPRECATED)

===============================================================================
⚠  ARCHIVED — UNMAINTAINED — NOT FOR PRODUCTION USE  ⚠
===============================================================================

## Status
This codebase represents the original Python prototype of the JA4proxy. It was
formally deprecated and moved to this archive in **Phase 128 (June 2026)**.

## Why was it archived?
1. **Production Promotion**: The Go implementation (`cmd/proxy/`, `internal/`)
   is the only supported production runtime. It offers 30x higher throughput
   and significantly lower resource utilization.
2. **Reduced Maintenance**: Archiving this code stops redundant security scans,
   linting, and vulnerability monitoring for code that is no longer shipped.

## What is NOT here?
*   **Analytics (`src/analytics/`)**: Remains active in the root `src/` folder
    to process telemetry streams from the Go proxy.
*   **Management API (`management/`)**: Remains active as the primary control
    plane.

## Historical Reference
This code is retained for historical reference and as a prototyping playground.
If you need to experiment with a new signal in Python, do it here, then
**port the implementation to Go** before deployment.

---
**Gemini CLI**
