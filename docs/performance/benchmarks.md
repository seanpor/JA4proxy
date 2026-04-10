# JA4proxy Performance Benchmarks

> **Run the benchmark harness:** `make bench` (full suite) or `make bench-quick` (10s scenarios).
> **Load test harness:** `make load-test-baseline`.
> Update this file after each benchmark run with actual measured numbers.

## Reference Hardware

| Component | Specification |
|-----------|--------------|
| CPU | _(record actual CPU model)_ |
| Cores | _(nproc)_ |
| RAM | _(total GB)_ |
| OS | _(uname -srm)_ |
| Redis | _(single node / cluster, version)_ |
| Go | _(go version)_ |
| Python | _(python3 --version)_ |

## Go Proxy Benchmarks

> Run date: _(date of run)_
> Git SHA: _(commit hash)_

### BYPASS PATH (h2/h1 ALPN → immediate allow)

| Metric | Value |
|--------|-------|
| Throughput | _(measure)_ conn/s |
| P50 latency | _(measure)_ ms |
| P99 latency | _(measure)_ ms |
| CPU (single core) | _(measure)_ % at peak |

### FULL SIGNAL PATH (all signal modules, Redis reads)

| Metric | Value |
|--------|-------|
| Throughput | _(measure)_ conn/s |
| P50 latency | _(measure)_ ms |
| P99 latency | _(measure)_ ms |
| CPU (single core) | _(measure)_ % at peak |

### TARPIT PATH

| Metric | Value |
|--------|-------|
| Max concurrent tarpitted | _(measure)_ |
| Memory per tarpitted conn | _(measure)_ KB |

### REDIS LATENCY SENSITIVITY

| Redis P99 Latency | Throughput |
|-------------------|------------|
| 1ms | _(measure)_ conn/s |
| 5ms | _(measure)_ conn/s |
| 20ms | _(measure)_ conn/s |

### MEMORY FOOTPRINT

| State | Memory |
|-------|--------|
| Proxy process (idle) | _(measure)_ MB |
| Proxy process (10K conns) | _(measure)_ MB |
| LRU cache (100K entries) | _(measure)_ MB |

## Historical Runs

| Date | Git SHA | Scenario | Throughput (conn/s) | P99 (ms) | Notes |
|------|---------|----------|---------------------|----------|-------|
| _(first run)_ | | | | | |
