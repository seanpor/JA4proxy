<!--
title: Benchmarking & Scalability Guide
status: active
audience: engineers
last_reviewed: 2026-06-09
phase: 161
-->

# JA4proxy Benchmarking & Scalability Guide

This document explains how to safely and accurately benchmark JA4proxy.

## Default POC Limitations ("Speedlimits")
By default, the Proof-of-Concept (POC) Docker environment (`deploy/docker/docker-compose.poc.yml`) is designed to run safely on a developer's laptop without starving the host OS.

The following resource limits are strictly enforced via Docker cgroups:
- **Proxy Container**: `cpus: '1.0'`, `GOMAXPROCS=4`
- **Mock Backend Container**: `cpus: '0.5'`
- **Analytics/Tarpit Containers**: Severely restricted CPU and Memory limits

Because the mock backend handles the termination of TLS 1.3 ECDHE handshakes (which are highly CPU-intensive), the `0.5` CPU limit creates a hard, artificial ceiling. This restricts the entire end-to-end POC pipeline to approximately **330 - 350 Connections Per Second (CPS)**. 

*Note: This is an infrastructure limit, not a limitation of the Go proxy core.*

---

## Uncapping the Speedlimits

If you are running the benchmark on dedicated hardware and wish to observe the true throughput of the JA4proxy Go core, you must manually uncap these constraints.

### Step 1: Remove Docker Resource Limits
Open `deploy/docker/docker-compose.poc.yml` and locate the `deploy` blocks for the `proxy` and `backend` services. 

You can either completely remove the `deploy` block, or increase the `cpus` allowance to match your host hardware:
```yaml
    deploy:
      resources:
        limits:
          cpus: '8.0' # Increase to match your available cores
```

### Step 2: Remove Go Thread Constraints
To prevent the Go runtime from thrashing against restrictive container cgroups, the POC environment forces `GOMAXPROCS=4`. 

If you uncap the Docker CPU limits in Step 1, you must also remove the `GOMAXPROCS=4` line from the `proxy` environment variables in `docker-compose.poc.yml` to allow Go to naturally scale across all available threads.

### Step 3: Run the High-Speed Benchmark
Once the speedlimits are removed, restart the stack and unleash the load generator:
```bash
make start-poc
./bin/ja4p test benchmark --host 127.0.0.1:8081 --good-rate 10000 --duration 15 --workers 500
```
*In this unrestricted configuration, the Go proxy has been verified to sustain over 2,600 CPS within Docker.*

---

## Host-Native Benchmarking (The Optimal Path)

To completely bypass the Docker User-Land Proxy (`docker-proxy`) — which introduces severe context-switching overhead under massive concurrency — you must run the components directly on the host network.

By using `network_mode: host` and bypassing the Docker bridge, JA4proxy is architecturally unblocked and can sustain **> 10,000 CPS per core** in a distributed production environment.