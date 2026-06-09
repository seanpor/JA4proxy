<!--
title: System Evaluation Guide
status: active
audience: architects
last_reviewed: 2026-06-09
phase: 226
-->

# JA4proxy System Evaluation Guide

## Overview
This guide provides enterprise architects with a systematic approach to evaluating JA4proxy in your environment.

## Prerequisites
- Hardware specifications (CPU, RAM, Network)
- Network topology diagram
- Security policy requirements
- Performance baselines

## Evaluation Phases

### Phase 1: Environment Setup
1. Install JA4proxy on your hardware
2. Configure network interfaces
3. Set up monitoring infrastructure

### Phase 2: Performance Benchmarking
1. Use ja4p load generator (via scripts/benchmark.py)
2. Run baseline tests (1, 2, 4 parallel proxies)
3. Establish performance baselines

### Phase 3: Security Validation
1. Test against known threat patterns
2. Verify blocking effectiveness (monitor vs dial vs block modes)
3. Audit log verification

### Phase 4: Integration Testing
1. SIEM integration (Splunk, Sentinel, QRadar)
2. Alert configuration
3. Performance impact analysis

### Phase 5: Documentation
1. Record findings
2. Create deployment plan
3. Document lessons learned

## Success Metrics
- Performance: >90% of target CPS achieved
- Security: Blocking accuracy verified against test corpus
- Integration: All SIEM connections successful
- Latency: <10ms for 95th percentile

## Quick Start Commands
```bash
# Build benchmark tool
make build

# Run benchmark against local proxy
make bench-macro ARGS="--good-rate 100 --bad-rates 500,1000"

# Run full benchmark matrix
make bench
```