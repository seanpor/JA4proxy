# Network-Focused Evaluation Template

## Environment Configuration
- **Network Topology**: [Your network diagram here]
- **Interface Configuration**: [IP address, MTU, VLANs]
- **Throughput Requirements**: [Target Mbps/connections per second]

## Test Scenarios

### 1. High-Volume Traffic Test
- **Objective**: Validate throughput under load
- **Parameters**: 
  - 10,000 concurrent connections
  - 1-10 Gbps traffic rate
  - Multiple parallel proxy instances
- **Metrics to Record**:
  - Latency (p50, p95, p99)
  - CPU utilization
  - Memory usage
  - Packet drop rate

### 2. Network Resilience Test
- **Objective**: Validate failover and recovery
- **Parameters**:
  - Interface failure simulation
  - Network partition testing
  - Recovery time measurement
- **Metrics to Record**:
  - Recovery time
  - Connection preservation
  - State synchronization

### 3. Latency Sensitivity Test
- **Objective**: Validate low-latency operation
- **Parameters**:
  - 100-1000 concurrent connections
  - Interactive web application traffic
- **Metrics to Record**:
  - End-to-end latency
  - 95th percentile latency
  - Jitter

## Expected Results
- < 10ms latency for 95% of connections (at target load)
- < 80% CPU utilization at 80% capacity
- < 500ms recovery time for interface failure
- Zero packet drops under normal load

## Evaluation Checklist
- [ ] Baseline throughput measured
- [ ] Latency benchmarks recorded
- [ ] CPU/memory baselines established
- [ ] Recovery time within SLA