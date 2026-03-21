# Phase 20 Detailed Work Plan: Passive TAP/SPAN Mode

## 1. Overview
This is a major architectural phase that adds a passive capture mode. The proxy will read copies of packets via a SPAN port, reconstruct streams, extract fingerprints, and signal enforcement points via Redis, completely out-of-band of the actual traffic.

## 2. Implementation Sequence (TDD)

### Step 1: Packet Capture Engine (`AF_PACKET`)
*   **Goal:** Efficiently capture raw packets from the interface.
*   **Task:** Implement `src/tap/capture.py`.
*   **Action:** Use Python `socket` with `AF_PACKET` and `SOCK_RAW`. Implement ring buffer polling.
*   **TDD:** Write `tests/unit/tap/test_capture.py`. Mock the socket and verify BPF filters and packet yielding.

### Step 2: TCP Stream Reassembler
*   **Goal:** Reconstruct reliable byte streams from out-of-order packets.
*   **Task:** Implement `src/tap/reassembler.py`.
*   **Action:** Create a 4-tuple state machine tracking SEQ/ACK numbers, handling retransmissions and overlaps using `sortedcontainers.SortedList`.
*   **TDD:** Write `tests/unit/tap/test_reassembler.py` using synthetic packet arrays (in-order, out-of-order, duplicates, missing fragments).

### Step 3: Fingerprint Extractors
*   **Goal:** Implement deep packet inspection logic for new signals.
*   **Task:** Create `src/tap/fingerprints/`.
*   **Action:** Implement extractors for `JA4S` (ServerHello), `JA4H` (HTTP headers), `JA4X` (Certificates), and `JA4SSH` (KEXINIT).
*   **TDD:** Provide raw byte arrays from known PCAPs (e.g., a standard curl request, an Nmap scan) and assert the exact expected fingerprint string.

### Step 4: Risk Scoring & Signaling
*   **Goal:** Connect TAP signals to the existing `RiskScorer` and signal the enforcement bridge.
*   **Task:** Modify the pipeline to run in "Observe" mode. If the score exceeds block thresholds, write a `ban:{ip}` key to Redis instead of dropping a connection.
*   **TDD:** Mock the reassembler to output a malicious stream, verify the Pipeline writes the `ban:{ip}` key to Redis.

### Step 5: Enforcement Bridge
*   **Goal:** Act on the bans written to Redis.
*   **Task:** Implement `src/tap/enforcement.py`.
*   **Action:** Listen to Redis pub/sub for new bans. Implement drivers for `iptables` (using `subprocess` or `ipset`) and `BGP` (ExaBGP pipe).
*   **TDD:** Mock the system calls and verify `ipset add` commands are generated correctly.