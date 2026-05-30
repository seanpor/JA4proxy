# Phase 51: Management UI - Phase 2: Frontend Dashboard

Priority: MEDIUM (Post-Phase 13)

## Goal
Implement a responsive, React-based dashboard for real-time visualization of proxy telemetry and security state.

## Sub-Tasks

### 51a — React Scaffold & Core UI
- [ ] **Setup:** Initialize React/TypeScript project with Vite and Tailwind CSS.
- [ ] **Architecture:** Implement a component-based architecture for the dashboard (Sidebar, Header, Metric Cards).
- [ ] **Dark Mode:** Support system-preferred dark/light modes for SecOps environments.

### 51b — Real-Time Telemetry Visualization
- [ ] **Graphs:** Implement time-series charts for throughput (Requests/sec) and error rates using Recharts or Chart.js.
- [ ] **Map:** Add a GeoIP-based heat map of current connection sources.
- [ ] **WebSockets:** Connect to the Phase 13 FastAPI backend for sub-second updates of the "Live Feed" of connection decisions.

### 51c — Dial Control & Risk Overview
- [ ] **Dial Widget:** Interactive circular dial for adjusting the current security posture (0-100).
- [ ] **Risk Breakdown:** Visual breakdown of current risk signals (e.g., % of traffic with JA4 blacklist matches).

## Acceptance Criteria
- [ ] Dashboard renders correctly on desktop and mobile browsers.
- [ ] Real-time connection feed updates without page refresh.
- [ ] Dial value correctly reflects the actual state in Redis.
- [ ] Zero build errors and passing lint checks.
