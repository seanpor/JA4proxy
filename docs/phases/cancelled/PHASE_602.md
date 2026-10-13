# Shadow Mode & Policy Analytics

## Goal
Enable enterprise operators to test complex JA4-based policies against live traffic without affecting production (Shadow Mode) and provide the analytics infrastructure to evaluate these policies.

## Background
Phase 100 identified Shadow Mode (100-L, 100-M) as a critical enterprise feature. Operators need to validate "what-if" scenarios (e.g., "What happens if I block JA4T:windows and JA4S:python?") before enforcement. This requires capturing decisions without applying them and providing a simulation report.

## Scope
1.  **Decision Capture**: Log all JA4-based decisions (block/allow/tarpit) to a dedicated Redis Stream (`events:shadow_decisions`) when Shadow Mode is enabled.
2.  **Signal Retention**: Implement a configurable retention policy for shadow signals (default 90 days) to allow for historical analysis.
3.  **Simulation API**: Expose `POST /api/v1/simulation/run` and `GET /api/v1/simulation/{id}/report` to run a simulation against a recorded traffic set.
4.  **Analytics Dashboard**: Add a "Shadow Mode" tab to the Grafana dashboard showing "would-be" blocks vs actual traffic.

## Implementation Plan
1.  **Step 1: Shadow Decision Logger**
    *   Add a `shadow_mode: true` toggle in `config/proxy.yml`.
    *   In the risk scorer, if shadow mode is on, write the decision to `events:shadow_decisions` instead of enforcing.
2.  **Step 2: Retention Service**
    *   Implement `analytics/shadow_retention.py` with a TTL-based cleanup.
3.  **Step 3: Simulation Engine**
    *   Implement `analytics/simulation_runner.py` that replays a traffic sample through the policy engine.
4.  **Step 4: Dashboard**
    *   Create `deploy/monitoring/grafana/dashboards/05_shadow_mode.json`.

## Acceptance Criteria
1.  `shadow_mode: true` results in zero enforcement actions (verified by metrics).
2.  `events:shadow_decisions` stream is populated with valid JSON decisions.
3.  `POST /api/v1/simulation/run` returns a job ID and `GET .../report` returns a valid JSON report.
4.  Grafana dashboard displays shadow mode traffic.
5.  Shadow signal retention is configurable and enforced.

## Dependencies
*   Phase 79 (Management API v2) - **COMPLETE**
*   Phase 100 (Gap Closure) - **COMPLETE**
