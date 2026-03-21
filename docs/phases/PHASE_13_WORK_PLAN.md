# Phase 13 Detailed Work Plan: Management UI Rewrite

## 1. Overview
The Management UI was removed in v13.2.0 due to extreme bloat (245MB node_modules, ~7k lines) without producing a stable interface. This phase resurrects the UI from scratch, utilizing the stable Go backend (Phase 15) as the API provider.

## 2. Preparation & Clean Slate
**Goal:** Ensure no residual broken code is interfering.
*   **Task:** Verify `management/` directory and UI-specific Dockerfiles are completely removed.
*   **Validation:** `git ls-files | grep management` should return nothing (except potentially `docs/runbooks/management_ui.md`, which should be flagged for update).

## 3. Architecture & Tech Stack
**Goal:** Keep it lightweight and fast.
*   **Backend:** Add an HTTP/REST layer to the Go Proxy (`cmd/proxy/` or a new `cmd/admin/`) instead of a separate FastAPI Python service.
*   **Frontend:** React 18 + TypeScript + Vite. No bloated component libraries; use lightweight or vanilla CSS.

## 4. Implementation Steps (TDD)

### Step 1: API Foundation (Go)
*   **Task:** Implement secure API routes in Go for:
    *   Health/Ready (`/api/v1/health`)
    *   Dial Counterfactual (`/api/v1/dial/counterfactual`)
    *   Config/Threshold management.
*   **TDD:** Write `net/http/httptest` unit tests for each handler.

### Step 2: Live Connection Feed (SSE)
*   **Task:** Implement Server-Sent Events (SSE) in Go for live log streaming.
*   **TDD:** Write tests to ensure the SSE channel broadcasts Redis `ja4proxy:events` properly and handles disconnects.

### Step 3: Frontend Foundation
*   **Task:** Initialize Vite project in `ui/`.
*   **Task:** Build the Dashboard (Dial controls, live feed).
*   **TDD:** Use Vitest/React Testing Library for component rendering tests.

### Step 4: Integration & Docker
*   **Task:** Update `docker-compose.yml` to serve the static UI files via the Go server or a lightweight Nginx container.
*   **Validation:** End-to-end test verifying that changing the dial in the UI successfully updates Redis and the Go Proxy.