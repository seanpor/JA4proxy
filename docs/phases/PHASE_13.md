# Phase 13 Detailed Work Plan: Management UI - Phase 1: Backend API

Status: DEFERRED
Priority: MEDIUM (Post-Phase 15)

## 1. Overview
The Management UI was removed in v13.2.0 due to extreme bloat. This phase resurrects the UI starting with a lightweight FastAPI backend that provides secure access to the proxy's Redis state and configuration.

## 2. Preparation & Clean Slate
**Goal:** Ensure no residual broken code is interfering.
*   **Task:** Verify `management/` directory and UI-specific Dockerfiles are completely removed.
*   **Validation:** `git ls-files | grep management` should return nothing (except potentially `../runbooks/management_ui.md`).

## 3. Architecture & Tech Stack
**Goal:** Keep it lightweight and fast.
*   **Backend:** FastAPI (Python) service. Utilizes existing `LocalCache` logic and Redis connections.
*   **Security:** JWT-based authentication for administrative endpoints.

## 4. Implementation Steps (TDD)

### Step 1: API Foundation
*   **Task:** Implement secure API routes for:
    *   Health/Ready (`/api/v1/health`) - Proxy health overview.
    *   Dial Management (`/api/v1/dial`) - GET/PUT current dial.
    *   Allowlist/Blocklist CRUD (`/api/v1/lists/ja4`).
*   **TDD:** Write `pytest` tests using `FastAPI.testclient`.

### Step 2: Live Connection Feed (SSE)
*   **Task:** Implement Server-Sent Events (SSE) for live log streaming from Redis `ja4proxy:events`.
*   **TDD:** Write tests to ensure the SSE channel broadcasts events properly and handles disconnects.

### Step 3: Docker Integration
*   **Task:** Create a slim `Dockerfile.admin` for the API service.
*   **Task:** Update `docker-compose.yml` to include the `admin-api` service.
*   **Validation:** End-to-end test verifying that changing the dial via API successfully updates Redis.
