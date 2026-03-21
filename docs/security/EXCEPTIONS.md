# JA4proxy — Approved Security & Testing Exceptions

This document tracks all manual approvals for deviations from the project's Zero-Tolerance policy (skips, warnings, or deferred security fixes). Every entry represents an acknowledged risk with a documented justification.

---

## 📜 Approval Protocol

1.  **Request:** The agent must present a clear technical justification for why a test must be skipped or a warning ignored.
2.  **Manual Approval:** Approval must be granted explicitly by the user in the session history.
3.  **Logging:** Every approved exception is assigned an ID (e.g., `#001`) and logged below.
4.  **Reference:** Code-level suppressions must reference the ID in a comment.
5.  **Audit:** This file is part of the security audit trail.

---

## 🏗️ Active Exceptions

| ID | Type | Target | Justification | Approved By | Expiry Date |
|----|------|--------|---------------|-------------|-------------|
| #... | [Skip/Warning] | [File/Test Name] | [Technical rationale] | [Conversation ID/TS] | [YYYY-MM-DD] |

---

## 🗃️ Archive (Closed Exceptions)

| ID | Status | Resolution |
|----|--------|------------|
| | | |
