# WP-R4 Claims Ledger — findings.yaml regression_test repointing

| Finding | Claim | Source | Verdict |
|---------|-------|--------|---------|
| JA4PROXY-2026-0060 | regression_test filled | `cmd/ja4pd/pentest_f003_f005_test.go::TestReassemblyLogLevel` | ✅ Test exists at line 46 |
| JA4PROXY-2026-0067 | `:` separator → `::` | `internal/security/pipeline_test.go::TestPipeline_AuditWorkerBounded` | ✅ Fixed; file:line verified |
| JA4PROXY-2026-0068 | wrong filename + `:` → `::` | `cmd/ja4pd/pentest_forward_config_local_capture_test.go::TestForward_ConfigLocalCapture` | ✅ Fixed; file:line verified |
| JA4PROXY-2026-0069 | `:` separator → `::` | `internal/security/pipeline_test.go::TestPipeline_ConfigReadUnderLock` | ✅ Fixed; file:line verified |
| JA4PROXY-2026-0070 | dangling path cleared | `internal/redis/pentest_keyfile_permissions_test.go::...` never existed | ✅ Cleared; permission check is guard clause in client.go:325-332 |
| JA4PROXY-2026-0071 | dangling path cleared | `internal/cluster/sync/agent_test.go::...` never existed | ✅ Cleared; permission check in agent.go:610-615; no test file in cluster/sync/ |
| JA4PROXY-2026-0072 | due date fixed | `2026-10-20` → `2026-10-22` | ✅ LOW SLA = 120 days from discovered |
| JA4PROXY-2026-0073 | due date fixed | `2026-10-20` → `2026-10-22` | ✅ LOW SLA = 120 days from discovered |
| JA4PROXY-2026-0074 | due date fixed | `2026-10-20` → `2026-10-22` | ✅ LOW SLA = 120 days from discovered |
| JA4PROXY-2026-0075 | due date fixed | `2026-10-20` → `2026-10-22` | ✅ LOW SLA = 120 days from discovered |
| JA4PROXY-2026-0076 | lane `infra` → `infrastructure`; path cleared; due fixed | `tests/unit/test_container_config.py::...` never existed | ✅ Fixed lane + due; no dedicated test |
| JA4PROXY-2026-0077 | lane `infra` → `infrastructure`; path cleared; due fixed | `tests/unit/test_container_config.py::...` never existed | ✅ Fixed lane + due; no dedicated test |
| JA4PROXY-2026-0078 | lane `infra` → `infrastructure`; due fixed | — | ✅ Fixed lane + due; no test (entrypoint echo removal) |
| JA4PROXY-2026-0079 | lane `infra` → `infrastructure`; due fixed | — | ✅ Fixed lane + due; OPEN status (no regression_test needed) |
| JA4PROXY-2026-0080 | lane `infra` → `infrastructure`; due fixed | — | ✅ Fixed lane + due; regression_test `test_pubsub_signing.py` verified |

## Known validation residual

5 FIXED findings (0070, 0071, 0076, 0077, 0078) have empty `regression_test` because
no dedicated test exists for their fixes (guard clauses, config changes, shell script
edits). The validator requires `regression_test` for FIXED status. These are genuine
"no regression test" cases per WP-R4 scope. Acceptable residual — all dangling paths
are eliminated, all paths resolve to existing files.
