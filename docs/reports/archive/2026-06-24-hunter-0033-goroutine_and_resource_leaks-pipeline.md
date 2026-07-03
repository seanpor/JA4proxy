# auditWorker — resource leak

**File:** `internal/security/pipeline.go`
**Lines:** 343-347
**Bug Class:** Goroutine & Resource Leak Accumulation
**Severity:** 7/10
**Impact:** 7/10
**Score (S×I):** 49

## Trigger

Same as beaconingWorker — Pipeline discarded without closing auditJobs.

## Vulnerable Code

```go
func (p *Pipeline) auditWorker() {
	for job := range p.auditJobs {
		p.auditDecision(job.ctx, job.ip, job.currentScore)
	}
}
```

## Execution Trace

  1. Step 1: auditWorker goroutine starts, blocks on for job := range p.auditJobs.
  2. Step 2: The Pipeline object becomes unreachable.
  3. Step 3: The auditJobs channel is never closed.
  4. Step 4: The goroutine remains blocked on the range statement.
  5. Step 5: The goroutine holds a reference to p (via closure), preventing garbage collection of the Pipeline.
  6. Step 6: This creates a memory leak of the entire Pipeline and all its fields.

## Consequence

Resource Leak

---
*Filed by [Hunter](https://github.com/seanpor/hunter) — adversarial AI bug-hunting agent.*

## Disposition (archived 2026-07-03)

Triaged into `docs/security/findings.yaml` as `JA4PROXY-2026-0090`, status
`FIXED`, closed commit `accdfff0`. Fix: moved `beaconingWorker`/`auditWorker`
startup out of `NewPipeline` and into `StartBackgroundWorkers(ctx)` alongside
the async scoring workers, selecting on `ctx.Done()` so they exit on
shutdown — construction now starts zero background goroutines. Regression
test: `internal/security/pipeline_worker_lifecycle_test.go`. Archived here
rather than left at the repo root now that the finding is closed.
