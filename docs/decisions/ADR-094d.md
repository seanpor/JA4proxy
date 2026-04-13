# ADR-094d: Helm Chart Topology — Convert Deployment to DaemonSet

**Status:** Accepted
**Date:** 2026-04-12
**Phase:** 94b (Kubernetes Operator + NetBox + ServiceNow CMDB)

---

## Context

The Helm chart at `deploy/helm/ja4proxy/` currently defines a `kind: Deployment`
with a configurable `replicaCount` (default 2) and an HPA for autoscaling. Phase
76's design recommended a DaemonSet topology (one proxy per node) to ensure every
node has a local proxy instance, minimising cross-node network hops and eliminating
the need for a separate Service-based load balancer.

However, Phase 76 was a paper-only recommendation — no chart change was shipped.
The operator design (Phase 94c–94g) assumes DaemonSet end-to-end: safety annotations
(`safe-to-evict: false`, `system-node-critical`, `terminationGracePeriodSeconds: 30`)
are meaningful only for DaemonSets, and the operator's reconciliation loop targets
DaemonSet pod templates.

Two options were considered:

| | Option A: Convert to DaemonSet | Option B: Keep Deployment, add opt-in DaemonSet |
|---|---|---|
| **Topology match** | Matches Phase 76 design and operator assumptions | Deployment remains default; DaemonSet is a secondary variant |
| **Backward compat** | Breaking change for any user with replicated Deployment usage | No breaking change |
| **Chart surface** | Single manifest — one topology to maintain and test | Doubles chart surface area (two template variants) |
| **Operator complexity** | Operator targets one known topology | Operator must detect which topology is installed per cluster |
| **Real-world usage** | Chart is recent; likely zero production Deployment users | Backward compatible but adds unused complexity |

---

## Decision

**Option A: Convert the chart to DaemonSet.**

The chart is recent and has no established production user base with a Deployment
topology. The operator design assumes DaemonSet end-to-end. Maintaining two template
variants for the chart would double testing burden and force the operator to detect
topology at runtime.

The following fields are removed from `values.yaml`:
- `replicaCount` (DaemonSet does not use replicas)
- `hpa.enabled`, `hpa.minReplicas`, `hpa.maxReplicas`, `hpa.targetConnectionCount`
  (HPA is meaningless for DaemonSets)
- `pdb.enabled`, `pdb.minAvailable` (PodDisruptionBudgets do not apply to DaemonSets)
- `nodeAffinity.enabled` (DaemonSet already schedules one pod per node; anti-affinity
  is redundant)

The DaemonSet template includes mandatory safety annotations:
- `cluster-autoscaler.kubernetes.io/safe-to-evict: "false"`
- `priorityClassName: system-node-critical`
- `terminationGracePeriodSeconds: 30`

---

## Rationale

A TLS passthrough proxy is a node-level infrastructure concern — every node that
accepts inbound traffic needs a local proxy instance. A Deployment with HPA scales
based on connection count, but connection distribution across nodes is not uniform,
and a scaled-down pod on a different node introduces cross-node latency. A DaemonSet
guarantees exactly one proxy per schedulable node, which is the correct production
topology for this workload.

The removed values (`replicaCount`, HPA, PDB) are deleted from `values.yaml` rather
than kept as no-ops. Keeping dead values would mislead future users into thinking
they affect the deployment.

---

## Consequences

- `deploy/helm/ja4proxy/templates/deployment.yaml` → renamed to `daemonset.yaml`,
  `kind: Deployment` changed to `kind: DaemonSet`, `replicas` removed.
- `deploy/helm/ja4proxy/values.yaml`: `replicaCount`, `hpa`, `pdb`, and
  `nodeAffinity` sections removed.
- Any existing users with a Deployment-based installation must delete the old
  Deployment before upgrading the chart (`kubectl delete deployment ja4proxy`).
- `helm template` and `helm lint` succeed with the DaemonSet manifest.
- The operator's Helm chart (Phase 94g) targets this DaemonSet directly.
