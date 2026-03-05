# Docker‑Based Application: Expanded Test Layers

## 1. Code‑Level and Build‑Time Tests
These tests validate the correctness and security of the application before containerisation.

- **Unit tests** — Validate individual functions, classes, and modules for correctness.  
- **Static Application Security Testing (SAST)** — Detect insecure patterns, unsafe functions, weak crypto, and embedded secrets.  
- **Dependency and SBOM scanning** — Identify vulnerable libraries and generate a Software Bill of Materials for supply‑chain visibility.  
- **Linting and formatting checks** — Enforce coding standards and reduce defect rates early in the pipeline.  
- **Pre‑commit hooks** — Prevent insecure or malformed code from entering the repository.

---

## 2. Image‑Level Tests
These tests validate the Docker image as a build artifact.

- **Dockerfile linting** — Enforce best practices such as minimal base images, pinned versions, and non‑root users.  
- **Image vulnerability scanning** — Detect CVEs in OS packages, language runtimes, and layered dependencies.  
- **Image composition validation** — Ensure only expected binaries, configs, and artifacts are present.  
- **Secrets scanning** — Confirm no credentials, tokens, or private keys are baked into layers.  
- **Reproducible build checks** — Validate deterministic builds for supply‑chain integrity.

---

## 3. Container‑Level Tests
These tests validate runtime behaviour when the image is executed as a container.

- **Runtime configuration tests** — Validate that the container runs with correct flags (no privileged mode, minimal capabilities, read‑only filesystem).  
- **Health check validation** — Ensure `HEALTHCHECK` commands correctly detect degraded or failed states.  
- **Environment variable and config injection tests** — Validate correct handling of secrets, config maps, and runtime parameters.  
- **Functional tests inside the container** — Confirm the application behaves correctly in its containerised environment.  
- **Resource limit tests** — Validate CPU/memory constraints and OOM behaviour.

---

## 4. Integration and Service‑Level Tests
These tests validate how containers interact with each other and external systems.

- **Integration tests** — Validate interactions with databases, message queues, caches, APIs, and storage systems.  
- **Contract tests** — Ensure API compatibility between microservices and prevent breaking changes.  
- **Network policy tests** — Validate that containers can only communicate with approved services.  
- **Service discovery and DNS tests** — Confirm correct resolution in Docker Compose, Swarm, or Kubernetes.  
- **Data migration tests** — Validate schema changes and backward compatibility.

---

## 5. Orchestration and Deployment Tests
These tests validate the behaviour of the application when deployed under an orchestrator.

- **Infrastructure‑as‑Code validation** — Linting and policy checks for Compose files, Helm charts, Terraform, Pulumi, etc.  
- **Security policy tests** — Validate RBAC, Pod Security Standards, network policies, and secrets management.  
- **Scalability and autoscaling tests** — Validate horizontal scaling behaviour and resource elasticity.  
- **Rolling update and rollback tests** — Ensure deployments are safe, reversible, and non‑disruptive.  
- **Node‑level scheduling tests** — Validate affinity, anti‑affinity, and taint toleration rules.

---

## 6. Security and Compliance Tests
These tests validate the security posture of the entire container lifecycle.

- **Container runtime security tests** — Detect privilege escalation paths, namespace escapes, and unsafe syscalls.  
- **Penetration testing of the containerised environment** — Validate external and internal attack surfaces.  
- **Supply‑chain security validation** — Image signing, provenance verification, registry access controls.  
- **Compliance checks** — CIS Docker Benchmark, CIS Kubernetes Benchmark, NIST 800‑190 container security guidelines.  
- **Secrets management tests** — Validate encryption, rotation, and injection mechanisms.

---

## 7. Performance, Resilience, and Operational Tests
These tests ensure the system behaves correctly under real‑world load and failure conditions.

- **Load and stress testing** — Validate performance under expected and peak load.  
- **Chaos testing** — Simulate container crashes, network partitions, node failures, and latency injection.  
- **Failover and recovery tests** — Validate restart policies, self‑healing, and multi‑node resilience.  
- **Backup and restore tests** — Validate data durability and recovery procedures.  
- **Long‑running stability tests** — Detect memory leaks, resource exhaustion, and degradation over time.

---

## 8. End‑to‑End and User‑Journey Tests
These tests validate the entire system from the perspective of a real user.

- **End‑to‑end functional tests** — Validate full workflows across all services.  
- **UI/UX tests** — Validate user‑facing behaviour where applicable.  
- **Synthetic monitoring tests** — Continuous probes that mimic user behaviour in production.  
- **Cross‑service workflow tests** — Validate multi‑step business processes.

---

## Summary Table

| Layer | Focus | Typical Tools |
|------|-------|----------------|
| Code‑level | Logic, quality, early security | pytest, Jest, SAST tools |
| Image‑level | Image security & composition | Trivy, Grype, Hadolint |
| Container‑level | Runtime behaviour | Docker, Testcontainers |
| Integration | Service interactions | Postman, Pact, custom suites |
| Orchestration | Deployment & platform | Helm tests, K8s conformance |
| Security | Hardening & attack simulation | Falco, kube‑bench, pen tests |
| Performance | Load & resilience | k6, Locust, Chaos Mesh |
| End‑to‑end | User workflows | Cypress, Playwright |
