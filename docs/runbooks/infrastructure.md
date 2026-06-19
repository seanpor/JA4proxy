<!--
title: "infrastructure Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Infrastructure Runbook

This runbook covers all alerts defined in the `ja4proxy_infrastructure`,
`ja4proxy_container`, `ja4proxy_haproxy`, `ja4proxy_capacity`, and
`ja4proxy_attack_detection` Prometheus alert groups.

**Dashboard:** Open the Infrastructure & Attack dashboard in Grafana
(e.g. `http://localhost:3000/d/ja4proxy-infrastructure`).
for visual context when responding to any alert in this runbook.

---

## host-cpu-high

**Alert:** `NodeHighCPU`

**What is firing:** Host CPU has exceeded 80% for 5 continuous minutes.

**Immediate check:**
```bash
# Top processes by CPU
top -b -n1 -o %CPU | head -20

# Active proxy connections
docker exec proxy curl -s http://localhost:9090/metrics | grep ja4proxy_active_connections

# Connection rate and block rate
docker exec proxy curl -s http://localhost:9090/metrics | grep ja4proxy_connections_total
```

**Common causes:**
- Sustained attack driving high connection rate through the scoring pipeline
- Tarpit overflow not engaged — many connections held in scoring loop
- Misconfigured signal module (e.g. synchronous DNS lookup not yielding)
- Beaconing detector scanning excessively large sorted sets

**Resolution steps:**
1. Check `ja4proxy_connections_total` rate. If above normal, this is load-driven — proceed to raise dial or engage HAProxy rate limiting upstream.
2. Check tarpit concurrent count (`ja4proxy_tarpit_concurrent`). If near cap (500), connections are queuing — review `overflow_action` config.
3. Check for any synchronous Redis calls in logs: `docker logs proxy 2>&1 | grep "blocked"`
4. If CPU is driven by a single signal module, disable that module temporarily via hot reload (`SIGHUP`).
5. If attack-driven and dial < 50, raise dial in steps of 10 to shed load via faster blocking decisions.

**Escalation:** Escalate if CPU remains above 80% after dial adjustment, or if no clear attack pattern is visible.

---

## host-cpu-critical

**Alert:** `NodeCriticalCPU`

**What is firing:** Host CPU has exceeded 95% for 2 continuous minutes — proxy is likely dropping connections.

**Immediate check:**
```bash
# Immediate view of CPU saturation
vmstat 1 5

# Check if HAProxy is already queuing
docker exec haproxy haproxy -c -f /etc/haproxy/haproxy.cfg
curl -s http://haproxy:8404/stats | grep -i queue
```

**Common causes:**
- DDoS exceeding proxy throughput ceiling (~350 conn/s Python, ~3000 conn/s Go)
- Redis pipeline exhausted — every connection waiting synchronously
- Python GIL contention under extreme connection rate
- Runaway tarpit loop holding CPU in asyncio event loop

**Resolution steps:**
1. Immediately engage HAProxy frontend rate limiting: `haproxy -sf $(pidof haproxy)` with updated config capping `rate-limit sessions`.
2. If possible, raise dial to maximum (100) to accelerate block decisions and reduce time per connection.
3. Check if Go proxy is available (`make switch-to-go`) — Go proxy handles ~10x more connections per CPU.
4. Scale horizontally: add another proxy instance and update HAProxy backend (`maxconn` per server).
5. If Redis is the bottleneck, check `redis-cli info stats | grep instantaneous_ops_per_sec`.

**Escalation:** Page on-call immediately. If CPU does not recover within 5 minutes of HAProxy rate limiting, escalate to architecture team.

---

## high-load

**Alert:** `NodeHighLoad`

**What is firing:** Normalised load average (load1 / CPU count) has exceeded 0.8 for 5 minutes.

**Immediate check:**
```bash
# Decompose load into CPU vs I/O wait
iostat -x 1 3

# Check DNS resolution queue depth
docker logs proxy 2>&1 | grep dns_enrichment | tail -20

# Check Redis AOF fsync lag
docker exec redis redis-cli info persistence | grep aof
```

**Common causes:**
- I/O wait from Redis AOF `always` fsync policy under high write rate
- DNS enrichment queue backing up with too many concurrent PTR lookups
- Disk I/O from log writes during attack (high event rate)
- Swap activity if memory is also constrained

**Resolution steps:**
1. Check `iostat` — if `%iowait` is high, the bottleneck is disk I/O, not CPU.
2. For Redis AOF: `docker exec redis redis-cli config set appendfsync everysec` to reduce fsync frequency.
3. For DNS: reduce `dns_enrichment.worker_count` in `config/proxy.yml` and reload.
4. Check swap: `vmstat -s | grep swap`. If swapping, add memory or reduce container limits to trigger OOM protection rather than swap.
5. Check log volume: `ls -lh /var/log/ja4proxy/`. Rotate if large.

**Escalation:** Escalate if load remains above 1.0 after I/O tuning, or if the source cannot be identified within 15 minutes.

---

## critical-load

**Alert:** `NodeCriticalLoad`

**What is firing:** Normalised load average has exceeded 1.5 for 2 minutes — every CPU core has more than 1.5 tasks queued.

**Immediate check:**
```bash
# Find which subsystem is contributing most load
sar -u 1 5
# Separate CPU% from iowait%

# Check for disk saturation
df -h && iostat -d 1 3
```

**Common causes:**
- Combined CPU + I/O saturation during a high-volume attack
- Runaway process (e.g. analytics node consuming all cores)
- NFS or remote filesystem stall blocking kernel threads
- Redis fork during BGSAVE holding memory pages

**Resolution steps:**
1. Use `ps aux --sort=-%cpu | head -20` to identify the runaway process.
2. If analytics container is consuming CPU: `docker stop analytics` temporarily — proxy continues without analytics signals (fail-open).
3. If Redis is doing BGSAVE: `docker exec redis redis-cli bgsave` should complete quickly; if hung, check disk space.
4. Reduce load by enabling HAProxy frontend rate limiting immediately.
5. Consider restarting the lowest-priority service (analytics first, then proxy with HAProxy failover).

**Escalation:** Immediate escalation if load above 2.0 or if any container has been OOM-killed.

---

## host-memory-high

**Alert:** `NodeHighMemory`

**What is firing:** Host memory utilisation has exceeded 85% for 5 minutes.

**Immediate check:**
```bash
# Memory breakdown by process
ps aux --sort=-%mem | head -15

# Redis memory usage
docker exec redis redis-cli info memory | grep used_memory_human

# Container memory limits
docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}"
```

**Common causes:**
- Redis with no `maxmemory` limit configured, growing unbounded
- Analytics node loading large datasets (numpy/pandas) during campaign analysis
- Log buffer accumulation in proxy container during high-event attack
- Memory leak in proxy (long-running connections not releasing buffers)

**Resolution steps:**
1. Check Redis memory: if above 2GB and no limit set, set one: `docker exec redis redis-cli config set maxmemory 2gb && config set maxmemory-policy allkeys-lru`.
2. Check analytics memory: `docker stats analytics`. If very high, restart it — analytics is stateless.
3. Check proxy for long-lived connections: `ss -s` for TIME_WAIT accumulation.
4. Review `config/proxy.yml` cache sizes — reduce `local_cache.max_size` and reload.
5. Add swap as emergency buffer only: `fallocate -l 4G /swapfile && mkswap /swapfile && swapon /swapfile`.

**Escalation:** Escalate if memory continues growing after Redis limit is set or analytics is restarted.

---

## host-memory-critical

**Alert:** `NodeCriticalMemory`

**What is firing:** Host memory has exceeded 95% — OOM kill of proxy or Redis is imminent.

**Immediate check:**
```bash
# Check OOM score for critical processes
cat /proc/$(pgrep -f bin/ja4pd)/oom_score
cat /proc/$(pgrep redis-server)/oom_score

# Which containers are largest
docker stats --no-stream
```

**Common causes:**
- Redis unbounded growth (no maxmemory) during prolonged attack (high scan/ban rate)
- Multiple large analytics jobs running concurrently
- Memory leak that was not caught at 85% threshold

**Resolution steps:**
1. Immediately set Redis maxmemory if not set: `docker exec redis redis-cli config set maxmemory 1gb`.
2. Stop analytics container to free memory fast: `docker stop analytics`.
3. Set OOM score to protect proxy: `echo -500 > /proc/$(pgrep -f bin/ja4pd)/oom_score_adj`.
4. Drop caches to release page cache: `sync && echo 1 > /proc/sys/vm/drop_caches`.
5. If OOM kill has already occurred, check `dmesg | grep -i oom` and restart killed service immediately.

**Escalation:** Immediate escalation. If Redis is killed, proxy is in fail-open mode with no rate limiting or bans active.

---

## file-descriptors

**Alert:** `NodeFileDescriptorsHigh`

**What is firing:** System-wide file descriptor utilisation has exceeded 70%.

**Immediate check:**
```bash
# Current FD usage
cat /proc/sys/fs/file-nr   # used / free / max

# Per-process FD counts
ls /proc/$(pgrep -f bin/ja4pd)/fd | wc -l
ls /proc/$(pgrep redis-server)/fd | wc -l

# Active TCP connections
ss -s
```

**Common causes:**
- Attack driving high connection rate — each connection uses 2+ FDs (client + backend)
- TIME_WAIT sockets not recycling fast enough (tcp_tw_reuse not enabled)
- Log file handles accumulating (log rotation not closing old handles)
- Redis connections not being pooled — each pipeline call opens a new connection

**Resolution steps:**
1. Increase system FD limit immediately: `sysctl -w fs.file-max=1000000`.
2. Enable TIME_WAIT socket reuse: `sysctl -w net.ipv4.tcp_tw_reuse=1`.
3. Check proxy connection pool: verify `redis_pool_size` in config is not too large.
4. Force log rotation to close handles: `logrotate -f /etc/logrotate.d/ja4proxy`.
5. Update `/etc/sysctl.conf` with the new values so they persist across reboots.

**Escalation:** Escalate if FD utilisation continues rising after sysctl increase.

---

## file-descriptors-critical

**Alert:** `NodeFileDescriptorsCritical`

**What is firing:** File descriptor utilisation has exceeded 85% — OS is likely already refusing new connections with EMFILE.

**Immediate check:**
```bash
# Confirm EMFILE errors in proxy log
docker logs proxy 2>&1 | grep -i "too many open\|EMFILE\|accept" | tail -20

# Current file-nr
cat /proc/sys/fs/file-nr
```

**Common causes:**
- Attack volume exceeding FD limit before sysctl was tuned
- FD leak in proxy — connections accepted but not closed on error paths
- Redis connection pool growing without bound

**Resolution steps:**
1. Emergency increase: `sysctl -w fs.file-max=2000000` and `ulimit -n 2000000` in proxy container.
2. Identify FD leak: `lsof -p $(pgrep -f bin/ja4pd) | wc -l` — compare over 30 seconds.
3. Restart proxy container with updated ulimit in docker-compose (`nofile: 1048576`).
4. Engage HAProxy frontend rate limiting to reduce new connection rate immediately.
5. Persist fix: update `/etc/security/limits.conf` and Docker daemon `default-ulimits`.

**Escalation:** Immediate escalation. New connections are being silently dropped.

---

## disk-low

**Alert:** `NodeDiskSpaceLow`

**What is firing:** A filesystem has exceeded 80% capacity.

**Immediate check:**
```bash
# Find largest directories
du -sh /var/lib/docker/* | sort -rh | head -10
du -sh /var/log/* | sort -rh | head -10

# Redis data files
du -sh /var/lib/docker/volumes/redis-data/
```

**Common causes:**
- Log files growing unchecked during a high-volume attack (high event rate fills logs fast)
- Redis RDB snapshots accumulating (BGSAVE creating large dump.rdb files)
- Docker overlay layers from image builds not cleaned up
- Backup retention policy not running — old backups not deleted

**Resolution steps:**
1. Run log rotation immediately: `logrotate -f /etc/logrotate.d/ja4proxy`.
2. Clean Docker images and stopped containers: `docker system prune -f`.
3. Check Redis dump.rdb size: `ls -lh /var/lib/docker/volumes/redis-data/_data/dump.rdb`. If large, verify `save ""` config or reduce save frequency.
4. Remove old backup files: `find /backups/ja4proxy -mtime +7 -delete`.
5. Expand the volume or mount a new disk if growth is structural (attack-sustained log rate).

**Escalation:** Escalate if disk above 85% after cleanup, or if log growth rate is so high that cleanup cannot keep up.

---

## disk-critical

**Alert:** `NodeDiskSpaceCritical`

**What is firing:** A filesystem has exceeded 90% capacity — Redis and log writes will start failing.

**Immediate check:**
```bash
# Immediate space recovery
docker system prune -f
journalctl --vacuum-size=500M

# Redis write errors
docker exec redis redis-cli info stats | grep rejected_connections
docker logs redis 2>&1 | grep -i "MISCONF\|disk\|AOF" | tail -20
```

**Common causes:**
- Same as disk-low but threshold was missed or escalated rapidly
- Redis AOF log growing very fast during a high-write-rate attack
- Core dump written to disk by crashed container

**Resolution steps:**
1. Immediately recover space: `docker system prune -af` (removes all unused images — safe if images are in registry).
2. Truncate Redis AOF if it is the culprit: `docker exec redis redis-cli bgrewriteaof`.
3. Delete old log files: `find /var/log -name "*.gz" -mtime +1 -delete`.
4. Check for core dumps: `find / -name "core.*" -size +100M -delete 2>/dev/null`.
5. Disable Redis AOF temporarily if disk is critically full: `docker exec redis redis-cli config set appendonly no`.

**Escalation:** Immediate escalation. If Redis cannot write, scoring state is degraded. Proxy continues (fail-open) but bans and rate limits are not persisted.

---

## inodes

**Alert:** `NodeInodesLow`

**What is firing:** Free inodes on a filesystem have dropped below 20%.

**Immediate check:**
```bash
# Which directory is consuming inodes
for dir in /var /tmp /var/log /var/lib/docker; do
  echo "$dir: $(find $dir -maxdepth 3 2>/dev/null | wc -l) files"
done

# Inode usage per filesystem
df -i
```

**Common causes:**
- Small files accumulating in tmp directories (metrics, lock files, session files)
- Docker overlay filesystem accumulating layer metadata
- Log rotation creating many small rotated files
- Redis RDB temporary files not cleaned up after failed saves

**Resolution steps:**
1. Find the directory with most files: `find /var -xdev -printf '%h\n' | sort | uniq -c | sort -rn | head -20`.
2. Clean up Docker metadata: `docker system prune -f`.
3. Remove small temp files: `find /tmp -mtime +1 -delete`.
4. Check for small log segments: `ls /var/log/ja4proxy/ | wc -l`. If thousands, run `logrotate -f`.
5. If the affected filesystem is `/var/lib/docker`, consider reformatting with a larger inode ratio (requires downtime).

**Escalation:** Escalate if inodes below 5% — at that point new files cannot be created and Redis/log writes will fail.

---

## entropy

**Alert:** `NodeEntropyLow`

**What is firing:** The kernel entropy pool has dropped below 512 bytes.

**Immediate check:**
```bash
# Current entropy
cat /proc/sys/kernel/random/entropy_avail

# Check if rng-tools is running
systemctl status rngd haveged 2>/dev/null || echo "No entropy daemon found"

# TLS handshake rate (entropy consumer)
docker exec proxy curl -s http://localhost:9090/metrics | grep connections_total
```

**Common causes:**
- High TLS handshake rate depleting entropy faster than the kernel can gather it
- Virtual machine with no hardware RNG attached
- `rng-tools` or `haveged` not installed or not running

**Resolution steps:**
1. Install and start an entropy daemon immediately: `apt install -y haveged && systemctl enable --now haveged` (or `rng-tools`).
2. On cloud/VM: ensure `virtio-rng` is attached: `ls /dev/hwrng && cat /sys/devices/virtual/misc/hw_random/rng_current`.
3. Verify entropy recovers: `watch -n1 cat /proc/sys/kernel/random/entropy_avail` — should rise to 1000+.
4. As a temporary workaround, load the `jitterentropy_rng` kernel module: `modprobe jitterentropy_rng`.
5. On RHEL/Fedora: enable `rngd`: `systemctl enable --now rngd`.

**Escalation:** Escalate if entropy remains below 256 after daemon installation. TLS handshakes stalling will manifest as connection rate drop.

---

## oom-kill

**Alert:** `ContainerOOMKilled`

**What is firing:** A JA4proxy-related container was killed by the Linux OOM killer.

**Immediate check:**
```bash
# Identify which container was killed and when
dmesg | grep -i "oom\|killed process" | tail -20

# Container restart count
docker inspect proxy redis analytics --format '{{.Name}}: restarts={{.RestartCount}}'

# Current memory state
docker stats --no-stream
```

**Common causes:**
- Redis with no `maxmemory` limit grew to fill all available memory
- Analytics container loading very large dataset into memory
- Memory leak in proxy causing gradual growth that triggered OOM at peak load
- Container memory limit set too low for the workload

**Resolution steps:**
1. Identify the killed container from `dmesg`. Restart it immediately if not auto-restarted.
2. If Redis was killed: proxy is in fail-open mode. Restart Redis, then verify proxy reconnects: `docker logs proxy | grep "Redis connected"`.
3. Set Redis memory limit to prevent recurrence: `docker exec redis redis-cli config set maxmemory 2gb`.
4. If proxy was killed: check for memory leak — compare `container_memory_working_set_bytes` before and after restart trends.
5. Increase container memory limit in `deploy/docker/docker-compose.poc.yml` and redeploy if the workload legitimately requires more.

**Escalation:** Immediate escalation if Redis was the killed container — all active bans and rate limits are lost until state rebuilds.

---

## restart-loop

**Alert:** `ContainerRestartLoop`

**What is firing:** A container has restarted 2 or more times within 30 minutes.

**Immediate check:**
```bash
# Container restart history and last exit code
docker inspect proxy --format '{{.RestartCount}} restarts, last exit: {{.State.ExitCode}}'

# Last 100 lines before crash
docker logs --tail 100 proxy

# Check for configuration errors (the Go proxy validates config at startup;
# this pre-checks YAML syntax before a restart)
python3 -c "import yaml; yaml.safe_load(open('config/proxy.yml'))"
```

**Common causes:**
- Configuration file syntax error after hot reload
- Redis connection failure at startup (Redis not yet ready)
- Import error after a code deployment
- Out-of-memory kill triggering restart (check alongside `ContainerOOMKilled`)
- Port conflict — another process took the proxy's listen port

**Resolution steps:**
1. Check exit code: `0` = clean exit (config issue), `137` = OOM kill, `1` = startup error (bad config, Redis unreachable at boot, or listen-port conflict).
2. For exit code 1: read last 50 lines of the container log to find the Go startup error or panic message.
3. For configuration errors: validate config before restart: `python3 -c "import yaml; yaml.safe_load(open('config/proxy.yml'))"`.
4. For Redis dependency: ensure Redis container starts first — add `depends_on: redis` with health check in docker-compose.
5. For port conflict: `ss -tlnp | grep 8080` to find the conflicting process.

**Escalation:** Escalate after 3 restarts if root cause is not identified — traffic is unprotected during each restart interval.

---

## container-memory

**Alert:** `ContainerMemoryHigh`

**What is firing:** A container is using more than 85% of its configured memory limit.

**Immediate check:**
```bash
# Memory breakdown
docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}"

# For Redis specifically
docker exec redis redis-cli info memory | grep -E "used_memory_human|maxmemory_human|mem_fragmentation_ratio"
```

**Common causes:**
- Redis cache growing during attack (many unique IPs being scored)
- Analytics node accumulating sliding window data during campaign analysis
- Proxy local cache `max_size` set too large relative to container limit
- Memory fragmentation in Redis (high `mem_fragmentation_ratio` > 1.5)

**Resolution steps:**
1. If Redis: check `mem_fragmentation_ratio`. If above 1.5, defragment: `docker exec redis redis-cli memory purge`.
2. If Redis: verify `maxmemory` is set and less than the container limit: `docker exec redis redis-cli config get maxmemory`.
3. If proxy: reduce `local_cache.max_size` in config and reload via SIGHUP.
4. If analytics: restart it — analytics is stateless and will rebuild state from Redis Stream.
5. Increase container memory limit in docker-compose if workload legitimately requires it.

**Escalation:** Escalate if memory continues growing after cache reduction — may indicate a leak.

---

## cpu-throttle

**Alert:** `ContainerCPUThrottleHigh`

**What is firing:** A container is spending more than 20% of its time waiting for CPU quota.

**Immediate check:**
```bash
# Container CPU usage vs limit
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}"

# Host CPU utilisation context
top -b -n1 | head -5

# Check container CPU limit in compose
grep -A5 "cpus:" deploy/docker/docker-compose.poc.yml
```

**Common causes:**
- Container `cpus` limit too low for the workload (common after adding new signal modules)
- Host CPU oversubscribed — many containers competing for limited CPU
- Burst traffic event hitting a tightly limited proxy container
- Proxy container limited to 1 CPU but scoring pipeline is CPU-intensive

**Resolution steps:**
1. Increase container CPU limit in `deploy/docker/docker-compose.poc.yml`: change `cpus: "1"` to `cpus: "2"` and redeploy.
2. If host CPU is the ceiling (NodeHighCPU also firing), address that first — container limit increase will not help.
3. Check if the throttled container is proxy: if so, consider switching to the Go proxy which is far more CPU-efficient.
4. Pin the proxy container to dedicated CPUs: `cpuset: "0,1"` to avoid competing with analytics.
5. If throttle is intermittent (burst), consider `cpu_shares` tuning rather than a hard limit.

**Escalation:** Escalate if throttle ratio above 0.5 (50%) and container CPU limit cannot be raised — this will manifest as connection latency spikes above 100ms.

---

## haproxy-queue

**Alert:** `HAProxyBackendQueueing`

**What is firing:** HAProxy has at least 1 connection queued waiting for a JA4proxy backend slot.

**Immediate check:**
```bash
# HAProxy stats page
curl -s 'http://haproxy:8404/stats;csv' | grep ja4proxy | cut -d, -f1,3,4,18,19,24

# Proxy active connections
docker exec proxy curl -s http://localhost:9090/metrics | grep ja4proxy_active_connections
```

**Common causes:**
- Proxy at max active connection capacity (`maxconn` per backend server in HAProxy config)
- Proxy CPU saturated — accepting connections slowly
- Proxy is handling many tarpit connections, holding slots
- Backend server `maxconn` in HAProxy config set too conservatively

**Resolution steps:**
1. Check queue depth trend — 1-3 queued is normal burst behaviour; sustained queue above 10 needs action.
2. Increase HAProxy backend `maxconn` if proxy can handle more: `server proxy1 127.0.0.1:8080 maxconn 2000`.
3. Reduce tarpit concurrent limit to free up connection slots: `config/proxy.yml tarpit.max_concurrent`.
4. Add a second proxy backend instance and add to HAProxy backend pool.
5. If queue is driven by attack, raise the dial to block faster and reduce active connection time.

**Escalation:** Escalate if queue depth above 50 for more than 2 minutes — users are experiencing connect delays.

---

## haproxy-sessions

**Alert:** `HAProxySessionLimitApproaching`

**What is firing:** HAProxy frontend session count has exceeded 80% of the configured maximum.

**Immediate check:**
```bash
# Current session count vs limit
curl -s 'http://haproxy:8404/stats;csv' | awk -F, 'NR==1 || /FRONTEND/ {print $1,$3,$4,$48}'

# Connection rate
curl -s 'http://haproxy:8404/stats;csv' | awk -F, '/FRONTEND/ {print "rate:", $46, "max:", $47}'
```

**Common causes:**
- DDoS attack filling HAProxy session table with slow/incomplete TLS handshakes
- HAProxy `maxconn` global too low for the traffic level
- Long-lived connections not being released (keep-alive abuse)
- Backend down causing HAProxy to hold retry connections

**Resolution steps:**
1. Identify connection origin: `curl -s 'http://haproxy:8404/stats' | grep -i "src"` or check ACL logs.
2. If under attack: enable HAProxy frontend rate limiting: `stick-table type ip size 1m expire 30s store conn_rate(10s)` and ACL to reject above threshold.
3. Increase HAProxy `maxconn` in global section if legitimate traffic is the cause.
4. Enable `timeout client-fin 5s` to aggressively close half-closed connections.
5. Check backend health — if backends are returning errors, HAProxy retries inflate session count.

**Escalation:** Escalate if session count reaches 95% — at limit, HAProxy returns 503 to all new connections.

---

## haproxy-backend-down

**Alert:** `HAProxyBackendDown`

**What is firing:** HAProxy has marked a JA4proxy backend server as DOWN.

**Immediate check:**
```bash
# HAProxy backend status
curl -s 'http://haproxy:8404/stats;csv' | awk -F, '/ja4proxy/ && /SERVER/ {print $1, $18}'

# Is proxy running?
docker ps | grep proxy
docker logs proxy --tail 30
```

**Common causes:**
- Proxy container crashed or OOM-killed
- Health check endpoint `/health` returning 503 or timing out
- Proxy port changed in config but HAProxy config not updated
- Network partition between HAProxy and proxy containers

**Resolution steps:**
1. Check proxy container status: `docker ps -a | grep proxy`. If exited, restart: `docker start proxy`.
2. Manually test health endpoint: `curl -v http://127.0.0.1:8080/health`.
3. Check HAProxy health check config: `haproxy.cfg` `option httpchk` — ensure path and port match proxy.
4. Check network: `docker exec haproxy ping proxy -c3`.
5. If health check is flapping: increase `rise` and `fall` values in HAProxy backend config to reduce flap sensitivity.

**Escalation:** Immediate escalation if all backends are DOWN — all traffic is being dropped by HAProxy.

---

## haproxy-connection-errors

**Alert:** `HAProxyConnectionErrorRate`

**What is firing:** HAProxy is experiencing more than 1 connection error per second to JA4proxy backends.

**Immediate check:**
```bash
# Error count and type
curl -s 'http://haproxy:8404/stats;csv' | awk -F, '/ja4proxy/ {print $1, $13, $14, $15}'
# Fields: econ (connection errors), eresp (response errors), wretr (retries)

# Check if proxy is accepting connections
nc -z 127.0.0.1 8080 && echo "port open" || echo "port closed"
```

**Common causes:**
- Proxy TCP backlog full — kernel not accepting new connections fast enough
- Proxy crashing under load (restart loop)
- TLS mismatch between HAProxy and proxy (proxy expects plaintext, HAProxy sends TLS)
- Proxy listen socket closed during reload

**Resolution steps:**
1. Increase proxy TCP backlog: `sysctl -w net.core.somaxconn=4096 net.ipv4.tcp_max_syn_backlog=4096`.
2. Check proxy is listening: `ss -tlnp | grep 8080`.
3. Verify connection mode: JA4proxy accepts plain TCP from HAProxy (HAProxy does TLS termination). Check HAProxy `mode tcp` vs `mode http`.
4. If proxy is in reload: wait 30 seconds, connection errors should clear.
5. Check proxy for `ConnectionRefusedError` in logs: `docker logs proxy 2>&1 | grep "Connection refused"`.

**Escalation:** Escalate if error rate above 10/s — significant traffic loss in progress.

---

## haproxy-queue-attack

**Alert:** `HAProxyQueueSignalsCapacityAttack`

**What is firing:** HAProxy has more than 5 connections queued for JA4proxy, indicating proxy saturation under attack.

**Immediate check:**
```bash
# Combined view: queue depth + connection rate
curl -s 'http://haproxy:8404/stats;csv' | awk -F, '/ja4proxy/ {print "queue:", $3, "rate:", $46}'

# Block rate — is attack being mitigated?
docker exec proxy curl -s http://localhost:9090/metrics | grep 'ja4proxy_connections_total{action="block"}'
```

**Common causes:**
- DDoS attack with connection rate exceeding proxy capacity
- Attack of slow TLS handshakes (not completing quickly enough to free slots)
- Proxy dial too low to block fast — too many connections going through full scoring

**Resolution steps:**
1. This alert fires together with `ConnectionRateSpike` or `ConnectionRateSustainedHigh`. Follow those runbooks in parallel.
2. Raise dial immediately: if dial < 70, raise to 70 to enable blocking. Monitor false-positive rate in dashboard.
3. Enable HAProxy source IP rate limiting: add `stick-table type ip size 200k expire 30s store conn_rate(10s)` and ACL.
4. Check if the attack is from a small number of IPs: `docker exec redis redis-cli zrevrange beacon:suspects 0 9`.
5. If a JA4 fingerprint dominates, blacklist it: `docker exec redis redis-cli sadd ja4:blacklist <fingerprint>`.

**Escalation:** Escalate if queue above 50 connections — users are being impacted.

---

## disk-prediction

**Alert:** `DiskWillFillIn24h`

**What is firing:** Based on the 6-hour growth rate, a filesystem will run out of space within 24 hours.

**Immediate check:**
```bash
# Current growth rate
df -h
# Compare with 6h ago in Grafana or:
watch -n 60 "df -h | grep -v tmpfs"

# Identify growth source
du -sh /var/log/ja4proxy/ /var/lib/docker/volumes/redis-data/ /backups/
```

**Common causes:**
- Sustained attack generating high log volume
- Redis AOF growing rapidly (high ban/block write rate)
- Backup process creating files but retention cleanup failing
- Docker pulling new images without cleaning old ones

**Resolution steps:**
1. Act now, before the threshold alert fires. Identify the growing directory from `du` output.
2. If logs: verify logrotate is running on schedule: `systemctl status logrotate.timer`. Force rotation: `logrotate -f /etc/logrotate.d/ja4proxy`.
3. If Redis AOF: trigger a rewrite: `docker exec redis redis-cli bgrewriteaof`.
4. If backups: verify retention script: `ls -lt /backups/ | head -20`. Remove old backups manually if needed.
5. If Docker images: `docker image prune -a --filter "until=48h"`.

**Escalation:** Escalate if growth source cannot be controlled and disk will fill within 6 hours.

---

## redis-memory-growth

**Alert:** `RedisMemoryWillHitLimitIn1h`

**What is firing:** Redis memory working set is growing and is predicted to hit its configured limit within 1 hour.

**Immediate check:**
```bash
# Redis memory details
docker exec redis redis-cli info memory | grep -E "used_memory_human|maxmemory_human|maxmemory_policy|mem_fragmentation_ratio"

# Which key patterns are largest
docker exec redis redis-cli --bigkeys 2>&1 | tail -20

# Key count by prefix
docker exec redis redis-cli info keyspace
```

**Common causes:**
- Attack generating many unique IPs — each creates ban:, beacon:, and enrichment cache keys
- Bloom filter not working — duplicate enrichment lookups accumulating
- Sorted sets growing without TTL (beaconing timestamps not expiring)
- Return visitor hashes for millions of IPs not expiring

**Resolution steps:**
1. Check `maxmemory_policy`: if `noeviction`, change to `allkeys-lru` to allow graceful eviction: `docker exec redis redis-cli config set maxmemory-policy allkeys-lru`.
2. Check key TTLs for large key classes: `docker exec redis redis-cli ttl "beacon:192.168.1.1:t13d..."`.
3. If beaconing sorted sets are large: `docker exec redis redis-cli scan 0 match "beacon:*" count 100` — verify TTL is set.
4. Run memory defragmentation: `docker exec redis redis-cli memory purge`.
5. Increase maxmemory limit if workload is legitimate: `docker exec redis redis-cli config set maxmemory 4gb`.

**Escalation:** Escalate if eviction starts before you can increase the limit — eviction will degrade scoring accuracy.

---

## slo-burn

**Alert:** `ProxyAvailabilitySLOBurn`

**What is firing:** JA4proxy availability is burning the 30-day error budget at more than 14.4x the allowed rate.

**Immediate check:**
```bash
# Is proxy up right now?
curl -sv http://127.0.0.1:8080/health

# Scrape success rate in Prometheus
# Check: up{job="ja4proxy"} and avg_over_time(up{job="ja4proxy"}[5m])

# Recent proxy logs
docker logs proxy --tail 50
```

**Common causes:**
- Proxy returning 503 on `/health` intermittently (partial outage)
- Prometheus unable to scrape metrics endpoint (port blocked or endpoint down)
- Proxy restart loop creating periodic gaps in availability
- Health check endpoint timing out under high CPU load

**Resolution steps:**
1. Verify current proxy health: `curl -v http://127.0.0.1:8080/health` — look for HTTP 200 response.
2. If health returns 503: check `ja4proxy_active_connections` vs configured max. If at max, it is a capacity issue.
3. Check Prometheus scrape errors: `curl http://prometheus:9090/api/v1/targets` — look for `ja4proxy` target and `lastError`.
4. If intermittent: check proxy logs for `handle_connection` exceptions and asyncio timeouts.
5. If persistent: escalate to proxy down procedure (see `proxy_down.md` runbook).

**Escalation:** Escalate if availability below 99% over 5 minutes — SLO violation is material.

---

## connection-rate-spike

**Alert:** `ConnectionRateSpike`

**What is firing:** The connection rate is at least 3x the 1-hour rolling average for 2 minutes.

**Immediate check:**
```bash
# Live connection rate
docker exec proxy curl -s http://localhost:9090/metrics | grep 'ja4proxy_connections_total'

# Block/ban rate — is JA4proxy mitigating?
docker exec proxy curl -s http://localhost:9090/metrics | grep -E '"block"|"ban"'

# Top source IPs in Redis
docker exec redis redis-cli zrevrange beacon:suspects 0 9 withscores
```

**Common causes:**
- Coordinated bot attack from distributed IPs
- Automated scanner starting a campaign (search engine recrawl, security scanner)
- Legitimate traffic spike (marketing campaign, news coverage)
- CDN routing change sending more traffic to this node

**Resolution steps:**
1. Check block rate. If JA4proxy is blocking the spike: monitor and wait, proxy is doing its job.
2. If the spike is clean traffic (block rate unchanged): verify it is not an attack before raising the dial.
3. If attack indicators present (high ASN concentration, low TLS diversity): raise dial by 20 and monitor.
4. Check HAProxy queue depth — if queuing, proxy is at capacity, follow `haproxy-queue-attack`.
5. For distributed attacks with many unique IPs: enable country blocking if geography is concentrated.

**Escalation:** Escalate if block rate is not rising with connection rate (attack bypassing scoring), or if connection rate exceeds 500/s.

---

## connection-rate-sustained

**Alert:** `ConnectionRateSustainedHigh`

**What is firing:** Connection rate has been above 600/s for 5 continuous minutes — above Python proxy capacity.

**Immediate check:**
```bash
# Confirm rate
docker exec proxy curl -s http://localhost:9090/metrics | grep ja4proxy_connections_total | head -5

# HAProxy queue depth
curl -s 'http://haproxy:8404/stats;csv' | awk -F, '/ja4proxy/ && /BACKEND/ {print "queue:", $3}'

# Is Go proxy available?
ls /opt/ja4proxy/proxy-go 2>/dev/null && echo "Go binary present"
```

**Common causes:**
- DDoS attack exceeding Python proxy throughput ceiling
- Flash crowd / viral event (legitimate but overloading)
- HAProxy misconfiguration routing all traffic to a single proxy instance

**Resolution steps:**
1. Immediately enable HAProxy frontend rate limiting to shed load: `stick-table type ip size 200k expire 30s store conn_rate(10s)` with ACL blocking above 20/s per source IP.
2. If Go proxy is available, switch: `make switch-to-go` — handles ~10x more connections per CPU.
3. Add a second proxy instance to HAProxy backend pool to distribute load.
4. Raise dial to maximum to make blocking decisions as fast as possible (reduces time per connection).
5. If legitimate traffic: scale horizontally and add capacity. If attack: coordinate with upstream provider for BGP null route or scrubbing center.

**Escalation:** Immediate escalation. Python proxy is degraded at this rate. If no Go proxy and no capacity to scale, contact upstream ISP for DDoS mitigation.

---

## syn-flood

**Alert:** `SYNFloodIndicator`

**What is firing:** Average inbound packet size has dropped below 150 bytes — consistent with a SYN flood.

**Immediate check:**
```bash
# TCP connection attempt failures (SYNs with no ACK)
cat /proc/net/netstat | grep -i "syncookies\|AttemptFails"

# NIC drop counters
ip -s link show eth0 | grep -A2 "RX:"

# SYN backlog
ss -s | grep SYN
```

**Common causes:**
- SYN flood attack (attacker sending SYN packets with spoofed source IPs, never completing handshake)
- Small-packet UDP amplification attack reflected at this host
- Port scanner sending SYN probes at high rate without completing handshakes

**Resolution steps:**
1. Enable SYN cookies immediately if not already: `sysctl -w net.ipv4.tcp_syncookies=1`.
2. Increase SYN backlog: `sysctl -w net.ipv4.tcp_max_syn_backlog=8192 net.core.somaxconn=8192`.
3. Reduce SYN retries to expire half-open connections faster: `sysctl -w net.ipv4.tcp_synack_retries=2`.
4. Add iptables rate limit for SYN packets: `iptables -A INPUT -p tcp --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT && iptables -A INPUT -p tcp --syn -j DROP`.
5. Contact upstream ISP if volume exceeds what iptables can handle — request BGP blackhole or scrubbing.

**Escalation:** Escalate immediately to network/ISP team. SYN floods require upstream mitigation if volumetric.

---

## time-wait-spike

**Alert:** `TimeWaitSpike`

**What is firing:** TCP TIME_WAIT socket count has exceeded 5000 — indicating rapid connection churn.

**Immediate check:**
```bash
# TIME_WAIT count breakdown
ss -s | grep -i "time-wait"

# Connection rate trend
docker exec proxy curl -s http://localhost:9090/metrics | grep ja4proxy_connections_total

# Source IP distribution of TIME_WAIT sockets
ss -n state time-wait | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
```

**Common causes:**
- Rapid attack with many short-lived connections
- Legitimate high-throughput client making many connections without HTTP keep-alive
- SYN flood precursor — attacker testing before full flood
- Application not using connection pooling (e.g. each Redis call opens new TCP connection)

**Resolution steps:**
1. Enable TIME_WAIT socket reuse to recycle sockets faster: `sysctl -w net.ipv4.tcp_tw_reuse=1`.
2. Reduce TIME_WAIT duration: `sysctl -w net.ipv4.tcp_fin_timeout=15`.
3. Increase local port range for outbound connections: `sysctl -w net.ipv4.ip_local_port_range="1024 65535"`.
4. Check if a small set of IPs are generating the churn — if so, rate-limit or ban those IPs in HAProxy.
5. Monitor for ConnectionRateSpike — TIME_WAIT spikes often precede a full attack by 1-2 minutes.

**Escalation:** Escalate if TIME_WAIT above 20,000 — OS is approaching ephemeral port exhaustion.

---

## nic-drops

**Alert:** `NICPacketDrops`

**What is firing:** The NIC is dropping more than 100 packets per second at the ring buffer level.

**Immediate check:**
```bash
# NIC queue and drop statistics
ethtool -S eth0 | grep -i "drop\|miss\|error" | grep -v " 0$"

# Interrupt distribution across CPUs
cat /proc/interrupts | grep eth0

# NIC ring buffer sizes
ethtool -g eth0
```

**Common causes:**
- Attack volume exceeding NIC ring buffer capacity
- NIC interrupt handling pinned to a single CPU (IRQ affinity not spread)
- NIC ring buffer too small for the traffic burst
- Kernel receiving more traffic than it can process (softirq backlog)

**Resolution steps:**
1. Increase NIC ring buffer size: `ethtool -G eth0 rx 4096 tx 4096`.
2. Spread NIC interrupts across all CPUs using `irqbalance`: `systemctl enable --now irqbalance`.
3. Enable Receive Packet Steering (RPS) to distribute processing: `echo "ff" > /sys/class/net/eth0/queues/rx-0/rps_cpus`.
4. If volume is exceeding NIC capacity entirely, contact ISP for upstream rate limiting or scrubbing.
5. Check if receive offloads are enabled: `ethtool -k eth0 | grep "receive-offload"`.

**Escalation:** Escalate to ISP if drops persist after NIC tuning — true volumetric floods require upstream mitigation.

---

## distributed-attack

**Alert:** `NewUniqueIPsBurst`

**What is firing:** More than 50 new unique source IPs per second have been seen for 3 minutes — indicating a distributed attack.

**Immediate check:**
```bash
# Beaconing suspects leaderboard
docker exec redis redis-cli zrevrange beacon:suspects 0 19 withscores

# ASN distribution of recent connections
docker exec proxy curl -s http://localhost:9090/metrics | grep ja4proxy_asn

# Campaign detector findings
docker exec redis redis-cli keys "analytics:campaign:*" | head -20
```

**Common causes:**
- Coordinated botnet campaign with rotating IPs
- Distributed scanner (e.g. Censys, Shodan, or threat actor using cloud IPs)
- Multiple autonomous scanners starting simultaneously (scan-campaign coordination)
- Large residential proxy pool being used for evasion

**Resolution steps:**
1. Check ASN concentration: if most IPs are from a few ASNs, consider ASN-level blocking via config.
2. Check JA4 fingerprint diversity: if the same JA4 appears across all IPs, blacklist that fingerprint.
3. Check campaign detector: `docker exec redis redis-cli get analytics:campaign:active`.
4. If geography is concentrated: enable country blocking in `config/proxy.yml` for affected countries.
5. Raise dial by 20 — distributed attacks with many IPs will have lower per-IP scores, so raising the threshold is needed.

**Escalation:** Escalate if the attack rate is above 200 unique IPs/second or if JA4 fingerprint diversity prevents fingerprint-based blocking. Coordinate with ISP for BGP-level countermeasures.
