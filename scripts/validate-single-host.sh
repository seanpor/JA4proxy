#!/usr/bin/env bash
# JA4proxy single-host deployment validator (phase-231b real-host E2E).
#
# This is the validation that CANNOT run in CI or the dev sandbox — it needs an
# actual deployed host (a clean VM is ideal). It checks the things `bootstrap.sh`
# wires up: the systemd service, .env secret hygiene, the firewall posture
# (public 443, admin ports loopback-only), logrotate, the backup cron, and the
# safe monitor-mode default.
#
# Run it in three contexts:
#
#   1. On the deployed host, AFTER `sudo ./scripts/bootstrap.sh`:
#        sudo ./scripts/validate-single-host.sh
#
#   2. From a SEPARATE client machine (the firewall-from-remote check — the one
#      thing you can only verify off-box):
#        ./scripts/validate-single-host.sh --from-remote <host-or-ip>
#
#   3. On an air-gapped host, to prove the offline image bundle loads:
#        ./scripts/validate-single-host.sh --offline-tarball ./ja4proxy-offline.tar.gz
#
# Exit code is non-zero if any non-SKIP check FAILs, so it doubles as a smoke gate.
#
# It is read-only except for the backup-cron check, which runs the backup script
# once (it only writes a dated tar.gz into the backup dir) — and --offline-tarball,
# which runs `docker load`.
set -uo pipefail

# ── deployment paths / ports (match bootstrap.sh defaults; .env overrides) ──────
ROOT="${ROOT:-/opt/ja4proxy}"
LOG_DIR="${LOG_DIR:-/var/log/ja4proxy}"
BACKUP_DIR="${BACKUP_DIR:-/backup/ja4proxy}"
ENV_FILE="$ROOT/.env"

PASS=0; FAIL=0; SKIP=0
green() { printf '  \033[32m✓ PASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
red()   { printf '  \033[31m✗ FAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip()  { printf '  \033[33m• SKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# Read a single KEY=value from .env without sourcing the whole file.
env_get() { [ -f "$ENV_FILE" ] && sed -nE "s/^$1=(.*)$/\1/p" "$ENV_FILE" | head -1; }

tcp_open() {  # tcp_open host port timeout → 0 if a TCP connect succeeds
  timeout "${3:-5}" bash -c ">/dev/tcp/$1/$2" 2>/dev/null
}

# ── on-host validation ──────────────────────────────────────────────────────────
validate_on_host() {
  [ "$(id -u)" -eq 0 ] || echo "NOTE: run with sudo for the journal/firewall checks to be reliable." >&2

  head_ "1. systemd service"
  if systemctl is-active --quiet ja4proxy.service; then green "ja4proxy.service is active"
  else red "ja4proxy.service is not active (systemctl status ja4proxy.service)"; fi
  if systemctl is-enabled --quiet ja4proxy.service; then green "ja4proxy.service is enabled (will start on boot)"
  else red "ja4proxy.service is not enabled — it won't survive a reboot"; fi

  head_ "2. .env secret hygiene"
  if [ -f "$ENV_FILE" ]; then
    local mode; mode="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null)"
    if [ "$mode" = "600" ] || [ "$mode" = "640" ]; then green ".env perms are $mode (not world/group-readable)"
    else red ".env perms are $mode — must be 600 (chmod 600 $ENV_FILE)"; fi
    # No secret value should have leaked into the service journal.
    local leaked=0 v
    for k in REDIS_PASSWORD ANALYTICS_REDIS_PASSWORD MANAGEMENT_ADMIN_PASSWORD MANAGEMENT_JWT_SECRET GRAFANA_ADMIN_PASSWORD; do
      v="$(env_get "$k")"
      [ -z "$v" ] || [ "$v" = "REPLACE_ME_SECURELY" ] && continue
      if journalctl -u ja4proxy.service --no-pager -q 2>/dev/null | grep -qF -- "$v"; then
        red "secret $k value appears in the service journal"; leaked=1
      fi
    done
    [ "$leaked" -eq 0 ] && green "no .env secret values found in the service journal"
  else
    red "no .env at $ENV_FILE (was bootstrap.sh run?)"
  fi

  head_ "3. network posture (public ingress vs loopback admin)"
  local ingress; ingress="$(env_get HOST_PORT_INGRESS)"; ingress="${ingress:-443}"
  if ss -ltnH 2>/dev/null | grep -qE "[:.]${ingress}\b"; then green "ingress port $ingress is listening"
  else red "nothing is listening on ingress port $ingress"; fi
  local mgmt met prom graf
  mgmt="$(env_get HOST_PORT_MANAGEMENT)"; mgmt="${mgmt:-8090}"
  met="$(env_get HOST_PORT_METRICS)"; met="${met:-9090}"
  prom="$(env_get HOST_PORT_PROMETHEUS)"; prom="${prom:-9091}"
  graf="$(env_get HOST_PORT_GRAFANA)"; graf="${graf:-3000}"
  for p in "$mgmt" "$met" "$prom" "$graf"; do
    local line; line="$(ss -ltnH 2>/dev/null | grep -E "[:.]${p}\b")"
    if [ -z "$line" ]; then skip "admin port $p not listening (service may be off, or container-internal only)"
    elif echo "$line" | grep -qE "0\.0\.0\.0:${p}|\*:${p}|\[::\]:${p}"; then
      red "admin port $p is bound to a PUBLIC interface — must be 127.0.0.1 only"
    else green "admin port $p bound to loopback only"; fi
  done

  head_ "4. firewall gating"
  if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -qE "\b(80|443)\b.*ALLOW"; then green "ufw allows 80/443"
    else skip "ufw active but no explicit 80/443 ALLOW seen (check 'ufw status')"; fi
    if ufw status 2>/dev/null | grep -qE "\b(${mgmt}|${met}|${prom}|${graf})\b.*DENY"; then green "ufw denies admin ports externally"
    else red "ufw does not DENY admin ports ($mgmt $met $prom $graf) — bootstrap should have added these"; fi
  elif command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --list-services 2>/dev/null | grep -qE "http|https"; then green "firewalld permits http/https"
    else red "firewalld does not permit http/https"; fi
    skip "firewalld: admin ports rely on loopback binding (verify section 3 PASSed)"
  else
    red "no ufw/firewalld present — firewall posture cannot be verified"
  fi

  head_ "5. logrotate"
  if [ -f /etc/logrotate.d/ja4proxy ]; then
    if logrotate -d /etc/logrotate.d/ja4proxy >/dev/null 2>&1; then green "logrotate config present and parses clean"
    else red "logrotate config present but fails 'logrotate -d' (syntax error)"; fi
  else red "/etc/logrotate.d/ja4proxy missing"; fi

  head_ "6. daily backup cron"
  if [ -f /etc/cron.d/ja4proxy-backup ] && [ -x /usr/local/bin/ja4proxy-backup.sh ]; then
    green "backup cron + script installed"
    local before after
    before="$(find "$BACKUP_DIR" -name 'ja4proxy-*.tar.gz' 2>/dev/null | wc -l)"
    if /usr/local/bin/ja4proxy-backup.sh >/dev/null 2>&1; then
      after="$(find "$BACKUP_DIR" -name 'ja4proxy-*.tar.gz' 2>/dev/null | wc -l)"
      if [ "$after" -gt "$before" ]; then green "backup script produced a new archive in $BACKUP_DIR"
      else red "backup script ran but no new archive appeared in $BACKUP_DIR"; fi
    else red "backup script exited non-zero"; fi
  else red "backup cron or /usr/local/bin/ja4proxy-backup.sh missing"; fi

  head_ "7. safe-by-default (monitor mode)"
  local rpass; rpass="$(env_get REDIS_PASSWORD)"
  if command -v redis-cli >/dev/null 2>&1 && [ -n "$rpass" ] && [ "$rpass" != "REPLACE_ME_SECURELY" ]; then
    local dial; dial="$(redis-cli -a "$rpass" --no-auth-warning GET dial 2>/dev/null)"
    if [ "$dial" = "0" ] || [ -z "$dial" ]; then green "dial is monitor mode (dial=${dial:-unset/0}) — never blocks on first deploy"
    else red "dial=$dial — NOT monitor mode; confirm this was a conscious choice"; fi
  else
    skip "cannot read dial via redis-cli — confirm dial=0 (monitor mode) in the Management UI"
  fi

  head_ "Manual steps this script can't do for you"
  echo "  • Reboot persistence: 'sudo reboot', then re-run this script — section 1 must still PASS."
  echo "  • Firewall from OUTSIDE: run '--from-remote <this-host-ip>' from a different machine."
  echo "  • Uninstall hygiene: 'sudo ./scripts/bootstrap.sh --uninstall', then confirm no"
  echo "    ja4proxy units/dirs/cron remain (backups under $BACKUP_DIR are intentionally kept)."
}

# ── firewall-from-remote (run on a SEPARATE machine) ─────────────────────────────
validate_from_remote() {
  local target="$1"
  head_ "Firewall posture from a remote client → $target"
  local ingress="${HOST_PORT_INGRESS:-443}"
  if tcp_open "$target" "$ingress" 5; then green "ingress $ingress is reachable (public service works)"
  else red "ingress $ingress is NOT reachable from here — the proxy isn't public"; fi
  for p in "${HOST_PORT_MANAGEMENT:-8090}" "${HOST_PORT_METRICS:-9090}" "${HOST_PORT_PROMETHEUS:-9091}" "${HOST_PORT_GRAFANA:-3000}"; do
    if tcp_open "$target" "$p" 3; then red "admin port $p is REACHABLE from outside — must be firewalled/loopback"
    else green "admin port $p is not reachable from outside (correct)"; fi
  done
}

# ── offline tarball load (air-gapped host) ───────────────────────────────────────
validate_offline_tarball() {
  local bundle="$1"
  head_ "Offline image bundle → $bundle"
  command -v docker >/dev/null 2>&1 || { red "docker not present"; return; }
  [ -f "$bundle" ] || { red "bundle not found: $bundle"; return; }
  if docker load -i "$bundle" >/dev/null 2>&1; then green "docker load succeeded (no network egress)"
  else red "docker load failed"; return; fi
  if docker image inspect ja4proxy:2.0.0 >/dev/null 2>&1; then green "ja4proxy:2.0.0 image present after load"
  else red "ja4proxy:2.0.0 not present after load"; fi
}

summary() {
  head_ "Result"
  printf '  PASS=%d  FAIL=%d  SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
  [ "$FAIL" -eq 0 ] && { echo "  ✅ single-host deployment validated"; exit 0; } || { echo "  ❌ validation failed — see FAILs above"; exit 1; }
}

main() {
  case "${1:-}" in
    --from-remote)     [ -n "${2:-}" ] || { echo "usage: $0 --from-remote <host-or-ip>"; exit 2; }; validate_from_remote "$2" ;;
    --offline-tarball) [ -n "${2:-}" ] || { echo "usage: $0 --offline-tarball <path>"; exit 2; }; validate_offline_tarball "$2" ;;
    "" )               validate_on_host ;;
    -h|--help)         sed -n '2,40p' "$0"; exit 0 ;;
    *)                 echo "unknown option: $1 (try --help)"; exit 2 ;;
  esac
  summary
}

main "$@"
