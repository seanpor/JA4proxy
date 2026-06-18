#!/usr/bin/env bash
# JA4proxy single-host bootstrapper (phase-231b / phase-332).
#
# Zero-compile installer for a clean Linux host (Ubuntu/Debian or RHEL/Rocky):
# installs *runtime* deps only, creates the service user + dirs, runs the
# Go-native setup wizard (`ja4p init`) to generate .env (secrets, chmod 600
# — never echoed), installs the systemd unit + logrotate + a daily backup
# cron, and gates the firewall so only 80/443 are public while admin ports
# (read from .env) stay on loopback.
#
# Usage:
#   sudo ./scripts/bootstrap.sh [--mode native|container] [--root /opt/ja4proxy]
#   sudo ./scripts/bootstrap.sh --non-interactive  # unattended (wizard takes defaults)
#   sudo ./scripts/bootstrap.sh --check       # dry-run diagnostics
#   sudo ./scripts/bootstrap.sh --uninstall   # remove (prompts before volumes)
#
# SECURITY (JA4PROXY-2026-0040): never echo secrets. Production hosts get NO
# compiler/build tooling (binaries/images are pre-built and copied or loaded).
set -euo pipefail

MODE="container"
ROOT="/opt/ja4proxy"
ACTION="install"
NONINTERACTIVE="false"
SVC_USER="ja4proxy"
LOG_DIR="/var/log/ja4proxy"
BACKUP_DIR="/backup/ja4proxy"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[0;34m▶\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m✓\033[0m %s\n' "$*"; }
err()  { printf '\033[0;31m✗\033[0m %s\n' "$*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --root) ROOT="$2"; shift 2 ;;
    --check) ACTION="check"; shift ;;
    --uninstall) ACTION="uninstall"; shift ;;
    --non-interactive|--yes) NONINTERACTIVE="true"; shift ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) err "unknown argument: $1"; exit 2 ;;
  esac
done

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt"
  elif command -v dnf >/dev/null 2>&1; then echo "dnf"
  else echo "unknown"; fi
}

assert_zero_compile() {
  # Production hosts must not carry build tooling; we copy/load pre-built artifacts.
  for t in gcc g++ clang make go; do
    if command -v "$t" >/dev/null 2>&1; then
      err "compiler/build tool present on host: $t — production hosts must be zero-compile"
      err "(install pre-built ja4pd/ja4p binaries or load ja4proxy-offline.tar.gz instead)"
      return 1
    fi
  done
  ok "zero-compile host verified (no gcc/clang/make/go)"
}

install_runtime_deps() {
  local mgr; mgr="$(detect_pkg_mgr)"
  log "installing runtime dependencies via $mgr"
  # Native mode runs Redis on the host (the systemd unit orders after
  # redis-server.service); container mode gets Redis from compose.
  local pkgs_apt="openssl" pkgs_dnf="openssl"
  if [ "$MODE" = "native" ]; then
    pkgs_apt="openssl redis-server"
    pkgs_dnf="openssl redis"
  fi
  case "$mgr" in
    apt) apt-get update -qq && apt-get install -y --no-install-recommends $pkgs_apt ;;
    dnf) dnf install -y $pkgs_dnf ;;
    *) err "unsupported package manager (need apt or dnf)"; return 1 ;;
  esac
  if [ "$MODE" = "container" ] && ! command -v docker >/dev/null 2>&1; then
    err "container mode needs Docker — install docker-ce + the compose plugin first"
    return 1
  fi
  ok "runtime dependencies present"
}

create_user_and_dirs() {
  if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
    ok "created system user $SVC_USER"
  fi
  install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$ROOT" "$LOG_DIR" "$BACKUP_DIR"
  ok "directories ready: $ROOT $LOG_DIR $BACKUP_DIR"
}

load_offline_images() {
  local bundle="$HERE/ja4proxy-offline.tar.gz"
  if [ "$MODE" = "container" ] && [ -f "$bundle" ]; then
    log "loading offline image bundle (no network egress)"
    docker load -i "$bundle"
    ok "offline images loaded"
  fi
}

run_wizard() {
  log "launching Go-native setup wizard (generates .env + proxy.yml + systemd unit; secrets never echoed)"
  local -a args=(init)
  if [ "$NONINTERACTIVE" = "true" ]; then
    # Unattended install: accept defaults, pass the chosen deployment mode.
    args+=(--non-interactive --lane 0 --mode "$MODE")
  fi
  if [ "$MODE" = "native" ]; then
    ( cd "$ROOT" && "$ROOT/bin/ja4p" "${args[@]}" )
  else
    local dockerit="-it"
    [ "$NONINTERACTIVE" = "true" ] && dockerit="-i"
    docker run --rm "$dockerit" \
      -v "$ROOT:$ROOT" \
      -v /etc/systemd/system:/etc/systemd/system \
      -w "$ROOT" \
      ja4proxy:2.0.0 \
      ja4p "${args[@]}"
  fi
  chown "$SVC_USER:$SVC_USER" "$ROOT/.env" 2>/dev/null || true
}

install_logrotate() {
  cat > /etc/logrotate.d/ja4proxy <<EOF
$LOG_DIR/*.log {
    size 10M
    rotate 3
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
  ok "logrotate configured (size 10M, keep 3)"
}

install_backup_cron() {
  cat > /usr/local/bin/ja4proxy-backup.sh <<EOF
#!/usr/bin/env bash
# Daily out-of-band backup of the Redis dump + config (phase-231b).
set -euo pipefail
ts=\$(date +%Y%m%d-%H%M%S)
tar -czf "$BACKUP_DIR/ja4proxy-\$ts.tar.gz" -C "$ROOT" config .env 2>/dev/null || true
find "$BACKUP_DIR" -name 'ja4proxy-*.tar.gz' -mtime +14 -delete
EOF
  chmod 0750 /usr/local/bin/ja4proxy-backup.sh
  echo "30 3 * * * $SVC_USER /usr/local/bin/ja4proxy-backup.sh" > /etc/cron.d/ja4proxy-backup
  ok "daily backup cron installed (03:30; 14-day retention; plain tar.gz — not encrypted)"
}

configure_firewall() {
  # Public: 80/443. Admin ports come from .env (HOST_PORT_*) and bind to loopback.
  # shellcheck disable=SC1091
  [ -f "$ROOT/.env" ] && . "$ROOT/.env"
  local admin_ports="${HOST_PORT_MANAGEMENT:-8090} ${HOST_PORT_METRICS:-9090} ${HOST_PORT_PROMETHEUS:-9091} ${HOST_PORT_GRAFANA:-3000}"
  if command -v ufw >/dev/null 2>&1; then
    # Allow SSH first so enabling the firewall never locks the operator out.
    ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
    ufw allow 80/tcp; ufw allow 443/tcp
    for p in $admin_ports; do ufw deny "$p"/tcp; done
    # Activate it — configured-but-disabled rules are a false sense of security.
    ufw --force enable
    ok "ufw: enabled; 80/443 public; admin ports denied externally ($admin_ports)"
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-service=http --add-service=https
    firewall-cmd --reload
    ok "firewalld: http/https public; bind admin services to 127.0.0.1 in compose ($admin_ports)"
  else
    err "no ufw/firewalld found — restrict admin ports ($admin_ports) to loopback manually"
  fi
}

enable_service() {
  systemctl daemon-reload
  systemctl enable --now ja4proxy.service
  ok "ja4proxy.service enabled and started"
}

check_one() {  # check_one <test-cmd-ok?> <ok-msg> <err-msg>
  if eval "$1" >/dev/null 2>&1; then ok "$2"; else err "$3"; fi
}

do_check() {
  log "diagnostics (dry-run)"
  if [ "$MODE" = "container" ]; then
    check_one "command -v docker" "docker present" "docker missing"
    check_one "docker image inspect ja4proxy:2.0.0 >/dev/null 2>&1" "ja4proxy:2.0.0 image present" "ja4proxy:2.0.0 image missing (load offline tarball or pull)"
  else
    check_one "[ -x '$ROOT/bin/ja4pd' ]" "ja4pd binary present" "ja4pd binary missing at $ROOT/bin/ja4pd"
    check_one "[ -x '$ROOT/bin/ja4p' ]" "ja4p binary present" "ja4p binary missing at $ROOT/bin/ja4p"
  fi
  check_one "[ -f '$ROOT/.env' ]" ".env present at $ROOT/.env" "no .env at $ROOT/.env (run without --check first)"
  check_one "systemctl is-enabled ja4proxy.service" "systemd unit enabled" "systemd unit not enabled"
}

do_uninstall() {
  log "uninstalling JA4proxy"
  systemctl disable --now ja4proxy.service 2>/dev/null || true
  rm -f /etc/systemd/system/ja4proxy.service /etc/logrotate.d/ja4proxy \
        /etc/cron.d/ja4proxy-backup /usr/local/bin/ja4proxy-backup.sh
  systemctl daemon-reload 2>/dev/null || true
  if [ "$MODE" = "container" ]; then
    printf 'Purge docker volumes (DESTROYS Redis/state)? [y/N] '; read -r ans
    [ "${ans:-N}" = "y" ] && docker compose -f "$ROOT/deploy/docker/docker-compose.poc.yml" down -v || true
  fi
  rm -rf "$ROOT" "$LOG_DIR"
  ok "removed units, dirs, and cron (backups under $BACKUP_DIR kept)"
}

main() {
  case "$ACTION" in
    check) do_check ;;
    uninstall) do_uninstall ;;
    install)
      [ "$(id -u)" -eq 0 ] || { err "install must run as root (sudo)"; exit 1; }
      [ "${ENVIRONMENT:-production}" = "production" ] && assert_zero_compile
      install_runtime_deps
      create_user_and_dirs
      load_offline_images
      run_wizard
      install_logrotate
      install_backup_cron
      configure_firewall
      enable_service
      ok "JA4proxy installed. It starts in MONITOR mode (dial=0) — raise the dial"
      ok "via the Management UI once you've confirmed legitimate traffic flows."
      ;;
  esac
}

main
