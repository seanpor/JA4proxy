#!/usr/bin/env bash
#
# spin-test-vm.sh — rebuild a throwaway Ubuntu VM for single-host (phase-231b)
# deployment testing, in ONE command, with NO host sudo.
#
# Why this exists
# ---------------
# The phase-231b bootstrapper (`scripts/bootstrap.sh`) is root-level and
# destructive — it installs system packages, writes systemd units, and edits the
# firewall. You must never run it on your workstation; it needs a disposable
# host. This script builds that host locally as a KVM-accelerated QEMU VM that
# runs *inside a Docker container*, so it needs only Docker group membership
# (which you already have) and a working /dev/kvm — no `sudo` on the host.
#
# It is the committed, reproducible form of the ad-hoc VM used to find and fix
# the 8 native-mode bugs in phase-231b. Pair it with
# `scripts/validate-single-host.sh`, which runs the 12 post-deploy checks.
#
# Quick start
# -----------
#   scripts/dev/spin-test-vm.sh up          # download image, boot VM, wait for SSH
#   scripts/dev/spin-test-vm.sh ssh         # shell into the VM
#   scripts/dev/spin-test-vm.sh push        # rsync this repo into the VM (~/JA4proxy)
#   scripts/dev/spin-test-vm.sh ssh 'cd JA4proxy && sudo ./scripts/bootstrap.sh --mode native --non-interactive'
#   scripts/dev/spin-test-vm.sh ssh 'cd JA4proxy && sudo ./scripts/validate-single-host.sh'
#   scripts/dev/spin-test-vm.sh down        # stop + remove the container (keeps disk)
#   scripts/dev/spin-test-vm.sh destroy      # stop + delete the VM dir entirely
#
# Requirements: docker (in your PATH, your user in the `docker` group) and
# /dev/kvm present. Everything else (qemu, cloud-init tooling) runs inside
# throwaway Alpine containers — nothing is installed on the host.
#
set -euo pipefail

# ----------------------------------------------------------------------------
# Tunables (override via env)
# ----------------------------------------------------------------------------
VM_DIR="${VM_DIR:-$HOME/vms/ja4test}"     # where the disk + seed + console log live
VM_NAME="${VM_NAME:-ja4-testvm}"          # docker container name
VM_CPUS="${VM_CPUS:-4}"                   # vCPUs
VM_MEM_MB="${VM_MEM_MB:-8192}"            # RAM (MiB)
VM_DISK_GB="${VM_DISK_GB:-20}"            # root disk size (GiB)
SSH_PORT="${SSH_PORT:-2222}"              # host port forwarded to guest :22
SSH_USER="${SSH_USER:-sean}"             # login user created by cloud-init
# Ubuntu 24.04 LTS (noble) minimal cloud image — qcow2, cloud-init enabled.
IMAGE_URL="${IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
# Small Alpine image used as the qemu/iso toolbox.
TOOLBOX="${TOOLBOX:-alpine:3.20}"

BASE_IMG="$VM_DIR/base.img"
DISK="$VM_DIR/disk.qcow2"
CONSOLE="$VM_DIR/console.log"
SSH_KEY="$VM_DIR/id_ed25519"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

preflight() {
    command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
    docker info >/dev/null 2>&1 || die "cannot talk to docker (are you in the 'docker' group?)"
    [ -e /dev/kvm ] || die "/dev/kvm not present — KVM acceleration unavailable"
    mkdir -p "$VM_DIR"
}

# Run a one-shot Alpine toolbox container with the VM dir mounted at /vm.
toolbox() {
    docker run --rm -v "$VM_DIR:/vm" "$TOOLBOX" sh -ec "$1"
}

ensure_ssh_key() {
    if [ ! -f "$SSH_KEY" ]; then
        log "Generating throwaway SSH keypair at $SSH_KEY"
        ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C "ja4-testvm" >/dev/null
    fi
}

build_disk() {
    if [ ! -f "$BASE_IMG" ]; then
        log "Downloading Ubuntu cloud image (cached at $BASE_IMG)"
        # Download inside the toolbox so the host needs no curl/wget.
        toolbox "apk add --no-cache curl >/dev/null && curl -fSL '$IMAGE_URL' -o /vm/base.img"
    fi
    log "Creating ${VM_DISK_GB}G overlay disk"
    # Fresh copy each boot so the VM is genuinely throwaway; resize to target.
    toolbox "apk add --no-cache qemu-img >/dev/null \
        && cp /vm/base.img /vm/disk.qcow2 \
        && qemu-img resize /vm/disk.qcow2 ${VM_DISK_GB}G >/dev/null"
}

build_seed() {
    local pub; pub="$(cat "${SSH_KEY}.pub")"
    log "Writing cloud-init seed (user '$SSH_USER', key-only SSH)"
    cat > "$VM_DIR/user-data" <<EOF
#cloud-config
hostname: ja4test
manage_etc_hosts: true
users:
  - name: ${SSH_USER}
    groups: [sudo]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ${pub}
ssh_pwauth: false
package_update: true
packages:
  - rsync
  - curl
  - ca-certificates
EOF
    cat > "$VM_DIR/meta-data" <<EOF
instance-id: ja4test
local-hostname: ja4test
EOF
    # NoCloud requires an ISO labelled CIDATA holding user-data + meta-data.
    toolbox "apk add --no-cache xorriso >/dev/null \
        && xorriso -as mkisofs -quiet -V CIDATA -J -r \
             -o /vm/seed.iso /vm/user-data /vm/meta-data"
}

boot() {
    if docker ps -a --format '{{.Names}}' | grep -qx "$VM_NAME"; then
        log "Removing existing container $VM_NAME"
        docker rm -f "$VM_NAME" >/dev/null
    fi
    : > "$CONSOLE"
    log "Booting VM ($VM_CPUS vCPU, ${VM_MEM_MB}MiB, ssh→localhost:$SSH_PORT)"
    docker run -d --name "$VM_NAME" \
        --device /dev/kvm \
        -v "$VM_DIR:/vm" \
        -p "127.0.0.1:${SSH_PORT}:22" \
        "$TOOLBOX" sh -ec "
            apk add --no-cache qemu-system-x86_64 >/dev/null
            exec qemu-system-x86_64 \
                -enable-kvm -cpu host \
                -smp ${VM_CPUS} -m ${VM_MEM_MB} \
                -drive file=/vm/disk.qcow2,if=virtio,format=qcow2 \
                -drive file=/vm/seed.iso,if=virtio,format=raw,readonly=on \
                -netdev user,id=n0,hostfwd=tcp:0.0.0.0:22-:22 \
                -device virtio-net,netdev=n0 \
                -nographic -serial file:/vm/console.log
        " >/dev/null
}

wait_for_ssh() {
    log "Waiting for SSH (first boot runs cloud-init; up to ~3 min)…"
    for _ in $(seq 1 90); do
        if ssh_run true 2>/dev/null; then
            log "VM is up. SSH: $0 ssh"
            return 0
        fi
        sleep 2
    done
    err "VM did not become reachable in time. Last console lines:"
    tail -n 25 "$CONSOLE" >&2 || true
    return 1
}

ssh_opts() {
    printf '%s' "-i $SSH_KEY -p $SSH_PORT \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=5"
}

ssh_run() {
    # shellcheck disable=SC2046
    ssh $(ssh_opts) "${SSH_USER}@127.0.0.1" "$@"
}

cmd_up() {
    preflight; ensure_ssh_key; build_disk; build_seed; boot; wait_for_ssh
}

cmd_ssh() {
    [ -f "$SSH_KEY" ] || die "no VM key — run '$0 up' first"
    if [ "$#" -eq 0 ]; then ssh_run; else ssh_run "$@"; fi
}

cmd_push() {
    local root; root="$(cd "$(dirname "$0")/../.." && pwd)"
    log "rsync $root → ${SSH_USER}@vm:~/JA4proxy (excludes .git, bin, node_modules)"
    rsync -az --delete \
        --exclude '.git' --exclude 'bin' --exclude 'node_modules' \
        --exclude '.local' --exclude 'test-results' \
        -e "ssh $(ssh_opts)" \
        "$root/" "${SSH_USER}@127.0.0.1:JA4proxy/"
}

cmd_status() {
    docker ps -a --filter "name=$VM_NAME" --format \
        'container: {{.Names}}  state: {{.Status}}' || true
    [ -f "$DISK" ] && log "disk: $DISK ($(du -h "$DISK" | cut -f1))"
    log "console log: $CONSOLE"
}

cmd_down() {
    docker rm -f "$VM_NAME" >/dev/null 2>&1 && log "stopped + removed $VM_NAME" \
        || log "no running container"
}

cmd_destroy() {
    cmd_down
    log "deleting $VM_DIR"
    rm -rf "$VM_DIR"
}

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
}

case "${1:-up}" in
    up)       cmd_up ;;
    ssh)      shift; cmd_ssh "$@" ;;
    push)     cmd_push ;;
    status)   cmd_status ;;
    down)     cmd_down ;;
    destroy)  cmd_destroy ;;
    -h|--help|help) usage ;;
    *) die "unknown command '${1}' (try: up | ssh | push | status | down | destroy)" ;;
esac
