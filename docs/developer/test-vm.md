<!--
title: Throwaway test VM for single-host deployment
audience: developer
last_reviewed: 2026-06-19
phase: v2.0
-->

# Throwaway test VM (`scripts/dev/spin-test-vm.sh`)

The phase-231b bootstrapper (`scripts/bootstrap.sh`) is **root-level and
destructive** — it installs system packages, writes a systemd unit, and edits
the firewall. Never run it on your workstation. `spin-test-vm.sh` builds a
disposable Ubuntu host to run it against, in one command, **without host
`sudo`**.

## How it works

The VM is a KVM-accelerated QEMU guest that runs **inside a Docker container**.
That means it needs only:

- Docker, with your user in the `docker` group (you already have this), and
- a working `/dev/kvm`.

QEMU and the cloud-init ISO tooling run inside throwaway Alpine containers, so
**nothing is installed on the host**. The guest is an Ubuntu 24.04 cloud image;
a NoCloud `seed.iso` (label `CIDATA`) injects a `sudo`-capable, key-only login
user on first boot. SSH is forwarded to `127.0.0.1:2222`.

## Usage

```bash
scripts/dev/spin-test-vm.sh up        # download image, boot VM, wait for SSH
scripts/dev/spin-test-vm.sh push      # rsync this repo into the VM (~/JA4proxy)

# Run the destructive bootstrapper + the post-deploy validator on the VM:
scripts/dev/spin-test-vm.sh ssh 'cd JA4proxy && sudo ./scripts/bootstrap.sh --mode native --non-interactive'
scripts/dev/spin-test-vm.sh ssh 'cd JA4proxy && sudo ./scripts/validate-single-host.sh'

scripts/dev/spin-test-vm.sh ssh       # interactive shell
scripts/dev/spin-test-vm.sh status    # container + disk state
scripts/dev/spin-test-vm.sh down      # stop + remove container (keeps disk)
scripts/dev/spin-test-vm.sh destroy   # stop + delete the VM dir entirely
```

This pairs with [`scripts/validate-single-host.sh`](../../scripts/validate-single-host.sh),
the 12-check post-deploy gate that can't run in CI (service health, `.env`
secret hygiene, firewall posture, logrotate, backup cron, monitor-mode default).

## Tunables (environment variables)

| Var | Default | Meaning |
|-----|---------|---------|
| `VM_DIR` | `~/vms/ja4test` | disk, seed, console log, throwaway SSH key |
| `VM_CPUS` | `4` | vCPUs |
| `VM_MEM_MB` | `8192` | RAM (MiB) |
| `VM_DISK_GB` | `20` | root disk size (GiB) |
| `SSH_PORT` | `2222` | host port → guest `:22` |
| `SSH_USER` | `sean` | login user created by cloud-init |
| `IMAGE_URL` | Ubuntu 24.04 noble cloud image | base qcow2 |

The disk is a fresh copy of the cached base image on every `up`, so the VM is
genuinely throwaway. `destroy` reclaims all disk under `VM_DIR`.
