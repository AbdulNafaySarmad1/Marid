#!/usr/bin/env bash
# Read-only Phase 0 host inventory. No disk, network, or service changes.
set -euo pipefail

run_if_present() {
  local command_name="$1"
  shift
  if command -v "$command_name" >/dev/null 2>&1; then
    "$command_name" "$@" || true
  else
    printf '%s: unavailable\n' "$command_name"
  fi
}

printf 'MARID host inventory (UTC): %s\n' "$(date -u +%FT%TZ)"
printf '\nOS\n'
cat /etc/os-release 2>/dev/null || true
run_if_present uname -a
printf '\nCPU and memory\n'
run_if_present nproc
run_if_present free -h
printf '\nBlock devices and mounted filesystems (inspection only)\n'
run_if_present lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS
run_if_present df -hT
printf '\nNetworking, DNS, and time\n'
run_if_present ip -brief address
run_if_present resolvectl status
run_if_present timedatectl status
printf '\nSecurity and runtimes\n'
run_if_present getenforce
run_if_present firewall-cmd --state
run_if_present podman --version
run_if_present tailscale version
printf '\nInspection complete. No configuration or storage changes were made.\n'
