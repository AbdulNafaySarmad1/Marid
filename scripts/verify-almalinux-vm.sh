#!/usr/bin/env bash
# Runs only inside an isolated, disposable Debian container. The guest disk
# stays in the container filesystem and disappears when the container exits.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/tmp/apt.log 2>&1
apt-get install -y -qq --no-install-recommends \
  ca-certificates curl gnupg qemu-system-x86 qemu-utils cloud-image-utils \
  coreutils >/tmp/apt.log 2>&1 || { tail -n 60 /tmp/apt.log; exit 1; }

workdir=/tmp/marid-guest
mkdir -p "$workdir"
cd "$workdir"
base_url=https://repo.almalinux.org/almalinux/9/cloud/x86_64/images
image=AlmaLinux-9-GenericCloud-latest.x86_64.qcow2

echo 'Downloading and verifying the official AlmaLinux 9 cloud image.'
curl -fsSL -o alma-key https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9
fingerprint=$(gpg --show-keys --with-colons --fingerprint alma-key 2>/dev/null |
  awk -F: '$1 == "fpr" {print $10; exit}')
if [[ "$fingerprint" != BF18AC2876178908D6E71267D36CB86CB86B3716 ]]; then
  echo 'AlmaLinux signing key fingerprint did not match the published value.' >&2
  exit 1
fi
gpg --batch --import alma-key >/dev/null 2>&1
curl -fsSL -o CHECKSUM "$base_url/CHECKSUM"
curl -fsSL -o CHECKSUM.asc "$base_url/CHECKSUM.asc"
gpg --batch --verify CHECKSUM.asc CHECKSUM >/dev/null 2>&1
curl -fsSL -o "$image" "$base_url/$image"
grep -F "$image" CHECKSUM | sha256sum -c - >/tmp/marid-checksum.log 2>&1 || {
  cat /tmp/marid-checksum.log
  exit 1
}
qemu-img info "$image" | head -n 5

cat > guest-run.sh <<'EOSCRIPT'
#!/usr/bin/env bash
exec >/dev/ttyS0 2>&1
echo MARID_VM_GUEST_STARTED
bash /root/marid-bootstrap.sh
result=$?
echo "MARID_VM_BOOTSTRAP_STATUS=$result"
source /etc/os-release
echo "MARID_VM_OS_ID=$ID"
systemctl poweroff
EOSCRIPT

bootstrap_b64=$(base64 -w0 /input/bootstrap.sh)
guest_run_b64=$(base64 -w0 guest-run.sh)
cat > user-data <<'EOF'
#cloud-config
write_files:
  - path: /root/marid-bootstrap.sh
    permissions: '0700'
    encoding: b64
    content:
EOF
printf '      %s\n' "$bootstrap_b64" >> user-data
cat >> user-data <<'EOF'
  - path: /root/guest-run.sh
    permissions: '0700'
    encoding: b64
    content:
EOF
printf '      %s\n' "$guest_run_b64" >> user-data
cat >> user-data <<'EOF'
runcmd:
  - [bash, /root/guest-run.sh]
EOF
printf 'instance-id: marid-disposable-guest\nlocal-hostname: marid-guest\n' > meta-data
cloud-localds seed.iso user-data meta-data
qemu-img create -q -f qcow2 -F qcow2 -b "$workdir/$image" guest.qcow2 8G

echo 'Booting a 1 GiB, one-vCPU AlmaLinux guest without guest networking.'
set +e
timeout --signal=TERM 900s qemu-system-x86_64 \
  -machine pc,accel=tcg -cpu max -smp 1 -m 1024 -no-hpet -rtc clock=vm \
  -drive "file=guest.qcow2,if=virtio,format=qcow2" \
  -drive "file=seed.iso,if=ide,media=cdrom,format=raw" \
  -nic none -display none -serial stdio -monitor none -no-reboot \
  >vm.log 2>&1
vm_exit=$?
set -e
if [[ "$vm_exit" -ne 0 ]] ||
   ! grep -q 'MARID_VM_BOOTSTRAP_STATUS=0' vm.log ||
   ! grep -q 'MARID_VM_OS_ID=almalinux' vm.log; then
  echo "Guest boot or inventory failed (QEMU exit $vm_exit)." >&2
  tail -n 100 vm.log >&2
  exit 1
fi
grep -E 'MARID_VM_|Inspection complete|^Enforcing$|^Permissive$' vm.log | tail -n 20
echo 'Disposable AlmaLinux VM boot and read-only inventory passed.'
