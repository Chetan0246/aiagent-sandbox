#!/usr/bin/env bash
# setup_vm.sh - Automates provisioning of a Debian Minimal AI Agent Sandbox under KVM/QEMU
set -euo pipefail

VM_NAME="debian-minimal"
RAM_MB=512
VCPUS=1
DISK_GB=8
ISO_PATH="${1:-/home/chetan/Downloads/debian-13.7.0-amd64-netinst.iso}"
DISK_IMAGE="/var/lib/libvirt/images/${VM_NAME}.qcow2"

echo "[+] Creating disk image: ${DISK_IMAGE} (${DISK_GB}G)"
sudo qemu-img create -f qcow2 "${DISK_IMAGE}" "${DISK_GB}G"

echo "[+] Launching virt-install for unattended preseed setup..."
virt-install \
  --name "${VM_NAME}" \
  --memory "${RAM_MB}" \
  --vcpus "${VCPUS}" \
  --cpu host-passthrough \
  --disk path="${DISK_IMAGE}",format=qcow2,bus=virtio \
  --cdrom "${ISO_PATH}" \
  --os-variant debian12 \
  --network network=default,model=virtio \
  --graphics none \
  --console pty,target_type=serial \
  --extra-args "auto=true priority=critical console=ttyS0" \
  --noautoconsole

echo "[+] VM ${VM_NAME} provisioning started."
