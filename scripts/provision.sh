#!/usr/bin/env bash
# Aegis-Sandbox Automated VM Provisioning Script
# Enforces systemd cgroups, hardened sudoers, tmpfs isolation, and user-1001 sandbox account.

set -euo pipefail

echo "============================================================"
echo "Aegis :: Automated Environment Provisioning"
echo "============================================================"

# 1. Install dependencies
echo "[1/5] Installing core dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
    bubblewrap \
    curl \
    git \
    libseccomp2 \
    python3 \
    python3-pip \
    python3-venv \
    sudo

# 2. Provision agentuser
echo "[2/5] Creating restricted agentuser (UID 1001)..."
if ! id -u agentuser >/dev/null 2>&1; then
    useradd -m -u 1001 -s /bin/bash agentuser
fi

# 3. Configure systemd cgroup slice override
echo "[3/5] Applying user-1001.slice cgroup v2 limits..."
mkdir -p /etc/systemd/system/user-1001.slice.d
cat << 'EOF' > /etc/systemd/system/user-1001.slice.d/override.conf
[Slice]
MemoryAccounting=true
MemoryMax=450M
MemorySwapMax=128M
TasksAccounting=true
TasksMax=256
CPUAccounting=true
CPUQuota=200%
EOF

systemctl daemon-reload

# 4. Deploy hardened sudoers policy with explicit negations
echo "[4/5] Deploying hardened sudoers policy..."
cat << 'EOF' > /etc/sudoers.d/agentuser
# Aegis-Sandbox Hardened Sudoers Policy
agentuser ALL=(ALL) NOPASSWD: \
    /usr/bin/systemctl is-active *, \
    /usr/bin/systemctl status *, \
    /usr/bin/dmesg, \
    /usr/bin/journalctl, \
    /usr/bin/apt-get update, \
    /usr/bin/apt-get install -y *
agentuser ALL=(ALL) !/usr/bin/systemd-run, \
    !/usr/bin/nsenter, \
    !/usr/bin/chroot, \
    !/usr/bin/unshare, \
    !/usr/bin/bash, \
    !/usr/bin/sh, \
    !/usr/bin/su, \
    !/usr/bin/tee
EOF
chmod 0440 /etc/sudoers.d/agentuser

# 5. Lock down sensitive DAC files
echo "[5/5] Hardening DAC permissions on /root and /etc/shadow..."
chmod 700 /root
chmod 700 /etc/shadow || true

echo "============================================================"
echo "[OK] Provisioning complete. Sandbox boundaries enforced."
echo "============================================================"
