#!/usr/bin/env bash
# ============================================================================
# One-command reproducible QNX Neutrino 8.0 (QEMU x86_64) live demo runner
# Prerequisites:
#   - QNX SDP 8.0 installed (source ~/qnx800/qnxsdp-env.sh)
#   - qemu-system-x86_64 installed (sudo apt install qemu-system-x86)
# ============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM_DIR="${QNX_VM_DIR:-/tmp/qnx8_omega_vm}"
SERIAL_LOG="${VM_DIR}/serial.log"

if ! command -v qcc >/dev/null 2>&1; then
    echo "ERROR: qcc not found in PATH. Run: source ~/qnx800/qnxsdp-env.sh" >&2
    exit 1
fi
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "ERROR: qemu-system-x86_64 not found. Run: sudo apt install qemu-system-x86" >&2
    exit 1
fi

echo "[1/3] Cross-compiling OmegaGate-QNX for QNX 8.0 (x86_64)..."
make -C "${REPO_DIR}" qnx ARCH=x86_64

echo "[2/3] Building QNX 8.0 QEMU disk image in ${VM_DIR}..."
mkdir -p "${VM_DIR}"
if [ ! -d "${VM_DIR}/local/snippets" ]; then
    (cd "${VM_DIR}" && mkqnximage --type=qemu --arch=x86_64 --ssh-ident=none --noprompt --build >/dev/null)
fi

cat <<EOF > "${VM_DIR}/local/snippets/data_files.custom"
[perms=0755]
omega_gate/omega_gate_resmgr=${REPO_DIR}/build/qnx_x86_64/omega_gate_resmgr
omega_gate/d0_planner=${REPO_DIR}/build/qnx_x86_64/d0_planner
omega_gate/trap_mirror_daemon=${REPO_DIR}/build/qnx_x86_64/trap_mirror_daemon
EOF

cat <<'EOF' > "${VM_DIR}/local/snippets/post_start.custom"
echo "================================================================="
echo "OMEGAGATE-QNX LIVE EXECUTION ON QNX NEUTRINO 8.0 (QEMU x86_64)"
uname -a
echo "================================================================="
/data/omega_gate/trap_mirror_daemon &
sleep 1
/data/omega_gate/omega_gate_resmgr &
sleep 1
ls -la /dev/omega_gate
/data/omega_gate/d0_planner
sleep 1
echo "================================================================="
echo "OMEGAGATE-QNX LIVE DEMO COMPLETE"
echo "================================================================="
shutdown -f
EOF

(cd "${VM_DIR}" && mkqnximage --build --noprompt >/dev/null)

echo "[3/3] Booting QNX Neutrino 8.0 in QEMU (timeout 40s)..."
rm -f "${SERIAL_LOG}"
CPU_FLAG="--cpu max"
if [ -w /dev/kvm ]; then
    CPU_FLAG="--enable-kvm --cpu host"
fi

timeout 40 qemu-system-x86_64 -m 1024M -smp 2 ${CPU_FLAG} \
    -drive "file=${VM_DIR}/output/disk-qemu.vmdk,if=ide,id=drv0" \
    -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0 \
    -display none -no-reboot -serial "file:${SERIAL_LOG}" 2>/dev/null || true

tr -d '\r' < "${SERIAL_LOG}"
