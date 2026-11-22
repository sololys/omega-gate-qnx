#!/usr/bin/env bash
# Reproducible QNX 8.0 QEMU runner for the 4-process OmegaGate-QNX cascade
# Requires QNX SDP 8.0 (QNX_TARGET / qnxsdp-env.sh) and qemu-system-x86_64.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
QNX_SDP="${QNX_SDP:-$HOME/qnx800}"
VM_DIR="${VM_DIR:-/tmp/qnx8_omega_vm}"
SERIAL_LOG="${SERIAL_LOG:-/tmp/qnx8_cascade_live.log}"

# shellcheck disable=SC1091
source "$QNX_SDP/qnxsdp-env.sh"

make -C "$REPO_DIR" qnx ARCH=x86_64

mkdir -p "$VM_DIR"
if [ ! -d "$VM_DIR/local/snippets" ]; then
    (cd "$VM_DIR" && mkqnximage --type=qemu --arch=x86_64 --noprompt)
fi

cat > "$VM_DIR/local/snippets/data_files.custom" <<EOF
[perms=0755]
omega_gate/test_hashprune_sluice=$REPO_DIR/build/qnx_x86_64/test_hashprune_sluice
omega_gate/d2_gate_resmgr=$REPO_DIR/build/qnx_x86_64/d2_gate_resmgr
omega_gate/d1_guestroom_resmgr=$REPO_DIR/build/qnx_x86_64/d1_guestroom_resmgr
omega_gate/d0_trap_resmgr=$REPO_DIR/build/qnx_x86_64/d0_trap_resmgr
omega_gate/cascade_mirror_daemon=$REPO_DIR/build/qnx_x86_64/cascade_mirror_daemon
omega_gate/cascade_driver=$REPO_DIR/build/qnx_x86_64/cascade_driver
EOF

cat > "$VM_DIR/local/snippets/post_start.custom" <<'EOF'
echo "================================================================="
echo "OMEGAGATE-QNX 4-PROCESS CASCADE & KILL -9 WATCHDOG VERIFICATION"
uname -a
echo "================================================================="
chmod +x /data/omega_gate/*
/data/omega_gate/test_hashprune_sluice
/data/omega_gate/d2_gate_resmgr &
sleep 1
/data/omega_gate/cascade_mirror_daemon &
sleep 1
/data/omega_gate/d1_guestroom_resmgr &
D1_PID=$!
sleep 1
/data/omega_gate/d0_trap_resmgr &
sleep 1
ls -la /dev/d0_trap /dev/d1_guestroom /dev/d2_gate
/data/omega_gate/cascade_driver $D1_PID
sleep 1
shutdown -f
EOF

(cd "$VM_DIR" && mkqnximage --build --noprompt)

rm -f "$SERIAL_LOG"
timeout 45 qemu-system-x86_64 \
    -smp 2 -m 512 --cpu max \
    -drive "file=$VM_DIR/output/disk-qemu.vmdk,if=ide,id=drv0" \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -display none -serial "file:$SERIAL_LOG" || true

echo "=== QNX 8.0 SERIAL LOG ($SERIAL_LOG) ==="
tail -n 60 "$SERIAL_LOG"
