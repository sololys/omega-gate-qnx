#!/usr/bin/env bash
# Reproducible QNX 8.0 QEMU runner for the 4-process OmegaGate-QNX cascade
# Requires QNX SDP 8.0 (QNX_TARGET / qnxsdp-env.sh) and qemu-system-x86_64.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
QNX_SDP="${QNX_SDP:-$HOME/qnx800}"
VM_DIR="${VM_DIR:-/tmp/qnx8_omega_vm}"
SERIAL_LOG="${SERIAL_LOG:-/tmp/qnx8_cascade_live.log}"
HW_PORT_LOG="${HW_PORT_LOG:-/tmp/qnx8_hw_port_e9.bin}"

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
omega_gate/test_d2_hardening=$REPO_DIR/build/qnx_x86_64/test_d2_hardening
omega_gate/spi_fpga_sim_resmgr=$REPO_DIR/build/qnx_x86_64/spi_fpga_sim_resmgr
omega_gate/d2_gate_resmgr=$REPO_DIR/build/qnx_x86_64/d2_gate_resmgr
omega_gate/d1_guestroom_resmgr=$REPO_DIR/build/qnx_x86_64/d1_guestroom_resmgr
omega_gate/d0_trap_resmgr=$REPO_DIR/build/qnx_x86_64/d0_trap_resmgr
omega_gate/cascade_mirror_daemon=$REPO_DIR/build/qnx_x86_64/cascade_mirror_daemon
omega_gate/cascade_driver=$REPO_DIR/build/qnx_x86_64/cascade_driver
EOF

cat > "$VM_DIR/local/snippets/post_start.custom" <<'EOF'
echo "================================================================="
echo "OMEGAGATE-QNX 4-PROCESS CASCADE + DCMD_SPI_DATA_XCHNG + L01 2-PHASE"
uname -a
echo "================================================================="
chmod +x /data/omega_gate/*
/data/omega_gate/test_hashprune_sluice
/data/omega_gate/test_d2_hardening
/data/omega_gate/spi_fpga_sim_resmgr /dev/spi_fpga_sim &
SPI_PID=$!
sleep 1
/data/omega_gate/d2_gate_resmgr --spi-dev /dev/spi_fpga_sim --l01-cooldown-ms 200 --hw-io-port 0xe9 &
sleep 1
/data/omega_gate/cascade_mirror_daemon &
sleep 1
/data/omega_gate/d1_guestroom_resmgr &
D1_PID=$!
sleep 1
/data/omega_gate/d0_trap_resmgr &
sleep 1
ls -la /dev/spi_fpga_sim /dev/d0_trap /dev/d1_guestroom /dev/d2_gate
echo "=== [PIDIN PRIORITIES BEFORE CASCADE] ==="
pidin -F "%a %b %p %n" | grep -E "d0_trap|d1_guestroom|d2_gate|spi_fpga_sim|cascade_mirror" || pidin | grep -E "d0_trap|d1_guestroom|d2_gate|spi_fpga_sim|cascade_mirror" || true
/data/omega_gate/cascade_driver $D1_PID $SPI_PID /dev/spi_fpga_sim
sleep 1
shutdown -f
EOF

(cd "$VM_DIR" && mkqnximage --build --noprompt)

rm -f "$SERIAL_LOG" "$HW_PORT_LOG"
CPU_FLAG="--cpu max"
if [ -w /dev/kvm ]; then
    CPU_FLAG="--enable-kvm --cpu host"
fi
timeout 45 qemu-system-x86_64 \
    -smp 2 -m 512 ${CPU_FLAG} \
    -drive "file=$VM_DIR/output/disk-qemu.vmdk,if=ide,id=drv0" \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -chardev "file,id=hwport0,path=$HW_PORT_LOG" \
    -device "isa-debugcon,iobase=0xe9,chardev=hwport0" \
    -display none -no-reboot -serial "file:$SERIAL_LOG" || true

echo "=== QNX 8.0 SERIAL LOG ($SERIAL_LOG) ==="
tail -n 70 "$SERIAL_LOG"

echo "=== [HOST ASSERT] VERIFYING FIXED QNX RT PRIORITY LADDER (15f/20f/25f/30f/30f) ==="
PIDIN_CLEAN="$(tr -d '\r' < "$SERIAL_LOG")"
check_prio() {
    local expected_prio="$1"
    local proc_name="$2"
    if ! printf '%s\n' "$PIDIN_CLEAN" | grep -Eq "^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+${expected_prio}[[:space:]]+.*${proc_name}"; then
        echo "[FAIL] Missing expected priority ${expected_prio} for ${proc_name} in pidin output!" >&2
        exit 1
    fi
    echo "  [PASS] ${proc_name} locked at ${expected_prio}"
}
check_prio "15f" "cascade_mirror_daemon"
check_prio "20f" "d0_trap_resmgr"
check_prio "25f" "d1_guestroom_resmgr"
check_prio "30f" "d2_gate_resmgr"
check_prio "30f" "spi_fpga_sim_resmgr"

if ! printf '%s\n' "$PIDIN_CLEAN" | grep -q "STATE_REPLY_STALL_PASS"; then
    echo "[FAIL] Missing STATE_REPLY_STALL_PASS in QNX serial log!" >&2
    exit 1
fi
echo "  [PASS] Live 200ms STATE_REPLY stall broken by TimerTimeout (<=35ms)"

if ! printf '%s\n' "$PIDIN_CLEAN" | grep -q "POST_STALL_RESYNC_PASS"; then
    echo "[FAIL] Missing POST_STALL_RESYNC_PASS in QNX serial log!" >&2
    exit 1
fi
echo "  [PASS] Post-stall resync verified (fresh seq=425 MISO, no stale seq=424)"

echo "=== [HOST ASSERT] VERIFYING HW I/O PORT 0xE9 BYTE TRACE ($HW_PORT_LOG) ==="
python3 - "$HW_PORT_LOG" << 'PYEOF'
import sys
from pathlib import Path

p = Path(sys.argv[1])
data = p.read_bytes()
hex_seq = " ".join(f"{b:02x}" for b in data)
print(f"  [HW 0xE9] len={len(data)} bytes | hex: {hex_seq}")
assert len(data) >= 3, f"Expected >= 3 HW port writes, got {len(data)}"
assert data[0] == 0x00, f"First byte must be 0x00 startup clamp, got 0x{data[0]:02x}"
assert any((b & 0x01) == 1 for b in data), "Expected at least one OPEN write with RAIL_5V_EN (bit 0 = 1)"
assert (data[-1] & 0x01) == 0, f"Final byte must have RAIL_5V_EN=0, got 0x{data[-1]:02x}"
print("  [PASS] HW I/O port 0xE9 sequence verified (0x00 boot clamp -> OPEN bit0=1 -> final bit0=0)")
PYEOF
