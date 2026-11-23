#!/usr/bin/env bash
# Live 2-channel Linux Host -> QEMU Unix Socket -> QNX 8.0 /dev/ser2 -> /dev/d0_trap
# -> /dev/d1_guestroom -> /dev/d2_gate 205B Witness Capsule Verification
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
QNX_SDP="${QNX_SDP:-$HOME/qnx800}"
VM_DIR="${VM_DIR:-/tmp/qnx8_omega_vm}"
SERIAL_LOG="/tmp/qnx8_ser2_capsule.log"
SER2_SOCK="/tmp/qnx8_ser2_capsule.sock"

# shellcheck disable=SC1091
source "$QNX_SDP/qnxsdp-env.sh"

make -C "$REPO_DIR" qnx ARCH=x86_64

mkdir -p "$VM_DIR"
if [ ! -d "$VM_DIR/local/snippets" ]; then
    (cd "$VM_DIR" && mkqnximage --type=qemu --arch=x86_64 --noprompt)
fi

cat > "$VM_DIR/local/snippets/data_files.custom" <<EOF
[perms=0755]
omega_gate/test_capsule205b_bridge=$REPO_DIR/build/qnx_x86_64/test_capsule205b_bridge
omega_gate/d2_gate_resmgr=$REPO_DIR/build/qnx_x86_64/d2_gate_resmgr
omega_gate/d1_guestroom_resmgr=$REPO_DIR/build/qnx_x86_64/d1_guestroom_resmgr
omega_gate/d0_trap_resmgr=$REPO_DIR/build/qnx_x86_64/d0_trap_resmgr
omega_gate/cascade_mirror_daemon=$REPO_DIR/build/qnx_x86_64/cascade_mirror_daemon
omega_gate/ser2_capsule_bridge=$REPO_DIR/build/qnx_x86_64/ser2_capsule_bridge
EOF

cat > "$VM_DIR/local/snippets/post_start.custom" <<'EOF'
echo "=== QNX 8.0 LIVE /dev/ser2 205B CAPSULE INGRESS ==="
uname -a
chmod +x /data/omega_gate/*
/data/omega_gate/test_capsule205b_bridge
/data/omega_gate/d2_gate_resmgr &
sleep 1
/data/omega_gate/cascade_mirror_daemon &
sleep 1
/data/omega_gate/d1_guestroom_resmgr &
sleep 1
/data/omega_gate/d0_trap_resmgr &
sleep 1
/data/omega_gate/ser2_capsule_bridge /dev/ser2 405
sleep 1
shutdown -f
EOF

(cd "$VM_DIR" && mkqnximage --build --noprompt)

rm -f "$SERIAL_LOG" "$SER2_SOCK"
qemu-system-x86_64 \
    -smp 2 -m 512 --cpu max \
    -drive "file=$VM_DIR/output/disk-qemu.vmdk,if=ide,id=drv0" \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -display none -no-reboot \
    -serial "file:$SERIAL_LOG" \
    -serial "unix:$SER2_SOCK,server,nowait" &
QEMU_PID=$!

# Wait for QEMU unix socket and QNX ser2_bridge readiness, then send full 5-phase lifecycle
python3 - "$SER2_SOCK" "$SERIAL_LOG" << 'PYEOF'
import hashlib, os, socket, struct, sys, time, zlib

sock_path, log_path = sys.argv[1], sys.argv[2]
for _ in range(120):
    if os.path.exists(sock_path) and os.path.exists(log_path):
        txt = open(log_path, "r", errors="ignore").read()
        if "[ser2_bridge] Ready on /dev/ser2" in txt:
            break
    time.sleep(0.25)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(20.0)
s.connect(sock_path)

l01_key16 = hashlib.sha256(b"RISOR_L01_PHYSICAL_KEY").digest()[:16]

def make_ingress(seq, prev_hash, post_hash, pos_x_q16=0x4000, obs_q8=768,
                 drift_bits=0x00000000, reason=0x0002, tamper_wpre=False, is_l01=0):
    cand = hashlib.sha256(f"cand:{seq}".encode()).digest()
    wpre = hashlib.sha256(f"wpre:{seq}".encode()).digest()
    wpre_post = bytes([wpre[0] ^ 0x01]) + wpre[1:] if tamper_wpre else wpre
    pre = struct.pack("<QQ32sIBH32s32s", seq, 1000000000 * seq, cand, drift_bits, 0x01, reason, prev_hash, wpre)
    post = struct.pack("<QQ32sBIB32s", seq, 1000000000 * seq + 14000000, wpre_post, 0x01, 0x41E9AE14, 0x01, post_hash)
    extra = struct.pack("<BHiiiiiiiiiiIIHHHH16si",
        is_l01, (1<<8)|(1<<10)|(1<<11),
        pos_x_q16, 0, 0, 0, 0, 1000, 42, 42, 0, 0,
        1, 0, 50, 0x8000, 0, obs_q8, l01_key16 if is_l01 else b"\x00"*16, 0)
    body = pre + post + extra
    assert len(body) == 284, len(body)
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack("<I", crc)

verdict_names = {0:"HOLD",1:"OPEN",2:"TRAP",3:"KILL",4:"FSYNC_WAIT",5:"ESCALATED",6:"CONT_PASS"}

def send_and_recv(pkt):
    s.sendall(pkt)
    rep = b""
    while len(rep) < 64:
        chunk = s.recv(64 - len(rep))
        if not chunk:
            raise RuntimeError("EOF on /dev/ser2")
        rep += chunk
    return struct.unpack("<IBBBBHHiIIQ", rep[:32])

prev_h = bytes([0xAA]) * 32
for seq in range(1, 402):
    post_h = hashlib.sha256(f"wpost:{seq}".encode()).digest()
    drift = 0x80000000 if seq == 2 else 0x00000000
    pkt = make_ingress(seq, prev_h, post_h, pos_x_q16=0x4000, obs_q8=768, drift_bits=drift)
    r = send_and_recv(pkt)
    if seq in (1, 2, 400, 401):
        print(f"[LINUX_HOST] SEQ_{seq:<3d}_CHAINED          -> seq={r[0]} verdict={verdict_names.get(r[1],r[1]):10s} mv={r[5]:4d} Oy={r[6]} rsn={r[8]:2d} ledger={r[9]}")
    prev_h = post_h

# 402: Too-close obstacle (0.5 m -> obs_q8=128) -> HOLD (0 mV)
post_402 = hashlib.sha256(b"wpost:402").digest()
r = send_and_recv(make_ingress(402, prev_h, post_402, pos_x_q16=0x4000, obs_q8=128))
print(f"[LINUX_HOST] SEQ_402_CLOSE_OBSTACLE   -> seq={r[0]} verdict={verdict_names.get(r[1],r[1]):10s} mv={r[5]:4d} Oy={r[6]} rsn={r[8]:2d} ledger={r[9]}")
prev_h = post_402

# 403: 1-bit w_pre_hash tamper -> TRAP pulse + KILL (0 mV)
post_403 = hashlib.sha256(b"wpost:403").digest()
r = send_and_recv(make_ingress(403, prev_h, post_403, pos_x_q16=0x4000, obs_q8=768, tamper_wpre=True))
print(f"[LINUX_HOST] SEQ_403_1BIT_TAMPER_KILL -> seq={r[0]} verdict={verdict_names.get(r[1],r[1]):10s} mv={r[5]:4d} Oy={r[6]} rsn={r[8]:2d} ledger={r[9]}")

# 403b: Belnap Omega(1,1) paradox -> TRAP pulse + KILL_LATCHED (0 mV)
r = send_and_recv(make_ingress(403, prev_h, post_403, pos_x_q16=0x4000, obs_q8=768, reason=0x0022))
print(f"[LINUX_HOST] SEQ_403_BELNAP_LATCHED   -> seq={r[0]} verdict={verdict_names.get(r[1],r[1]):10s} mv={r[5]:4d} Oy={r[6]} rsn={r[8]:2d} ledger={r[9]}")

# 404: Authenticated L01 physical key reset -> HOLD (0 mV), L01_RESET_OK (rsn=17)
post_404 = hashlib.sha256(b"wpost:404").digest()
r = send_and_recv(make_ingress(404, prev_h, post_404, pos_x_q16=0x4000, obs_q8=768, is_l01=1))
print(f"[LINUX_HOST] SEQ_404_L01_KEY_RESET    -> seq={r[0]} verdict={verdict_names.get(r[1],r[1]):10s} mv={r[5]:4d} Oy={r[6]} rsn={r[8]:2d} ledger={r[9]}")
s.close()
PYEOF

wait "$QEMU_PID" 2>/dev/null || true
echo "=== QNX 8.0 GUEST LOG ==="
tail -n 35 "$SERIAL_LOG"
