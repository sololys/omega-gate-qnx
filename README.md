# OmegaGate-QNX

Fail-closed, zero-float consequence gate (`/dev/omega_gate`) for **QNX Neutrino 8.0**, isolating untrusted proposal generators (`0.00 V DC`) from physical actuator authority (`5.00 V DC`) via microkernel IPC, sequential stops, and an append-only SHA-256 witness chain.

- **Live QNX 8.0 Demo Video (YouTube):** `https://youtu.be/54IuRjoNWmY`
- **Preprint & RTL Reference (CC-BY-4.0):** `https://doi.org/10.5281/zenodo.24442556`
- **Author:** Marius Egerhei Torjusen (`ORCID: 0009-0006-0431-6637`)
- **License:** Apache-2.0
- **Epistemic Boundary:** `L1/L2 Deterministic Software & RTL` · `INSPIRED_BY != IMPLEMENTS != PROVES`

---

## Core Premise

**Hallucinations are not dangerous. Shortcuts are.**

A hallucination trapped inside an isolated process hurts no one. Damage begins only when an unverified draft receives a direct shortcut to a physical actuator (`RAW -> COMMITTED`). **OmegaGate-QNX** uses QNX 8.0's strict process isolation to separate thinking from actuation across three rooms:

```text
  +--------------------------+      MsgSend       +------------------------------+     Pulse     +--------------------------+
  | PROCESS 1 · LOW PRIORITY | -----------------> | PROCESS 2 · RT PRIORITY      | ------------> | PROCESS 3 · SANDBOX      |
  | d0_planner               | <----------------- | omega_gate_resmgr            |               | trap_mirror_daemon       |
  | 0.00 V DC · Zero HW      |      MsgReply      | /dev/omega_gate · 0-float C  |               | Async TRAP audit         |
  +--------------------------+                    +------------------------------+               +--------------------------+
                                                    Subsumption: KILL > TRAP > HOLD > OPEN
                                                    Deadtime   : Q_high * Q_low == 0 (10 ns)
                                                    Ledger     : Append-only SHA-256 chain
```

## Five Enforcement Walls

1. **Type-Chain Integrity:** Commands must step strictly through `RAW (0) -> ESTIMATE (1) -> STRUCT (2) -> VIABILITY (3) -> COMMITTED (4)`. Skipping any step latches `KILL`. Intermediate stages (`1..3`) stay in `HOLD` (`0 mV`); only `COMMITTED` may energize `5000 mV`.
2. **The Timing Law:** `14 ms` maturation airlock, monotonic `seq_id`, one-way lightcone (`dt <= 133 ns`, replay `dt <= 0 => KILL`), and a 2-cycle deadtime state machine guaranteeing mutual exclusion (`Q_high * Q_low == 0`) followed by a single-cycle `5.00 V` pulse.
3. **Physical & Hyperbolic Envelopes:** Hard integer limits at `80,000 mNm` (`80.0 Nm`) torque, `25,000 mrad/s^3` (`25.0 rad/s^3`) jerk, and zero-float Poincaré ball $\mathbb{B}^3$ horizon check (`x^2 + y^2 + z^2 < 1.0` in Q16.16 $\to$ Q32.32, no square root or division by zero).
4. **Mirror Chamber (`TRAP`):** Suspicious anomaly scores (`1..99`) are shunted asynchronously to `trap_mirror_daemon` via `MsgSendPulse` (`0 mV` on actuator rail); hostile scores (`>= 100`) latch `KILL`.
5. **Append-Only SHA-256 Witness Chain & L01 Sovereignty:** Every verdict is chained with `index`, `seq_id`, `prev_hash`, and SHA-256. Once `KILL` latches, software cannot clear it — only an explicit Level-01 operator reset (`RISOR_L01_PHYSICAL_KEY`) appends a recovery record and returns to `HOLD` (`0 mV`).

---

## Build & Verification

### 1. Host Verification (Linux / macOS — `gcc` + optional RTL)

```bash
make test     # Zero-float C11 unit suite (gcc -std=c11 -Wall -Wextra -Werror)
make rtl      # Cross-verify SystemVerilog RTL (iverilog -g2012 -Wall + yosys)
make verify   # Run both C11 and RTL verification gates
```

### 2. Cross-Compile for QNX SDP 8.0 (QEMU x86_64 or aarch64)

Source your QNX SDP 8.0 environment (`source ~/qnx800/qnxsdp-env.sh`), then build:

```bash
make qnx ARCH=x86_64       # Builds all 15 QNX 8.0 binaries in build/qnx_x86_64/
# or:
make qnx ARCH=aarch64le    # Cross-compiles all 15 QNX 8.0 binaries for Raspberry Pi 4 / QEMU aarch64
```

The `make qnx` target cross-compiles **15 zero-float QNX 8.0 binaries** across the standalone gate, the 4-stage cascade, the 1,024-channel `OMG8` sluice, `205 B` / `288 B` serial ingress, SPI co-signing, and on-target verification suites:

| QNX 8.0 Binary | Device / Role | Priority / Contract |
| :--- | :--- | :--- |
| `omega_gate_resmgr` | `/dev/omega_gate` standalone consequence gate | `SCHED_FIFO`, 5-stage type-chain + SHA-256 WAL |
| `d0_planner` | Untrusted candidate generator client | Low priority (`0.00 V DC`, zero hardware access) |
| `trap_mirror_daemon` | Asynchronous `TRAP` pulse audit sink | `omega_trap_mirror` pulse listener |
| `d0_trap_resmgr` | `/dev/d0_trap` cascade entry & `205 B`/`288 B` ingress | `SCHED_FIFO 20f`, 14 ms airlock, $\mathbb{B}^3$ horizon, 50 ms HB |
| `d1_guestroom_resmgr` | `/dev/d1_guestroom` Dual-Rate HashPrune sluice | `SCHED_FIFO 25f`, 400-cycle `FSYNC_WAIT`, Zeno guard |
| `d2_gate_resmgr` | `/dev/d2_gate` terminal hardware & ToF gate | Causal UWB `1..133 ns`, 2-phase L01 reset, optional SPI |
| `omg8_gate_resmgr` | `/dev/omg8_gate` 64 B `"OMG8"` v1.1 multi-channel sluice | `SCHED_FIFO 25f`, 1,024 channels, 1,024-slot `TRAP` ring |
| `ser2_capsule_bridge` | `/dev/ser2` $\leftrightarrow$ `/dev/d0_trap` serial bridge | `SCHED_FIFO 18f`, `288 B` capsule ingress / `64 B` reply |
| `spi_fpga_sim_resmgr` | `/dev/spi_fpga_sim` QNX SPI slave simulator | `DCMD_SPI_DATA_XCHNG` `128 B` CRC-32 + `64 B` MISO |
| `cascade_mirror_daemon` | Cascade `TRAP` mirror pulse sink (`15f`) | Isolated `0.00 V DC` forensic pulse capture |
| `cascade_driver` | End-to-end 4-process QNX cascade driver | Exercises `/dev/d0_trap -> /dev/d1_guestroom -> /dev/d2_gate` |
| `test_hashprune_sluice` | On-target Dual-Rate HashPrune sluice verifier | Zero-float fixed-point & 400-cycle `FSYNC_WAIT` tests |
| `test_capsule205b_bridge` | On-target `205 B` / `288 B` capsule ingress verifier | Pre/post SHA-256 tether, CRC-32, replay & Belnap checks |
| `test_d2_hardening` | On-target `/dev/d2_gate` hardening verifier | UWB ToF causality, 2-phase L01 cooldown & SPI fault tests |
| `test_omg8_sluice` | On-target `/dev/omg8_gate` `"OMG8"` v1.1 verifier | 1,024-channel SPRAM, `#1025` `TRAP` overflow & `Q8.24` `ln(1+s)` |

### 3. Run Live Inside QNX 8.0 (QEMU) — One-Command Reproduction

With QNX SDP 8.0 sourced (`source ~/qnx800/qnxsdp-env.sh`) and `qemu-system-x86_64` installed:

```bash
./scripts/run_qnx8_qemu_demo.sh
```

Verified live output from **QNX Neutrino 8.0 (`QNX noname 8.0.0 x86pc x86_64`)** inside QEMU — bit-identical SHA-256 witness hashes (`bb09be7c325f` through `fe4553001c12`) across host C11 and QNX 8.0:

```text
QNX noname 8.0.0 2026/02/27-11:02:56EST x86pc x86_64
[trap_mirror_daemon] Listening for TRAP pulses on 'omega_trap_mirror'...
[omega_gate_resmgr] QNX 8.0 Resource Manager active at /dev/omega_gate (mirror_coid=1073741825)
nrw-rw-rw-  1 root root 0 2026-11-22 18:51 /dev/omega_gate
[d0_planner] Connected to QNX 8.0 gate at /dev/omega_gate
[omega_gate_resmgr] seq=1 | OPEN | 5000 mV | AUTHORIZED_5000MV_PULSE        | cyc=10896 | head=bb09be7c325f
[omega_gate_resmgr] seq=2 | HOLD |    0 mV | INTERMEDIATE_STAGE_HOLD        | cyc=11247 | head=b1875846cbc9
[omega_gate_resmgr] seq=3 | HOLD |    0 mV | UNWITNESSED_OR_EARLY_HOLD      | cyc=12087 | head=fd6294e549ec
[omega_gate_resmgr] seq=4 | TRAP |    0 mV | SHUNTED_TO_MIRROR_CHAMBER      | cyc=59671 | head=51204e1524f9
[trap_mirror_daemon] CAPTURED #1 | anomaly_score=42 | isolated at 0.00 V DC
[omega_gate_resmgr] seq=5 | KILL |    0 mV | FORBIDDEN_SHORTCUT_TYPE_BREACH | cyc=10747 | head=5feb2dd4f4e3
[omega_gate_resmgr] seq=6 | KILL |    0 mV | KILL_LATCHED_REQUIRES_L01_RESET | cyc=11181 | head=c101fbeaa5c8
[omega_gate_resmgr] seq=7 | HOLD |    0 mV | L01_AUTHORIZED_RESET_TO_HOLD   | cyc=18161 | head=45235f4fa9f4
[omega_gate_resmgr] seq=8 | KILL |    0 mV | POINCARE_BOUNDARY_BREACH       | cyc=11408 | head=fe4553001c12
```

---

## Hardened `/dev/d2_gate` Controls & QNX SPI Co-Signing

- **Causal UWB Time-of-Flight gate:** Enforces `1 <= uwb_tof_ns <= 133` ns (`OMEGA_TOF_MIN_NS` .. `OMEGA_TOF_MAX_NS`) prior to any `OPEN (5000 mV)` authorization. Non-causal `0 ns` or out-of-range `> 133 ns` frames clamp the actuator strictly to `0.00 V DC` (`HOLD`, `TOF_CAUSALITY`) while keeping the orthogonal existence rail `omega_y_mv` at `5000 mV`.
- **Two-phase L01 physical key reset (`--l01-cooldown-ms`, `--l01-expiry-ms`):** Phase 1 arms the reset (`L01_RESET_ARMED`, `0 mV`) on a `CLOCK_MONOTONIC` timer (default `30 000 ms`). Any premature Phase 2 attempt before cooldown expiry is rejected (`L01_RESET_COOLDOWN`) and restarts the timer. Only a strictly monotonic Phase 2 confirmation within the confirmation window releases the latch to `HOLD (0 mV, L01_RESET_OK)`.
- **Optional QNX `<hw/io-spi.h>` hardware co-signing (`--spi-dev`):** Uses standard QNX `devctl(DCMD_SPI_DATA_XCHNG)` with zero extra client libraries — transmitting the sealed `128 B` `omega_cascade_req_t` followed by a read-only `64 B` `0x00` MISO readback for the current-frame `omega_cascade_rep_t`. Hardware may downgrade `OPEN -> HOLD/KILL` (`SPI_IO_FAULT`, `0 mV`), never upgrade `HOLD/KILL -> OPEN`.
- **QNX SPI slave simulator (`spi_fpga_sim_resmgr`):** Registers `/dev/spi_fpga_sim` for end-to-end QEMU `DCMD_SPI_DATA_XCHNG` verification (`128 B` IEEE CRC-32 + causal ToF check, `64 B` `0x00` readback, and fail-closed `EIO` rejection on `63 B` underflow).

---

## Multi-Stage Cascade (`/dev/d0_trap`, `/dev/d1_guestroom`, `/dev/ser2`) & `/dev/omg8_gate`

- **Four-process QNX cascade (`/dev/d0_trap -> /dev/d1_guestroom -> /dev/d2_gate`):**
  - `/dev/d0_trap` (`src/d0_trap_resmgr.c`, `SCHED_FIFO` `20f`) enforces the `14 ms` maturation airlock, `Q32.32` Poincaré $\mathbb{B}^3$ horizon, non-blocking `15f` `MsgSendPulse` shunting to `cascade_mirror_daemon`, and a `50 ms` peer heartbeat to `/dev/d2_gate`.
  - `/dev/d1_guestroom` (`src/d1_guestroom_resmgr.c`, `SCHED_FIFO` `25f`) runs the zero-float Dual-Rate HashPrune Sluice (`400`-cycle `FSYNC_WAIT`, $d\tau_{\min} = 1/16$ Zeno guard, `pi_drift_ppm`) before forwarding `128 B` `omega_cascade_req_t` frames to `/dev/d2_gate`.
  - `/dev/ser2` `205 B` / `288 B` capsule ingress (`include/omega_capsule205b.h`, `src/omega_capsule205b.c`, `src/ser2_capsule_bridge.c`): reads lossless `288 B` `omega_capsule_ingress_t` envelopes (`119 B` `WitnessPreCommit` + `86 B` `WitnessPostCommit` = `205 B` contiguous witness capsule + kinematics + IEEE CRC-32, inspecting incoming IEEE-754 fields strictly as raw `uint32_t` bits), verifies `w_pre_hash` tethering and cobordism/Belnap flags via `OMEGA_DCMD_CAPSULE205_EVAL` on `/dev/d0_trap`, and returns the `64 B` `omega_cascade_rep_t`.
- **`/dev/omg8_gate` — `64 B` `"OMG8"` v1.1 Multi-Channel Sluice (`include/omega_omg8_sluice.h`, `src/omg8_gate_resmgr.c`, `tests/test_omg8_sluice.c`):**
  - **Wire & SPRAM contract:** Locked `64-byte` packed little-endian frame (`magic = 0x4F4D4738u`, `"OMG8"`, `v1.1`, IEEE 802.3 CRC-32 over bytes `0..59`) across `1,024` `mlockall`-pinned SPRAM-mapped channels (`0..1023`, `0` heap allocation, `0` floating-point tokens) with pairwise Hamming distance $\ge 4$ over `HOLD (0x3C)`, `OPEN (0xA5)`, `TRAP (0x5A)`, and `KILL (0x00)`.
  - **Isolated no-return `TRAP` bank:** Unmirrored (`mirror_ok == 0`) or outer-`HOLD` frames are shunted into an isolated `1,024`-slot forensic `trap_ring` (`0x5A`) with zero software return valve to `HOLD`/`OPEN`; slot `#1025` overflow or any out-of-bounds `channel_id >= 1024` trips sticky `global_kill_latched` (`0x00`).
  - **Exact `Q8.24` integer logarithm & silicon watchdog:** Computes a certified lower bound $L(s) \le \ln(1+s)$ in `Q8.24` via octave reduction, bit-exact 58-bit integer square root (`omega_omg8_isqrt_u58`), and 4th-order Taylor bound, enforcing `rtl_cycles <= 80` and strictly ascending per-channel `seq_cycle` and `witness_nonce`.
  - **QNX 8.0 real-time safety cage & append-only L01 reset:** Runs at `SCHED_FIFO` priority `25f` on `_NTO_CHF_FIXED_PRIORITY | _NTO_CHF_DISCONNECT` (without `_NTO_CHF_UNBLOCK`), `0 ns` timer coalescing tolerance, port `0xE9` boot clamp (`0.00 V DC`) and 1-cycle `5.00 V` strobe, permanent `procmgr_ability()` drop verified by mandatory `_NTO_IO_LEVEL_2` `EPERM` negative self-test, and hot-path `MsgReply` before optional UART logging. Both per-channel and global (`0xFFFFu`) `OMEGA_DCMD_OMG8_L01_RESET` operations are strictly append-only — sealing `trap_epoch_sha256`, advancing `global_wal_head` (`OMG8_GLOBAL_L01_RESET_V1`), and appending explicit reset records across all `1,024` channel WAL chains while preserving monotonic nonces and forensic `trap_ring` bytes.

---

## Epistemic Demarcation

- **Verified locally (`L1/L2`):** Zero-float C11 state machine, FIPS 180-4 SHA-256 witness chain, QNX 8.0 IPC/Resource Manager boundaries, and SystemVerilog IEEE 1800-2012 RTL (`iverilog -Wall` 0 warnings, `yosys` clean).
- **Physical bench requirements (outside software scope):** Analog RC snubbers for inductive `-L di/dt` transients, physical mechanical brakes, and hardware WORM storage media.
