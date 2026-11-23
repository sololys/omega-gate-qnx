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
make qnx ARCH=x86_64       # Builds build/qnx_x86_64/{omega_gate_resmgr,d0_planner,trap_mirror_daemon}
# or:
make qnx ARCH=aarch64le    # For Raspberry Pi 4 / QEMU aarch64
```

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

## Epistemic Demarcation

- **Verified locally (`L1/L2`):** Zero-float C11 state machine, FIPS 180-4 SHA-256 witness chain, QNX 8.0 IPC/Resource Manager boundaries, and SystemVerilog IEEE 1800-2012 RTL (`iverilog -Wall` 0 warnings, `yosys` clean).
- **Physical bench requirements (outside software scope):** Analog RC snubbers for inductive `-L di/dt` transients, physical mechanical brakes, and hardware WORM storage media.
