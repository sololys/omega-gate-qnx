# OmegaGate-QNX

Fail-closed, zero-float consequence gate (`/dev/omega_gate`) for **QNX Neutrino 8.0**, isolating untrusted proposal generators (`0.00 V DC`) from physical actuator authority (`5.00 V DC`) via microkernel IPC, sequential stops, and an append-only SHA-256 witness chain.

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

### 3. Run Live Inside QNX 8.0 (QEMU)

Transfer the three binaries to your QNX 8.0 QEMU target (e.g. `/tmp/`) and run:

```sh
/tmp/trap_mirror_daemon &
/tmp/omega_gate_resmgr &
sleep 1
/tmp/d0_planner
```

`d0_planner` executes the full canonical sequence over QNX IPC (`OPEN 5000 mV`, intermediate `HOLD 0 mV`, unwitnessed `HOLD 0 mV`, `TRAP` pulse to `trap_mirror_daemon`, shortcut `RAW -> COMMITTED -> KILL`, replay `KILL`, and Level-01 authorized reset to `HOLD`).

---

## Epistemic Demarcation

- **Verified locally (`L1/L2`):** Zero-float C11 state machine, FIPS 180-4 SHA-256 witness chain, QNX 8.0 IPC/Resource Manager boundaries, and SystemVerilog IEEE 1800-2012 RTL (`iverilog -Wall` 0 warnings, `yosys` clean).
- **Physical bench requirements (outside software scope):** Analog RC snubbers for inductive `-L di/dt` transients, physical mechanical brakes, and hardware WORM storage media.
