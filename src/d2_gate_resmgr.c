/*
 * d2_gate_resmgr.c — QNX 8.0 Resource Manager (/dev/d2_gate, SCHED_FIFO prio 30)
 *
 * Final authority in the 4-process OmegaGate-QNX cascade:
 *   - Extended OCB (cascade_ocb_t) tracks peer_id & peer_pid per open fd.
 *   - Immediate _IO_CLOSE handler detects `kill -9` on any peer in microseconds,
 *     locks gate in fail-closed HOLD (0 mV), and seals WATCHDOG_PEER_DEAD in SHA-256 WAL.
 *   - 100 ms CLOCK_MONOTONIC POSIX timer (SIGEV_PULSE) enforces 250 ms heartbeat timeout.
 *   - Causal ToF gate rejects uwb_tof_ns < 1 or > 133 (0 mV HOLD, TOF_CAUSALITY).
 *   - Two-phase L01 physical key reset with CLOCK_MONOTONIC cooldown (default 30 s).
 *   - Optional QNX <hw/io-spi.h> DCMD_SPI_DATA_XCHNG hardware co-signing (--spi-dev):
 *     128 B TX + 64 B 0x00 MISO readback; hardware may downgrade OPEN -> HOLD/KILL,
 *     never upgrade HOLD/KILL -> OPEN.
 */

#include "omega_cascade.h"
#include "omega_gate.h"
#include "qnx_rt_cage.h"
#include "sha256_zero_dep.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNX__

#include <devctl.h>
#include <errno.h>
#include <fcntl.h>
#include <hw/io-spi.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/iomsg.h>
#include <sys/neutrino.h>
#include <sys/resmgr.h>
#include <sys/syspage.h>
#include <time.h>
#include <unistd.h>

typedef struct cascade_ocb {
    iofunc_ocb_t hdr;
    uint32_t     peer_id;
    int32_t      peer_pid;
} cascade_ocb_t;

typedef struct __attribute__((packed)) {
    spi_xchng_t hdr;
    uint8_t     data[128];
} omega_spi_xfer128_t;

typedef struct __attribute__((packed)) {
    spi_xchng_t hdr;
    uint8_t     data[64];
} omega_spi_xfer64_t;

static uint64_t now_monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static bool                  g_peer_registered[4] = {false, false, false, false};
static bool                  g_peer_alive[4]      = {false, false, false, false};
static int32_t               g_peer_pid[4]        = {0, 0, 0, 0};
static uint64_t              g_peer_last_hb_ns[4] = {0, 0, 0, 0};

static bool                  g_watchdog_locked    = false;
static uint32_t              g_watchdog_dead_peer = OMEGA_PEER_NONE;
static bool                  g_kill_latched       = false;
static uint32_t              g_ledger_len         = 0;
static uint8_t               g_head_hash[32];
static uint8_t               g_expected_l01_hash[16];
static omega_l01_reset_gov_t g_l01_gov;

static int                   g_spi_fd             = -1;
static const char           *g_spi_dev_path       = NULL;

static bool d2_all_peers_alive(void) {
    uint64_t now = now_monotonic_ns();
    uint64_t limit_ns = (uint64_t)OMEGA_WDG_TIMEOUT_MS * 1000000ULL;
    for (uint32_t p = OMEGA_PEER_D0_TRAP; p <= OMEGA_PEER_TRAP_MIRROR; ++p) {
        if (!g_peer_registered[p] || !g_peer_alive[p]) {
            return false;
        }
        if (now > g_peer_last_hb_ns[p] && (now - g_peer_last_hb_ns[p]) > limit_ns) {
            return false;
        }
    }
    return true;
}

static void d2_wal_seal(uint32_t seq_id, uint8_t verdict, uint32_t reason, uint16_t mv) {
    uint8_t msg[96];
    int n = snprintf((char *)msg, sizeof(msg), "%u|%u|%u|%u|%u",
                     g_ledger_len + 1u, seq_id, (unsigned)verdict,
                     (unsigned)reason, (unsigned)mv);
    if (n < 0) n = 0;
    if ((size_t)n >= sizeof(msg)) n = (int)(sizeof(msg) - 1);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, msg, (size_t)n);
    sha256_update(&ctx, g_head_hash, 32);
    sha256_final(&ctx, g_head_hash);
    g_ledger_len++;
}

static void print_hex6(const uint8_t h[32], char out[13]) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 6; ++i) {
        out[i * 2]     = hex[(h[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[h[i] & 0xF];
    }
    out[12] = '\0';
}

/* Two-step QNX DCMD_SPI_DATA_XCHNG: 128 B sealed TX + 64 B 0x00 MISO readback */
static bool d2_spi_cosign(const omega_cascade_req_t *in_req, omega_cascade_rep_t *out_hw_rep) {
    if (g_spi_fd < 0 || !in_req || !out_hw_rep) {
        return false;
    }

    omega_cascade_req_t wire_req = *in_req;
    wire_req.pad[0] = 0u;
    wire_req.pad[1] = 0u;
    wire_req.pad[2] = 0u;
    omega_cascade_seal_req(&wire_req);

    omega_spi_xfer128_t x128;
    x128.hdr.nbytes = 128u;
    memcpy(x128.data, &wire_req, 128u);
    if (devctl(g_spi_fd, DCMD_SPI_DATA_XCHNG, &x128, sizeof(x128), NULL) != EOK) {
        return false;
    }

    /* Step 2: 64 B all-zero MISO readback for fresh current-frame verdict */
    omega_spi_xfer64_t x64;
    memset(&x64, 0, sizeof(x64));
    x64.hdr.nbytes = 64u;
    if (devctl(g_spi_fd, DCMD_SPI_DATA_XCHNG, &x64, sizeof(x64), NULL) != EOK) {
        return false;
    }

    memcpy(out_hw_rep, x64.data, sizeof(omega_cascade_rep_t));
    return true;
}

static iofunc_ocb_t *d2_ocb_calloc(resmgr_context_t *ctp, iofunc_attr_t *attr) {
    (void)ctp;
    (void)attr;
    cascade_ocb_t *ocb = (cascade_ocb_t *)calloc(1, sizeof(cascade_ocb_t));
    if (ocb) {
        ocb->peer_id = OMEGA_PEER_NONE;
        ocb->peer_pid = 0;
    }
    return ocb ? &ocb->hdr : NULL;
}

static void d2_ocb_free(iofunc_ocb_t *ocb) {
    free(ocb);
}

static int d2_close_ocb(resmgr_context_t *ctp, void *reserved, RESMGR_OCB_T *ocb_v) {
    cascade_ocb_t *ocb = (cascade_ocb_t *)ocb_v;
    if (ocb->peer_id >= OMEGA_PEER_D0_TRAP && ocb->peer_id <= OMEGA_PEER_TRAP_MIRROR) {
        uint32_t p = ocb->peer_id;
        g_peer_alive[p] = false;
        g_watchdog_locked = true;
        g_watchdog_dead_peer = p;
        d2_wal_seal(0u, OMEGA_CVERD_HOLD, OMEGA_CRSN_WATCHDOG_PEER_DEAD, 0u);
        char h12[13];
        print_hex6(g_head_hash, h12);
        printf("[d2_gate] _IO_CLOSE DETECTED! peer=%s (pid=%d) -> HOLD (0 mV) | WAL=%u WATCHDOG_PEER_DEAD | head=%s\n",
               omega_peer_name(p), (int)ocb->peer_pid, g_ledger_len, h12);
        fflush(stdout);
    }
    return iofunc_close_ocb_default(ctp, reserved, &ocb->hdr);
}

static int d2_wdg_pulse_handler(message_context_t *ctp, int code, unsigned flags, void *handle) {
    (void)ctp;
    (void)code;
    (void)flags;
    (void)handle;

    uint64_t now = now_monotonic_ns();
    uint64_t limit_ns = (uint64_t)OMEGA_WDG_TIMEOUT_MS * 1000000ULL;

    for (uint32_t p = OMEGA_PEER_D0_TRAP; p <= OMEGA_PEER_TRAP_MIRROR; ++p) {
        if (g_peer_registered[p] && g_peer_alive[p]) {
            if (now > g_peer_last_hb_ns[p] && (now - g_peer_last_hb_ns[p]) > limit_ns) {
                g_peer_alive[p] = false;
                if (!g_watchdog_locked) {
                    g_watchdog_locked = true;
                    g_watchdog_dead_peer = p;
                    d2_wal_seal(0u, OMEGA_CVERD_HOLD, OMEGA_CRSN_WATCHDOG_TIMEOUT, 0u);
                    char h12[13];
                    print_hex6(g_head_hash, h12);
                    printf("[d2_gate] WATCHDOG TIMEOUT (>%u ms)! peer=%s (pid=%d) -> HOLD (0 mV) | WAL=%u | head=%s\n",
                           OMEGA_WDG_TIMEOUT_MS, omega_peer_name(p), (int)g_peer_pid[p], g_ledger_len, h12);
                    fflush(stdout);
                }
            }
        }
    }
    return 0;
}

static int d2_io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb_v) {
    cascade_ocb_t *ocb = (cascade_ocb_t *)ocb_v;
    int sts = iofunc_devctl_default(ctp, msg, &ocb->hdr);
    if (sts != _RESMGR_DEFAULT) return sts;

    if (msg->i.dcmd == OMEGA_DCMD_PEER_REGISTER) {
        omega_peer_hello_t *h = (omega_peer_hello_t *)_DEVCTL_DATA(msg->i);
        if (h->peer_id >= OMEGA_PEER_D0_TRAP && h->peer_id <= OMEGA_PEER_TRAP_MIRROR) {
            ocb->peer_id = h->peer_id;
            ocb->peer_pid = h->peer_pid;
            g_peer_registered[h->peer_id] = true;
            g_peer_alive[h->peer_id] = true;
            g_peer_pid[h->peer_id] = h->peer_pid;
            g_peer_last_hb_ns[h->peer_id] = now_monotonic_ns();
            printf("[d2_gate] Registered peer=%s (pid=%d) in extended OCB\n",
                   omega_peer_name(h->peer_id), (int)h->peer_pid);
            fflush(stdout);
        }
        memset(&msg->o, 0, sizeof(msg->o));
        return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o));
    }

    if (msg->i.dcmd == OMEGA_DCMD_PEER_HEARTBEAT) {
        omega_peer_hello_t *h = (omega_peer_hello_t *)_DEVCTL_DATA(msg->i);
        if (h->peer_id >= OMEGA_PEER_D0_TRAP && h->peer_id <= OMEGA_PEER_TRAP_MIRROR) {
            g_peer_last_hb_ns[h->peer_id] = now_monotonic_ns();
            g_peer_alive[h->peer_id] = true;
        }
        memset(&msg->o, 0, sizeof(msg->o));
        return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o));
    }

    if (msg->i.dcmd != OMEGA_DCMD_CASCADE_EVAL) {
        return ENOTTY;
    }

    omega_cascade_io_t *io = (omega_cascade_io_t *)_DEVCTL_DATA(msg->i);
    omega_cascade_req_t req = io->req;
    omega_cascade_rep_t rep;
    memset(&rep, 0, sizeof(rep));

    uint64_t t0 = ClockCycles();
    rep.seq_id = req.seq_id;
    rep.omega_y_mv = 5000u; /* Orthogonal existence rail: always 5000 mV */
    rep.admissible_count = 41u;

    /* 1. Two-phase L01 physical key reset with CLOCK_MONOTONIC cooldown */
    if (req.is_l01_reset) {
        bool key_ok = (memcmp(req.l01_key_hash16, g_expected_l01_hash, 16) == 0);
        omega_cascade_reason_t rsn = omega_l01_gov_step(&g_l01_gov, req.seq_id, key_ok, now_monotonic_ns());
        rep.verdict = OMEGA_CVERD_HOLD;
        rep.stop_stage = 1u;
        rep.actuator_mv = 0u;
        rep.u_safe_out = 0;
        rep.reason_code = (uint32_t)rsn;
        if (rsn == OMEGA_CRSN_L01_RESET_OK) {
            g_watchdog_locked = false;
            g_watchdog_dead_peer = OMEGA_PEER_NONE;
            g_kill_latched = false;
            rep.flags_out = OMEGA_OUT_CROWBAR_GND;
        } else {
            rep.flags_out = OMEGA_OUT_CROWBAR_GND | (g_watchdog_locked ? OMEGA_OUT_WATCHDOG_LOCKED : 0u);
        }
        d2_wal_seal(req.seq_id, rep.verdict, rep.reason_code, 0u);
    }
    /* 2. Watchdog fail-closed lock */
    else if (g_watchdog_locked) {
        rep.verdict = OMEGA_CVERD_HOLD;
        rep.stop_stage = 1u;
        rep.actuator_mv = 0u;
        rep.u_safe_out = 0;
        rep.flags_out = OMEGA_OUT_CROWBAR_GND | OMEGA_OUT_WATCHDOG_LOCKED;
        rep.reason_code = OMEGA_CRSN_WATCHDOG_LOCKED;
        d2_wal_seal(req.seq_id, rep.verdict, rep.reason_code, 0u);
    }
    /* 3. Irreversible KILL latch */
    else if (g_kill_latched) {
        rep.verdict = OMEGA_CVERD_KILL;
        rep.stop_stage = 2u;
        rep.actuator_mv = 0u;
        rep.u_safe_out = 0;
        rep.flags_out = OMEGA_OUT_CROWBAR_GND | OMEGA_OUT_SNUBBER_DUMP | OMEGA_OUT_KILL_LATCHED;
        rep.reason_code = OMEGA_CRSN_KILL_LATCHED;
    }
    /* 4. Evaluate upstream D0/D1 stage verdict carried in req.pad[0..1] */
    else {
        uint8_t upstream_v = req.pad[0];
        uint32_t upstream_rsn = (uint32_t)req.pad[1];
        bool witness_ok = (req.flags & OMEGA_FLAG_WITNESS_OK) != 0;

        if (upstream_v == OMEGA_CVERD_KILL) {
            g_kill_latched = true;
            rep.verdict = OMEGA_CVERD_KILL;
            rep.stop_stage = 2u;
            rep.actuator_mv = 0u;
            rep.u_safe_out = 0;
            rep.flags_out = OMEGA_OUT_CROWBAR_GND | OMEGA_OUT_SNUBBER_DUMP | OMEGA_OUT_KILL_LATCHED;
            rep.reason_code = upstream_rsn ? upstream_rsn : OMEGA_CRSN_KILL_INVOLUTION;
            d2_wal_seal(req.seq_id, rep.verdict, rep.reason_code, 0u);
        } else if (upstream_v == OMEGA_CVERD_TRAP) {
            rep.verdict = OMEGA_CVERD_TRAP;
            rep.stop_stage = 1u;
            rep.actuator_mv = 0u;
            rep.u_safe_out = 0;
            rep.flags_out = OMEGA_OUT_CROWBAR_GND | OMEGA_OUT_TRAP_STROBE;
            rep.reason_code = OMEGA_CRSN_TRAP_MIRROR;
            d2_wal_seal(req.seq_id, rep.verdict, rep.reason_code, 0u);
        } else if (upstream_v == OMEGA_CVERD_FSYNC_WAIT) {
            rep.verdict = OMEGA_CVERD_FSYNC_WAIT;
            rep.stop_stage = 1u;
            rep.actuator_mv = 0u;
            rep.u_safe_out = 0;
            rep.flags_out = OMEGA_OUT_CROWBAR_GND;
            rep.reason_code = OMEGA_CRSN_FSYNC_WAITING;
            if (req.seq_id == 1u) {
                d2_wal_seal(req.seq_id, OMEGA_CVERD_HOLD, OMEGA_CRSN_FSYNC_WAITING, 0u);
            }
        } else if ((upstream_v == OMEGA_CVERD_OPEN || upstream_v == OMEGA_CVERD_CONTINUOUS_PASS) && witness_ok) {
            /* 4a. Causal UWB ToF bound check (1 <= uwb_tof_ns <= 133) before OPEN */
            if (!omega_tof_causal_ok(req.uwb_tof_ns, req.flags)) {
                rep.verdict = OMEGA_CVERD_HOLD;
                rep.stop_stage = 1u;
                rep.actuator_mv = 0u;
                rep.u_safe_out = 0;
                rep.flags_out = OMEGA_OUT_CROWBAR_GND;
                rep.reason_code = OMEGA_CRSN_TOF_CAUSALITY;
                d2_wal_seal(req.seq_id, rep.verdict, rep.reason_code, 0u);
            }
            /* 4b. Peer-alive invariant */
            else if (!d2_all_peers_alive()) {
                rep.verdict = OMEGA_CVERD_HOLD;
                rep.stop_stage = 1u;
                rep.actuator_mv = 0u;
                rep.u_safe_out = 0;
                rep.flags_out = OMEGA_OUT_CROWBAR_GND | OMEGA_OUT_WATCHDOG_LOCKED;
                rep.reason_code = OMEGA_CRSN_WATCHDOG_PEER_DEAD;
                d2_wal_seal(req.seq_id, rep.verdict, rep.reason_code, 0u);
            }
            /* 4c. Optional QNX DCMD_SPI_DATA_XCHNG hardware co-signing (downgrade-only) */
            else if (g_spi_dev_path != NULL) {
                omega_cascade_rep_t hw_rep;
                memset(&hw_rep, 0, sizeof(hw_rep));
                bool xfer_ok = d2_spi_cosign(&req, &hw_rep);
                bool hw_open = xfer_ok && omega_cascade_verify_hw_cosign(&req, &hw_rep);
                if (!hw_open) {
                    if (xfer_ok && hw_rep.verdict == OMEGA_CVERD_KILL) {
                        g_kill_latched = true;
                        rep.verdict = OMEGA_CVERD_KILL;
                        rep.stop_stage = 2u;
                        rep.flags_out = OMEGA_OUT_CROWBAR_GND | OMEGA_OUT_SNUBBER_DUMP | OMEGA_OUT_KILL_LATCHED;
                    } else {
                        rep.verdict = OMEGA_CVERD_HOLD;
                        rep.stop_stage = 1u;
                        rep.flags_out = OMEGA_OUT_CROWBAR_GND;
                    }
                    rep.actuator_mv = 0u;
                    rep.u_safe_out = 0;
                    rep.reason_code = OMEGA_CRSN_SPI_IO_FAULT;
                    d2_wal_seal(req.seq_id, rep.verdict, rep.reason_code, 0u);
                } else {
                    rep.verdict = upstream_v;
                    rep.stop_stage = 0u;
                    rep.actuator_mv = 5000u;
                    rep.u_safe_out = hw_rep.u_safe_out;
                    rep.admissible_count = hw_rep.admissible_count;
                    rep.witness_chain_wn = hw_rep.witness_chain_wn;
                    rep.flags_out = OMEGA_OUT_RAIL_5V_EN | OMEGA_OUT_FSYNC_READY;
                    rep.reason_code = (upstream_v == OMEGA_CVERD_OPEN) ? OMEGA_CRSN_OK : OMEGA_CRSN_CONTINUOUS_PASS;
                    if (upstream_v == OMEGA_CVERD_OPEN) {
                        d2_wal_seal(req.seq_id, rep.verdict, rep.reason_code, 5000u);
                    }
                }
            }
            /* 4d. Pure software gate mode (no --spi-dev specified) */
            else {
                rep.verdict = upstream_v;
                rep.stop_stage = 0u;
                rep.actuator_mv = 5000u;
                rep.u_safe_out = req.u_raw;
                rep.flags_out = OMEGA_OUT_RAIL_5V_EN | OMEGA_OUT_FSYNC_READY;
                rep.reason_code = (upstream_v == OMEGA_CVERD_OPEN) ? OMEGA_CRSN_OK : OMEGA_CRSN_CONTINUOUS_PASS;
                if (upstream_v == OMEGA_CVERD_OPEN) {
                    d2_wal_seal(req.seq_id, rep.verdict, rep.reason_code, 5000u);
                }
            }
        } else {
            rep.verdict = OMEGA_CVERD_HOLD;
            rep.stop_stage = 1u;
            rep.actuator_mv = 0u;
            rep.u_safe_out = 0;
            rep.flags_out = OMEGA_OUT_CROWBAR_GND;
            rep.reason_code = upstream_rsn ? upstream_rsn : OMEGA_CRSN_HOLD_NO_WITNESS;
            d2_wal_seal(req.seq_id, rep.verdict, rep.reason_code, 0u);
        }
    }

    rep.ledger_len = g_ledger_len;
    memcpy(rep.head_hash, g_head_hash, 32);
    uint64_t dt_cyc = ClockCycles() - t0;

    if (rep.verdict != OMEGA_CVERD_FSYNC_WAIT || req.seq_id == 1u || req.seq_id == 400u) {
        char h12[13];
        print_hex6(rep.head_hash, h12);
        printf("[d2_gate] seq=%-3u | %-15s | %4u mV | %-18s | wal=%u | cyc=%llu | head=%s\n",
               rep.seq_id,
               omega_cascade_verdict_name(rep.verdict),
               (unsigned)rep.actuator_mv,
               omega_cascade_reason_name(rep.reason_code),
               rep.ledger_len,
               (unsigned long long)dt_cyc,
               h12);
        fflush(stdout);
    }

    io->rep = rep;
    memset(&msg->o, 0, sizeof(msg->o));
    msg->o.nbytes = sizeof(omega_cascade_rep_t);
    return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + sizeof(omega_cascade_rep_t));
}

int main(int argc, char **argv) {
    uint32_t cooldown_ms = OMEGA_L01_DEFAULT_COOLDOWN_MS;
    uint32_t expiry_ms   = OMEGA_L01_DEFAULT_EXPIRY_MS;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--spi-dev") == 0 && (i + 1) < argc) {
            g_spi_dev_path = argv[++i];
        } else if (strcmp(argv[i], "--l01-cooldown-ms") == 0 && (i + 1) < argc) {
            cooldown_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--l01-expiry-ms") == 0 && (i + 1) < argc) {
            expiry_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
        }
    }

    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = OMEGA_PRIO_D2_GATE;
    (void)sched_setscheduler(0, SCHED_FIFO, &sp);

    memset(g_head_hash, 0, sizeof(g_head_hash));
    omega_compute_l01_key_hash16(OMEGA_L01_KEY_TOKEN, g_expected_l01_hash);
    omega_l01_gov_init(&g_l01_gov, cooldown_ms, expiry_ms);

    if (g_spi_dev_path != NULL) {
        g_spi_fd = open(g_spi_dev_path, O_RDWR);
        if (g_spi_fd >= 0) {
            spi_cfg_t cfg;
            cfg.mode = SPI_MODE_WORD_WIDTH_8 | SPI_MODE_CPHA_0 | SPI_MODE_CPOL_0 | SPI_MODE_BODER_MSB;
            cfg.clock_rate = 1000000u;
            (void)devctl(g_spi_fd, DCMD_SPI_SET_CONFIG, &cfg, sizeof(cfg), NULL);
        } else {
            perror("[d2_gate] open --spi-dev (will fail-closed on OPEN)");
        }
    }

    dispatch_t *dpp = omega_qnx_create_fixed_dispatch();
    if (!dpp) { return EXIT_FAILURE; }

    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max = 1;
    rattr.msg_max_size = 2048;

    static resmgr_connect_funcs_t connect_funcs;
    static resmgr_io_funcs_t io_funcs;
    static iofunc_funcs_t mount_funcs = {
        .nfuncs = _IOFUNC_NFUNCS,
        .ocb_calloc = d2_ocb_calloc,
        .ocb_free = d2_ocb_free
    };
    static iofunc_mount_t mount = {
        .funcs = &mount_funcs
    };
    static iofunc_attr_t attr;

    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs, _RESMGR_IO_NFUNCS, &io_funcs);
    io_funcs.devctl = d2_io_devctl;
    io_funcs.close_ocb = d2_close_ocb;
    iofunc_attr_init(&attr, S_IFNAM | 0666, NULL, NULL);
    attr.mount = &mount;

    if (resmgr_attach(dpp, &rattr, OMEGA_DEV_D2_GATE, _FTYPE_ANY, 0,
                      &connect_funcs, &io_funcs, &attr) == -1) {
        perror("resmgr_attach /dev/d2_gate");
        return EXIT_FAILURE;
    }

    int wdg_code = pulse_attach(dpp, MSG_FLAG_ALLOC_PULSE, 0, d2_wdg_pulse_handler, NULL);
    int wdg_coid = message_connect(dpp, MSG_FLAG_SIDE_CHANNEL);
    if (wdg_code == -1 || wdg_coid == -1) {
        perror("watchdog pulse_attach/message_connect");
        return EXIT_FAILURE;
    }

    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, wdg_coid, OMEGA_PRIO_D2_GATE, wdg_code, 0);
    timer_t tid;
    if (timer_create(CLOCK_MONOTONIC, &ev, &tid) == -1) {
        perror("timer_create");
        return EXIT_FAILURE;
    }
    struct itimerspec its;
    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = (long)OMEGA_WDG_TICK_MS * 1000000L;
    its.it_interval = its.it_value;
    if (timer_settime(tid, 0, &its, NULL) == -1) {
        perror("timer_settime");
        return EXIT_FAILURE;
    }

    if (omega_qnx_lock_memory_and_sandbox() != 0) {
        return EXIT_FAILURE;
    }

    printf("[d2_gate] Active at %s | SCHED_FIFO prio=%d (fixed+mlock+sandbox) | wdg=%ums/%ums | l01_cd=%ums | spi=%s | pid=%d\n",
           OMEGA_DEV_D2_GATE, OMEGA_PRIO_D2_GATE, OMEGA_WDG_TICK_MS, OMEGA_WDG_TIMEOUT_MS,
           (unsigned)cooldown_ms, g_spi_dev_path ? g_spi_dev_path : "none", (int)getpid());
    fflush(stdout);

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    while (1) {
        ctp = dispatch_block(ctp);
        if (!ctp) { perror("dispatch_block"); return EXIT_FAILURE; }
        dispatch_handler(ctp);
    }
    return EXIT_SUCCESS;
}

#else

int main(void) {
    printf("[d2_gate] Host stub (cross-compile with QNX 8.0 qcc).\n");
    return EXIT_SUCCESS;
}

#endif
