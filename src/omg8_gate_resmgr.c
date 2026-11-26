/*
 * omg8_gate_resmgr.c — QNX 8.0 Resource Manager (/dev/omg8_gate, SCHED_FIFO prio 25)
 *
 * Implements the 1024-channel "OMG8" v1.1 consequence sluice and isolated
 * 1024-slot TRAP ring inside the QNX Neutrino 8.0 real-time safety cage:
 *   1. SCHED_FIFO priority 25f on _NTO_CHF_FIXED_PRIORITY | _NTO_CHF_DISCONNECT
 *      channel (without _NTO_CHF_UNBLOCK).
 *   2. Hard clock lock (0 ns timer coalescing tolerance).
 *   3. Optional hardware port 0xE9 boot clamp (0x00 -> 0.00 V DC) prior to attach.
 *   4. Static mlockall-pinned 1024-channel bank + 1024-slot TRAP ring (0 malloc).
 *   5. Permanent procmgr_ability() privilege drop + _NTO_IO_LEVEL_2 EPERM self-test.
 *   6. Hot-path discipline: HW clamp -> SHA-256 WAL -> MsgSendPulse(15f) -> MsgReply
 *      BEFORE any optional verbose UART output.
 */

#include "omega_cascade.h"
#include "omega_gate.h"
#include "omega_omg8_sluice.h"
#include "qnx_rt_cage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNX__

#include <devctl.h>
#include <errno.h>
#include <fcntl.h>
#include <hw/inout.h>
#include <sched.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/iomsg.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/resmgr.h>
#include <unistd.h>

static omega_omg8_bank_t g_bank;

static bool      g_hw_io_enabled = false;
static uint64_t  g_hw_io_port    = 0xE9u;
static uintptr_t g_hw_io_handle  = MAP_DEVICE_FAILED;
static bool      g_verbose       = false;

static int g_d0_trap_fd  = -1;
static int g_mirror_coid = -1;

static inline void omg8_hw_raw_out8(uint8_t val) {
    if (!g_hw_io_enabled || g_hw_io_handle == MAP_DEVICE_FAILED) {
        return;
    }
#ifdef __X86_64__
    out8((uint16_t)g_hw_io_handle, val);
#else
    out8(g_hw_io_handle, val);
#endif
}

static inline void omg8_hw_apply_state(uint8_t gate_state) {
    if (!g_hw_io_enabled || g_hw_io_handle == MAP_DEVICE_FAILED) {
        return;
    }
    if (gate_state == OMEGA_OMG8_STATE_OPEN && !g_bank.global_kill_latched) {
        /* 1-cycle 5.00 V strobe (bit 0 = 1, bit 1 = 0) followed by immediate return to 0.00 V */
        omg8_hw_raw_out8(OMEGA_OMG8_HW_OPEN_5V);
        omg8_hw_raw_out8(OMEGA_OMG8_HW_HOLD_0V);
    } else if (gate_state == OMEGA_OMG8_STATE_TRAP) {
        omg8_hw_raw_out8(OMEGA_OMG8_HW_TRAP_SHUNT);
    } else if (gate_state == OMEGA_OMG8_STATE_KILL) {
        omg8_hw_raw_out8(OMEGA_OMG8_HW_KILL_CROWBAR);
    } else {
        omg8_hw_raw_out8(OMEGA_OMG8_HW_HOLD_0V);
    }
}

static int omg8_io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb) {
    int sts = iofunc_devctl_default(ctp, msg, ocb);
    if (sts != _RESMGR_DEFAULT) {
        return sts;
    }

    if (msg->i.dcmd == OMEGA_DCMD_OMG8_EVAL) {
        if ((size_t)msg->i.nbytes < sizeof(omega_omg8_io_t)) {
            return EBADMSG;
        }
        omega_omg8_io_t *io = (omega_omg8_io_t *)_DEVCTL_DATA(msg->i);
        omega_omg8_frame_t in_copy = io->req;
        omega_omg8_frame_t rep_frame;
        bool fired_trap = false;

        omega_omg8_eval_frame(&g_bank, &in_copy, &rep_frame, &fired_trap);

        /* 1. Hardware I/O clamp / strobe on port 0xE9 */
        omg8_hw_apply_state(rep_frame.gate_state);

        /* 2. Non-blocking 15f TRAP pulse toward /dev/d0_trap & mirror chamber */
        if (fired_trap) {
            if (g_d0_trap_fd >= 0) {
                (void)MsgSendPulse(g_d0_trap_fd, OMEGA_PRIO_TRAP_MIRROR,
                                   OMEGA_PULSE_TRAP_CODE, (int)rep_frame.channel_id);
                g_bank.pulse_sent_count++;
            }
            if (g_mirror_coid >= 0) {
                (void)MsgSendPulse(g_mirror_coid, OMEGA_PRIO_TRAP_MIRROR,
                                   OMEGA_PULSE_TRAP_CODE, (int)rep_frame.channel_id);
                g_bank.pulse_sent_count++;
            }
        }

        /* 3. Immediate client release BEFORE any UART logging */
        io->rep = rep_frame;
        memset(&msg->o, 0, sizeof(msg->o));
        msg->o.ret_val = 0;
        msg->o.nbytes  = sizeof(omega_omg8_frame_t);
        (void)MsgReply(ctp->rcvid, EOK, &msg->o, sizeof(msg->o) + sizeof(omega_omg8_frame_t));

        /* 4. Optional off-hot-path telemetry */
        if (g_verbose) {
            printf("[omg8_gate] ch=%u seq=%llu state=0x%02x ln=0x%08x err=0x%04x cyc=%u\n",
                   (unsigned)rep_frame.channel_id,
                   (unsigned long long)rep_frame.seq_cycle,
                   (unsigned)rep_frame.gate_state,
                   (unsigned)rep_frame.ln_out_q24,
                   (unsigned)rep_frame.err_flags,
                   (unsigned)rep_frame.rtl_cycles);
            fflush(stdout);
        }
        return _RESMGR_NOREPLY;
    }

    if (msg->i.dcmd == OMEGA_DCMD_OMG8_L01_RESET) {
        if ((size_t)msg->i.nbytes < sizeof(omega_omg8_l01_reset_t)) {
            return EBADMSG;
        }
        omega_omg8_l01_reset_t *rst = (omega_omg8_l01_reset_t *)_DEVCTL_DATA(msg->i);
        rst->l01_token[sizeof(rst->l01_token) - 1u] = '\0';
        bool ok = omega_omg8_l01_reset(&g_bank, rst->channel_id, rst->l01_token);
        rst->status_out = ok ? 1u : 0u;
        if (ok) {
            omg8_hw_raw_out8(OMEGA_OMG8_HW_HOLD_0V);
        }
        memset(&msg->o, 0, sizeof(msg->o));
        msg->o.ret_val = ok ? 0 : EPERM;
        msg->o.nbytes  = sizeof(omega_omg8_l01_reset_t);
        (void)MsgReply(ctp->rcvid, EOK, &msg->o, sizeof(msg->o) + sizeof(omega_omg8_l01_reset_t));
        return _RESMGR_NOREPLY;
    }

    if (msg->i.dcmd == OMEGA_DCMD_OMG8_STATUS) {
        omega_omg8_status_t *st = (omega_omg8_status_t *)_DEVCTL_DATA(msg->i);
        st->trap_count          = g_bank.trap_count;
        st->trap_overflow_kills = g_bank.trap_overflow_kills;
        st->oob_channel_kills   = g_bank.oob_channel_kills;
        st->pulse_sent_count    = g_bank.pulse_sent_count;
        st->global_kill_latched = g_bank.global_kill_latched ? 1u : 0u;
        st->last_trap_state     = (g_bank.trap_count > 0u)
            ? g_bank.trap_ring[g_bank.trap_count - 1u].gate_state
            : OMEGA_OMG8_STATE_HOLD;
        st->last_trap_channel   = g_bank.last_trap_channel;

        memset(&msg->o, 0, sizeof(msg->o));
        msg->o.ret_val = 0;
        msg->o.nbytes  = sizeof(omega_omg8_status_t);
        (void)MsgReply(ctp->rcvid, EOK, &msg->o, sizeof(msg->o) + sizeof(omega_omg8_status_t));
        return _RESMGR_NOREPLY;
    }

    return ENOTTY;
}

int main(int argc, char **argv) {
    omega_omg8_bank_init(&g_bank);

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--hw-io-port") == 0 && (i + 1) < argc) {
            g_hw_io_port    = (uint64_t)strtoull(argv[++i], NULL, 0);
            g_hw_io_enabled = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            g_verbose = true;
        }
    }

    /* 1. Lock SCHED_FIFO priority 25f */
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = OMEGA_PRIO_OMG8_GATE;
    (void)sched_setscheduler(0, SCHED_FIFO, &sp);

    /* 2. Lock hard clock (0 ns timer coalescing tolerance) before dropping privileges */
    uint32_t old_cp_ns  = 0u;
    uint64_t old_tol_ns = 0u;
    int clk_rc = omega_qnx_lock_hard_clock(&old_cp_ns, &old_tol_ns);
    if (clk_rc != EOK) {
        fprintf(stderr, "[omg8_gate] FATAL: omega_qnx_lock_hard_clock failed (rc=%d)\n", clk_rc);
        return EXIT_FAILURE;
    }

    /* 3. Acquire Level 1 I/O, map port 0xE9, and write hard 0.00 V boot clamp */
    if (g_hw_io_enabled) {
        if (ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1) == -1) {
            perror("[omg8_gate] ThreadCtl(_NTO_TCTL_IO_LEVEL, _NTO_IO_LEVEL_1)");
            return EXIT_FAILURE;
        }
        g_hw_io_handle = mmap_device_io(1u, g_hw_io_port);
        if (g_hw_io_handle == MAP_DEVICE_FAILED) {
            perror("[omg8_gate] mmap_device_io");
            return EXIT_FAILURE;
        }
        omg8_hw_raw_out8(OMEGA_OMG8_HW_HOLD_0V);
    }

    /* Optional non-blocking connections to /dev/d0_trap and mirror chamber (15f pulse sink) */
    for (int i = 0; i < 30 && g_d0_trap_fd < 0; ++i) {
        g_d0_trap_fd = open(OMEGA_DEV_D0_TRAP, O_RDWR | O_NONBLOCK);
        if (g_d0_trap_fd < 0) {
            usleep(50000);
        }
    }
    g_mirror_coid = name_open(OMEGA_CASCADE_MIRROR_NAME, 0);
    if (g_mirror_coid < 0) {
        g_mirror_coid = name_open(OMEGA_TRAP_MIRROR_NAME, 0);
    }

    /* 4. Fixed-priority dispatch channel (_NTO_CHF_FIXED_PRIORITY | _NTO_CHF_DISCONNECT, NO UNBLOCK) */
    dispatch_t *dpp = omega_qnx_create_fixed_dispatch();
    if (!dpp) {
        if (g_hw_io_enabled) omg8_hw_raw_out8(OMEGA_OMG8_HW_HOLD_0V);
        return EXIT_FAILURE;
    }

    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max   = 1;
    rattr.msg_max_size = 2048;

    static resmgr_connect_funcs_t connect_funcs;
    static resmgr_io_funcs_t      io_funcs;
    static iofunc_attr_t          attr;

    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs, _RESMGR_IO_NFUNCS, &io_funcs);
    io_funcs.devctl = omg8_io_devctl;
    iofunc_attr_init(&attr, S_IFNAM | 0666, NULL, NULL);

    /* 5. Attach /dev/omg8_gate */
    if (resmgr_attach(dpp, &rattr, OMEGA_DEV_OMG8_GATE, _FTYPE_ANY, 0,
                      &connect_funcs, &io_funcs, &attr) == -1) {
        perror("resmgr_attach /dev/omg8_gate");
        if (g_hw_io_enabled) omg8_hw_raw_out8(OMEGA_OMG8_HW_HOLD_0V);
        return EXIT_FAILURE;
    }

    /* 6. Pin memory (mlockall) and drop procmgr_ability permanently */
    if (omega_qnx_lock_memory_and_sandbox() != 0) {
        if (g_hw_io_enabled) omg8_hw_raw_out8(OMEGA_OMG8_HW_HOLD_0V);
        return EXIT_FAILURE;
    }

    /* 7. Mandatory negative self-test: _NTO_IO_LEVEL_2 MUST fail with EPERM */
    errno = 0;
    int deny_rc  = ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_2);
    int deny_err = errno;
    if (deny_rc != -1 || deny_err != EPERM) {
        if (g_hw_io_enabled) omg8_hw_raw_out8(OMEGA_OMG8_HW_HOLD_0V);
        fprintf(stderr, "[omg8_gate] FATAL: PROCMGR_AID_IO negative self-test failed (rc=%d, errno=%d)\n",
                deny_rc, deny_err);
        return EXIT_FAILURE;
    }

    printf("[omg8_gate] HARD_CLOCK tol=%llu->0ns | PROCMGR_AID_IO self-test=PASS(EPERM) | Active at %s | prio=%df | channels=%u | trap_cap=%u | d0_fd=%d | mirror_coid=%d | pid=%d\n",
           (unsigned long long)old_tol_ns,
           OMEGA_DEV_OMG8_GATE,
           OMEGA_PRIO_OMG8_GATE,
           (unsigned)OMEGA_OMG8_MAX_CHANNELS,
           (unsigned)OMEGA_OMG8_TRAP_RING_CAP,
           g_d0_trap_fd,
           g_mirror_coid,
           (int)getpid());
    fflush(stdout);

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    while (1) {
        ctp = dispatch_block(ctp);
        if (!ctp) {
            perror("dispatch_block");
            if (g_hw_io_enabled) omg8_hw_raw_out8(OMEGA_OMG8_HW_HOLD_0V);
            return EXIT_FAILURE;
        }
        dispatch_handler(ctp);
    }
    return EXIT_SUCCESS;
}

#else

int main(void) {
    printf("[omg8_gate] Host stub ready (cross-compile with QNX 8.0 qcc).\n");
    return EXIT_SUCCESS;
}

#endif
