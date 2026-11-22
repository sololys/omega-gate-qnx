/*
 * Process 2: omega_gate_resmgr — QNX Neutrino 8.0 Resource Manager (/dev/omega_gate)
 *
 * On QNX 8.0 (__QNX__):
 *   - Registers /dev/omega_gate via resmgr_attach().
 *   - Accepts omega_cmd_t via devctl(OMEGA_DCMD_EVAL) and returns omega_reply_t.
 *   - Sends non-blocking MsgSendPulse() to trap_mirror_daemon on TRAP verdicts.
 *   - Reads monotonic hardware cycles via ClockCycles() for timing telemetry.
 *
 * On Linux host (without __QNX__):
 *   - Compiles cleanly as a standalone smoke-test runner (--selftest).
 */

#include "omega_gate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNX__
#include <devctl.h>
#include <errno.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/iomsg.h>
#include <sys/neutrino.h>
#include <sys/resmgr.h>
#include <sys/syspage.h>

#define OMEGA_DCMD_EVAL __DIOTF(_DCMD_MISC, 1, omega_cmd_t)

typedef union {
    omega_cmd_t   cmd;
    omega_reply_t reply;
} omega_io_msg_t;

static omega_gate_t g_gate;
static int g_mirror_coid = -1;

static int io_devctl_handler(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb) {
    int sts = iofunc_devctl_default(ctp, msg, ocb);
    if (sts != _RESMGR_DEFAULT) {
        return sts;
    }
    if (msg->i.dcmd != OMEGA_DCMD_EVAL) {
        return ENOTTY;
    }

    omega_io_msg_t *io = (omega_io_msg_t *)_DEVCTL_DATA(msg->i);
    omega_cmd_t cmd_copy = io->cmd;
    omega_reply_t reply;

    uint64_t t0 = ClockCycles();
    omega_gate_eval(&g_gate, &cmd_copy, &reply);

    /* Advance deadtime state machine for OPEN pulse verification */
    if (reply.decision == OMEGA_DEC_OPEN) {
        uint8_t qh = 0, ql = 0;
        for (unsigned c = 0; c <= OMEGA_DEADTIME_CYCLES; ++c) {
            omega_gate_tick_deadtime(&g_gate, &qh, &ql);
        }
        reply.rail_5v_en = qh;
        reply.crowbar_gnd = ql;
        /* Return rail to grounded clamp after single-cycle pulse */
        omega_gate_tick_deadtime(&g_gate, &qh, &ql);
    }

    /* Non-blocking pulse to Process 3 (trap_mirror_daemon) on TRAP */
    if (reply.trap_mirror_strobe && g_mirror_coid >= 0) {
        (void)MsgSendPulse(g_mirror_coid, -1, OMEGA_PULSE_TRAP_CODE, (int)cmd_copy.anomaly_score);
    }
    uint64_t dt_cyc = ClockCycles() - t0;

    printf("[omega_gate_resmgr] seq=%u | %-4s | %4u mV | %-30s | cyc=%llu | head=%.12s\n",
           reply.seq_id,
           omega_decision_name(reply.decision),
           (unsigned)reply.voltage_mv,
           omega_reason_name(reply.reason),
           (unsigned long long)dt_cyc,
           reply.head_hash);
    fflush(stdout);

    io->reply = reply;
    memset(&msg->o, 0, sizeof(msg->o));
    msg->o.nbytes = sizeof(omega_reply_t);
    return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + sizeof(omega_reply_t));
}

int main(void) {
    omega_gate_init(&g_gate);
    g_mirror_coid = name_open(OMEGA_TRAP_MIRROR_NAME, 0);

    dispatch_t *dpp = dispatch_create();
    if (!dpp) {
        perror("dispatch_create");
        return EXIT_FAILURE;
    }

    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max = 1;
    rattr.msg_max_size = 2048;

    static resmgr_connect_funcs_t connect_funcs;
    static resmgr_io_funcs_t io_funcs;
    static iofunc_attr_t attr;

    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs, _RESMGR_IO_NFUNCS, &io_funcs);
    io_funcs.devctl = io_devctl_handler;
    iofunc_attr_init(&attr, S_IFNAM | 0666, NULL, NULL);

    int id = resmgr_attach(dpp, &rattr, OMEGA_DEV_PATH, _FTYPE_ANY, 0,
                           &connect_funcs, &io_funcs, &attr);
    if (id == -1) {
        perror("resmgr_attach");
        return EXIT_FAILURE;
    }

    printf("[omega_gate_resmgr] QNX 8.0 Resource Manager active at %s (mirror_coid=%d)\n",
           OMEGA_DEV_PATH, g_mirror_coid);
    fflush(stdout);

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    while (1) {
        ctp = dispatch_block(ctp);
        if (!ctp) {
            perror("dispatch_block");
            return EXIT_FAILURE;
        }
        dispatch_handler(ctp);
    }
    return EXIT_SUCCESS;
}

#else /* Linux host fallback */

int main(void) {
    omega_gate_t gate;
    omega_gate_init(&gate);
    printf("[omega_gate_resmgr] Host C11 build ready (target QNX 8.0 with `make qnx`).\n");
    printf("[omega_gate_resmgr] Ledger genesis verified: %s\n",
           omega_ledger_verify(&gate) ? "OK" : "FAIL");
    return EXIT_SUCCESS;
}

#endif
