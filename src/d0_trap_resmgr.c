/*
 * d0_trap_resmgr.c — QNX 8.0 Resource Manager (/dev/d0_trap, SCHED_FIFO prio 20)
 *
 * Entry stage of the 4-process cascade:
 *   - Airlock (>= 14 ms), Poincare B^3 boundary check (in Q32.32), and TRAP detection.
 *   - On TRAP: fires non-blocking MsgSendPulse(prio 15) to cascade_mirror_daemon.
 *   - Forwards 128B omega_cascade_req_t to /dev/d1_guestroom and returns 64B reply.
 *   - Keeps open fd + 50 ms heartbeat to /dev/d2_gate.
 */

#include "omega_cascade.h"
#include "omega_gate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNX__

#include <devctl.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/iomsg.h>
#include <sys/neutrino.h>
#include <sys/resmgr.h>
#include <unistd.h>

static int g_d2_fd = -1;
static int g_d1_fd = -1;
static int g_mirror_coid = -1;

static void *d0_heartbeat_thread(void *arg) {
    (void)arg;
    omega_peer_hello_t h = { OMEGA_PEER_D0_TRAP, (int32_t)getpid() };
    while (1) {
        if (g_d2_fd >= 0) {
            (void)devctl(g_d2_fd, OMEGA_DCMD_PEER_HEARTBEAT, &h, sizeof(h), NULL);
        }
        usleep(OMEGA_WDG_HB_INTERVAL_MS * 1000u);
    }
    return NULL;
}

static int d0_io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb) {
    int sts = iofunc_devctl_default(ctp, msg, ocb);
    if (sts != _RESMGR_DEFAULT) return sts;
    if (msg->i.dcmd != OMEGA_DCMD_CASCADE_EVAL) return ENOTTY;

    omega_cascade_io_t *io = (omega_cascade_io_t *)_DEVCTL_DATA(msg->i);
    omega_cascade_io_t fwd;
    fwd.req = io->req;

    /* Default pass-through tag to D1 (0xFF means D0 cleared -> D1 evaluates sluice) */
    fwd.req.reserved = 0xFFu;

    if (!fwd.req.is_l01_reset) {
        if (fwd.req.anomaly_score >= OMEGA_KILL_ANOMALY_TH || fwd.req.anomaly_score < 0) {
            fwd.req.reserved = ((uint32_t)OMEGA_CRSN_KILL_HOSTILE << 8) | (uint32_t)OMEGA_CVERD_KILL;
        } else if (fwd.req.anomaly_score >= 50) {
            /* TRAP -> async side-channel pulse to isolated mirror daemon at 0.00 V DC */
            if (g_mirror_coid >= 0) {
                (void)MsgSendPulse(g_mirror_coid, OMEGA_PRIO_TRAP_MIRROR,
                                   OMEGA_PULSE_TRAP_CODE, (int)fwd.req.anomaly_score);
            }
            fwd.req.reserved = ((uint32_t)OMEGA_CRSN_TRAP_MIRROR << 8) | (uint32_t)OMEGA_CVERD_TRAP;
        } else if (fwd.req.airlock_elapsed_ms < OMEGA_MIN_AIRLOCK_MS) {
            fwd.req.reserved = ((uint32_t)OMEGA_CRSN_HOLD_AIRLOCK << 8) | (uint32_t)OMEGA_CVERD_HOLD;
        }
    }

    if (devctl(g_d1_fd, OMEGA_DCMD_CASCADE_EVAL, &fwd, sizeof(fwd), NULL) != EOK) {
        return EIO;
    }

    io->rep = fwd.rep;
    memset(&msg->o, 0, sizeof(msg->o));
    msg->o.nbytes = sizeof(omega_cascade_rep_t);
    return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + sizeof(omega_cascade_rep_t));
}

int main(void) {
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = OMEGA_PRIO_D0_TRAP;
    (void)sched_setscheduler(0, SCHED_FIFO, &sp);

    for (int i = 0; i < 40 && g_d2_fd < 0; ++i) {
        g_d2_fd = open(OMEGA_DEV_D2_GATE, O_RDWR);
        if (g_d2_fd < 0) usleep(50000);
    }
    for (int i = 0; i < 40 && g_d1_fd < 0; ++i) {
        g_d1_fd = open(OMEGA_DEV_D1_GUESTROOM, O_RDWR);
        if (g_d1_fd < 0) usleep(50000);
    }
    for (int i = 0; i < 20 && g_mirror_coid < 0; ++i) {
        g_mirror_coid = name_open(OMEGA_CASCADE_MIRROR_NAME, 0);
        if (g_mirror_coid < 0) usleep(50000);
    }
    if (g_d2_fd < 0 || g_d1_fd < 0) {
        perror("d0_trap upstream open failed");
        return EXIT_FAILURE;
    }

    omega_peer_hello_t h = { OMEGA_PEER_D0_TRAP, (int32_t)getpid() };
    (void)devctl(g_d2_fd, OMEGA_DCMD_PEER_REGISTER, &h, sizeof(h), NULL);

    pthread_t hb_thr;
    (void)pthread_create(&hb_thr, NULL, d0_heartbeat_thread, NULL);

    dispatch_t *dpp = dispatch_create();
    if (!dpp) { perror("dispatch_create"); return EXIT_FAILURE; }

    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max = 1;
    rattr.msg_max_size = 2048;

    static resmgr_connect_funcs_t connect_funcs;
    static resmgr_io_funcs_t io_funcs;
    static iofunc_attr_t attr;

    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs, _RESMGR_IO_NFUNCS, &io_funcs);
    io_funcs.devctl = d0_io_devctl;
    iofunc_attr_init(&attr, S_IFNAM | 0666, NULL, NULL);

    if (resmgr_attach(dpp, &rattr, OMEGA_DEV_D0_TRAP, _FTYPE_ANY, 0,
                      &connect_funcs, &io_funcs, &attr) == -1) {
        perror("resmgr_attach /dev/d0_trap");
        return EXIT_FAILURE;
    }

    printf("[d0_trap] Active at %s | SCHED_FIFO prio=%d | mirror_coid=%d | pid=%d\n",
           OMEGA_DEV_D0_TRAP, OMEGA_PRIO_D0_TRAP, g_mirror_coid, (int)getpid());
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
    printf("[d0_trap] Host stub (cross-compile with QNX 8.0 qcc).\n");
    return EXIT_SUCCESS;
}

#endif
