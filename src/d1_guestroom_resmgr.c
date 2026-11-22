/*
 * d1_guestroom_resmgr.c — QNX 8.0 Resource Manager (/dev/d1_guestroom, SCHED_FIFO prio 25)
 *
 * Runs the zero-float C11 Dual-Rate HashPrune Sluice (400-cycle FSYNC_WAIT,
 * dtau_min = 1/16 Zeno guard, pi_drift_ppm) and forwards 128B requests to /dev/d2_gate.
 * Maintains an open fd + 50 ms heartbeat to /dev/d2_gate so `kill -9` triggers _IO_CLOSE.
 */

#include "omega_cascade.h"

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

static int        g_d2_fd = -1;
static hp_sluice_t g_sluice;

static void *d1_heartbeat_thread(void *arg) {
    (void)arg;
    omega_peer_hello_t h = { OMEGA_PEER_D1_GUESTROOM, (int32_t)getpid() };
    while (1) {
        if (g_d2_fd >= 0) {
            (void)devctl(g_d2_fd, OMEGA_DCMD_PEER_HEARTBEAT, &h, sizeof(h), NULL);
        }
        usleep(OMEGA_WDG_HB_INTERVAL_MS * 1000u);
    }
    return NULL;
}

static uint8_t map_sluice_to_verdict(hp_step_result_t r, uint32_t *out_rsn) {
    switch (r) {
        case HP_RES_OPEN:            *out_rsn = OMEGA_CRSN_OK; return OMEGA_CVERD_OPEN;
        case HP_RES_CONTINUOUS_PASS: *out_rsn = OMEGA_CRSN_CONTINUOUS_PASS; return OMEGA_CVERD_CONTINUOUS_PASS;
        case HP_RES_FSYNC_WAIT:      *out_rsn = OMEGA_CRSN_FSYNC_WAITING; return OMEGA_CVERD_FSYNC_WAIT;
        case HP_RES_ESCALATED_EXT:   *out_rsn = OMEGA_CRSN_ESCALATED_STALLED; return OMEGA_CVERD_ESCALATED_EXT;
        case HP_RES_KILL:            *out_rsn = OMEGA_CRSN_KILL_INVOLUTION; return OMEGA_CVERD_KILL;
        case HP_RES_KILL_LATCHED:    *out_rsn = OMEGA_CRSN_KILL_LATCHED; return OMEGA_CVERD_KILL;
        default:                     *out_rsn = OMEGA_CRSN_HOLD_DRIFT; return OMEGA_CVERD_HOLD;
    }
}

static int d1_io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb) {
    int sts = iofunc_devctl_default(ctp, msg, ocb);
    if (sts != _RESMGR_DEFAULT) return sts;
    if (msg->i.dcmd != OMEGA_DCMD_CASCADE_EVAL) return ENOTTY;

    omega_cascade_io_t *io = (omega_cascade_io_t *)_DEVCTL_DATA(msg->i);
    omega_cascade_io_t fwd;
    fwd.req = io->req;

    uint8_t d0_v = fwd.req.pad[0];
    if (!fwd.req.is_l01_reset && d0_v != OMEGA_CVERD_KILL && d0_v != OMEGA_CVERD_TRAP && d0_v != OMEGA_CVERD_HOLD) {
        /* Use dedicated physical obstacle clearance (byte 92..95), keeping byte 16..27 strictly Poincare B^3 */
        int32_t obs_pos[HP_MAX_DIM] = { (int32_t)fwd.req.obstacle_dist_q16, 0, 0 };
        bool inv_ok = ((fwd.req.flags & (OMEGA_FLAG_REVERSE_CLOSED | OMEGA_FLAG_INVOLUTION_OK)) != 0) &&
                      (fwd.req.state_s == fwd.req.f_f_state_s);
        bool wit_ok = (fwd.req.flags & OMEGA_FLAG_WITNESS_OK) != 0;

        hp_step_result_t sr = hp_sluice_step(&g_sluice, fwd.req.target_id, obs_pos,
                                             fwd.req.pi_drift_ppm, inv_ok, wit_ok);
        uint32_t rsn = OMEGA_CRSN_OK;
        uint8_t v = map_sluice_to_verdict(sr, &rsn);
        fwd.req.pad[0] = v;
        fwd.req.pad[1] = (uint8_t)(rsn & 0xFFu);
    }

    if (devctl(g_d2_fd, OMEGA_DCMD_CASCADE_EVAL, &fwd, sizeof(fwd), NULL) != EOK) {
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
    sp.sched_priority = OMEGA_PRIO_D1_GUESTROOM;
    (void)sched_setscheduler(0, SCHED_FIFO, &sp);

    /* Wait briefly for /dev/d2_gate */
    for (int i = 0; i < 40 && g_d2_fd < 0; ++i) {
        g_d2_fd = open(OMEGA_DEV_D2_GATE, O_RDWR);
        if (g_d2_fd < 0) usleep(50000);
    }
    if (g_d2_fd < 0) { perror("open /dev/d2_gate"); return EXIT_FAILURE; }

    omega_peer_hello_t h = { OMEGA_PEER_D1_GUESTROOM, (int32_t)getpid() };
    (void)devctl(g_d2_fd, OMEGA_DCMD_PEER_REGISTER, &h, sizeof(h), NULL);

    /* Initialize Dual-Rate HashPrune Sluice (400-cycle FSYNC_WAIT, dtau_min=1/16) */
    static const int32_t origin[HP_MAX_DIM] = {0, 0, 0};
    static const int32_t planes[2][HP_MAX_DIM] = {
        { HP_Q16_ONE, 0, 0 },
        { 0, HP_Q16_ONE, 0 }
    };
    hp_reservoir_t res;
    hp_reservoir_init(&res, 1, 2, origin, 2, planes, 4);
    hp_sluice_init(&g_sluice, &res, 4LL * HP_Q32_ONE, 10000u,
                   1000LL * HP_Q16_ONE, HP_Q16_ONE, HP_Q16_ONE / 16, 400u);

    pthread_t hb_thr;
    (void)pthread_create(&hb_thr, NULL, d1_heartbeat_thread, NULL);

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
    io_funcs.devctl = d1_io_devctl;
    iofunc_attr_init(&attr, S_IFNAM | 0666, NULL, NULL);

    if (resmgr_attach(dpp, &rattr, OMEGA_DEV_D1_GUESTROOM, _FTYPE_ANY, 0,
                      &connect_funcs, &io_funcs, &attr) == -1) {
        perror("resmgr_attach /dev/d1_guestroom");
        return EXIT_FAILURE;
    }

    printf("[d1_guestroom] Active at %s | SCHED_FIFO prio=%d | fsync=400 | pid=%d\n",
           OMEGA_DEV_D1_GUESTROOM, OMEGA_PRIO_D1_GUESTROOM, (int)getpid());
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
    printf("[d1_guestroom] Host stub (cross-compile with QNX 8.0 qcc).\n");
    return EXIT_SUCCESS;
}

#endif
