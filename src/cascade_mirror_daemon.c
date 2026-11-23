/*
 * cascade_mirror_daemon.c — Isolated TRAP Mirror Process (SCHED_FIFO prio 15)
 *
 * Receives non-blocking TRAP pulses from /dev/d0_trap at 0.00 V DC and
 * maintains a registered heartbeat fd to /dev/d2_gate.
 */

#include "omega_cascade.h"
#include "omega_gate.h"
#include "qnx_rt_cage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNX__

#include <devctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include <unistd.h>

static int g_d2_fd = -1;

static void *mirror_heartbeat_thread(void *arg) {
    (void)arg;
    omega_peer_hello_t h = { OMEGA_PEER_TRAP_MIRROR, (int32_t)getpid() };
    while (1) {
        if (g_d2_fd >= 0) {
            (void)devctl(g_d2_fd, OMEGA_DCMD_PEER_HEARTBEAT, &h, sizeof(h), NULL);
        }
        usleep(OMEGA_WDG_HB_INTERVAL_MS * 1000u);
    }
    return NULL;
}

int main(void) {
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = OMEGA_PRIO_TRAP_MIRROR;
    (void)sched_setscheduler(0, SCHED_FIFO, &sp);

    for (int i = 0; i < 40 && g_d2_fd < 0; ++i) {
        g_d2_fd = open(OMEGA_DEV_D2_GATE, O_RDWR);
        if (g_d2_fd < 0) usleep(50000);
    }
    if (g_d2_fd < 0) { perror("open /dev/d2_gate"); return EXIT_FAILURE; }

    omega_peer_hello_t h = { OMEGA_PEER_TRAP_MIRROR, (int32_t)getpid() };
    (void)devctl(g_d2_fd, OMEGA_DCMD_PEER_REGISTER, &h, sizeof(h), NULL);

    pthread_t hb_thr;
    (void)pthread_create(&hb_thr, NULL, mirror_heartbeat_thread, NULL);

    name_attach_t *attach = name_attach(NULL, OMEGA_CASCADE_MIRROR_NAME, 0);
    if (!attach) { perror("name_attach"); return EXIT_FAILURE; }

    if (omega_qnx_lock_memory_and_sandbox() != 0) {
        return EXIT_FAILURE;
    }

    printf("[trap_mirror_daemon] Active on '%s' | SCHED_FIFO prio=%d (mlock+sandbox) | 0.00 V DC | pid=%d\n",
           OMEGA_CASCADE_MIRROR_NAME, OMEGA_PRIO_TRAP_MIRROR, (int)getpid());
    fflush(stdout);

    struct _pulse pulse;
    uint32_t count = 0;
    while (1) {
        int rcvid = MsgReceivePulse(attach->chid, &pulse, sizeof(pulse), NULL);
        if (rcvid == 0 && pulse.code == OMEGA_PULSE_TRAP_CODE) {
            count++;
            printf("[trap_mirror_daemon] ISOLATED TRAP #%u | anomaly=%d | rail=0.00 V DC\n",
                   count, pulse.value.sival_int);
            fflush(stdout);
        }
    }
    return EXIT_SUCCESS;
}

#else

int main(void) {
    printf("[trap_mirror_daemon] Host stub (cross-compile with QNX 8.0 qcc).\n");
    return EXIT_SUCCESS;
}

#endif
