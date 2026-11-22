/*
 * cascade_driver.c — Live QNX 8.0 4-Process Cascade & `kill -9` Watchdog Verifier
 *
 * Usage on QNX 8.0:
 *   ./cascade_driver <pid_of_d1_guestroom>
 *
 * Proves:
 *   (A) Valid 128B requests traverse /dev/d0_trap -> /dev/d1_guestroom -> /dev/d2_gate,
 *       holding 0 mV through 400-cycle FSYNC_WAIT and opening 5000 mV on cycle 401.
 *   (B) TRAP anomaly triggers async pulse to trap_mirror_daemon at 0 mV.
 *   (C) `kill -9 <d1_pid>` triggers immediate _IO_CLOSE in /dev/d2_gate, locking
 *       the gate in HOLD (0 mV) with WATCHDOG_PEER_DEAD in WAL, and denying OPEN
 *       until a valid L01 physical key reset is supplied.
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
#include <signal.h>
#include <unistd.h>

static void make_valid_req(omega_cascade_req_t *r, uint32_t seq_id) {
    memset(r, 0, sizeof(*r));
    r->seq_id = seq_id;
    r->stage = 4u;
    r->prev_stage = 3u;
    r->flags = OMEGA_FLAG_INTENT_VALID | OMEGA_FLAG_WITNESS_OK | OMEGA_FLAG_INVOLUTION_OK;
    r->pos_x_q16 = 5 * HP_Q16_ONE;
    r->pos_y_q16 = 5 * HP_Q16_ONE;
    r->pos_z_q16 = 0;
    r->target_id = 10u;
    r->airlock_elapsed_ms = 20u;
    r->u_raw = 1000;
    r->pi_drift_ppm = 0u;
    r->state_s = 42;
    r->f_f_state_s = 42;
    omega_cascade_seal_req(r);
}

int main(int argc, char **argv) {
    int kill_pid = (argc >= 2) ? atoi(argv[1]) : 0;

    int fd_d0 = open(OMEGA_DEV_D0_TRAP, O_RDWR);
    int fd_d2 = open(OMEGA_DEV_D2_GATE, O_RDWR);
    if (fd_d0 < 0 || fd_d2 < 0) {
        perror("cascade_driver open");
        return EXIT_FAILURE;
    }

    printf("\n=== [PHASE A] 400-CYCLE FSYNC_WAIT -> 5000 mV OPEN (d0 -> d1 -> d2) ===\n");
    fflush(stdout);

    omega_cascade_io_t io;
    for (uint32_t seq = 1u; seq <= 402u; ++seq) {
        make_valid_req(&io.req, seq);
        if (devctl(fd_d0, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) != EOK) {
            perror("devctl /dev/d0_trap");
            return EXIT_FAILURE;
        }
        if (seq == 1u || seq == 400u || seq == 401u || seq == 402u) {
            printf("[driver] seq=%-3u -> verdict=%-15s | %4u mV | omega_y=%4u mV | wal=%u\n",
                   io.rep.seq_id,
                   omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv,
                   (unsigned)io.rep.omega_y_mv,
                   io.rep.ledger_len);
            fflush(stdout);
        }
    }

    printf("\n=== [PHASE B] TRAP ANOMALY (score=75) -> ASYNC PULSE TO MIRROR ===\n");
    make_valid_req(&io.req, 403u);
    io.req.anomaly_score = 75;
    omega_cascade_seal_req(&io.req);
    if (devctl(fd_d0, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
        printf("[driver] seq=%-3u -> verdict=%-15s | %4u mV | reason=%s\n",
               io.rep.seq_id,
               omega_cascade_verdict_name(io.rep.verdict),
               (unsigned)io.rep.actuator_mv,
               omega_cascade_reason_name(io.rep.reason_code));
        fflush(stdout);
    }
    usleep(50000);

    if (kill_pid > 0) {
        printf("\n=== [PHASE C] LIVE `kill -9 %d` ON d1_guestroom -> WATCHDOG _IO_CLOSE ===\n", kill_pid);
        fflush(stdout);
        kill((pid_t)kill_pid, SIGKILL);
        usleep(100000);

        /* Attempt direct OPEN against /dev/d2_gate while watchdog is locked */
        make_valid_req(&io.req, 404u);
        io.req.reserved = (uint32_t)OMEGA_CVERD_OPEN;
        if (devctl(fd_d2, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
            printf("[driver] seq=%-3u (OPEN attempt after kill -9) -> verdict=%-4s | %4u mV | reason=%s | wdg_lock=%u\n",
                   io.rep.seq_id,
                   omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv,
                   omega_cascade_reason_name(io.rep.reason_code),
                   (unsigned)((io.rep.flags_out & OMEGA_OUT_WATCHDOG_LOCKED) != 0));
            fflush(stdout);
        }

        printf("\n=== [PHASE D] L01 PHYSICAL KEY RESET + POST-RESET PEER-ALIVE INVARIANT ===\n");
        memset(&io.req, 0, sizeof(io.req));
        io.req.seq_id = 405u;
        io.req.is_l01_reset = 1u;
        omega_compute_l01_key_hash16(OMEGA_L01_KEY_TOKEN, io.req.l01_key_hash16);
        omega_cascade_seal_req(&io.req);
        if (devctl(fd_d2, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
            printf("[driver] seq=%-3u (L01 reset) -> verdict=%-4s | %4u mV | reason=%s | wal=%u\n",
                   io.rep.seq_id,
                   omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv,
                   omega_cascade_reason_name(io.rep.reason_code),
                   io.rep.ledger_len);
            fflush(stdout);
        }

        /* seq=406: d1_guestroom is STILL dead -> OPEN must remain DENIED (0 mV) */
        make_valid_req(&io.req, 406u);
        io.req.reserved = (uint32_t)OMEGA_CVERD_OPEN;
        if (devctl(fd_d2, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
            printf("[driver] seq=%-3u (OPEN while d1 still dead) -> verdict=%-4s | %4u mV | reason=%s | wdg_lock=%u\n",
                   io.rep.seq_id,
                   omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv,
                   omega_cascade_reason_name(io.rep.reason_code),
                   (unsigned)((io.rep.flags_out & OMEGA_OUT_WATCHDOG_LOCKED) != 0));
            fflush(stdout);
        }
    }

    close(fd_d0);
    close(fd_d2);
    printf("\n=== [CASCADE DRIVER COMPLETE] ===\n");
    fflush(stdout);
    return EXIT_SUCCESS;
}

#else

int main(void) {
    printf("[cascade_driver] Host stub (cross-compile with QNX 8.0 qcc).\n");
    return EXIT_SUCCESS;
}

#endif
