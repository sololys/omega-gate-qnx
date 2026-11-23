/*
 * cascade_driver.c — Live QNX 8.0 4-Process Cascade, Causal ToF, Two-Phase L01
 *                    & DCMD_SPI_DATA_XCHNG Hardware Co-Signing Verifier
 *
 * Usage on QNX 8.0:
 *   ./cascade_driver <pid_of_d1_guestroom> [pid_of_spi_fpga_sim] [/dev/spi_fpga_sim]
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
#include <hw/io-spi.h>
#include <signal.h>
#include <unistd.h>

static void make_valid_req(omega_cascade_req_t *r, uint32_t seq_id) {
    memset(r, 0, sizeof(*r));
    r->seq_id = seq_id;
    r->stage = 4u;
    r->prev_stage = 3u;
    r->flags = OMEGA_FLAG_INTENT_VALID | OMEGA_FLAG_WITNESS_OK |
               OMEGA_FLAG_INVOLUTION_OK | OMEGA_FLAG_UWB_LINK_ACTIVE;
    r->pos_x_q16 = HP_Q16_ONE / 4; /* 0.25 inside Poincare B^3 */
    r->pos_y_q16 = 0;
    r->pos_z_q16 = 0;
    r->obstacle_dist_q16 = 5u * (uint32_t)HP_Q16_ONE; /* 5.0 m obstacle clearance */
    r->target_id = 10u;
    r->airlock_elapsed_ms = 20u;
    r->u_raw = 1000;
    r->pi_drift_ppm = 0u;
    r->state_s = 42;
    r->f_f_state_s = 42;
    r->uwb_tof_ns = 42u; /* Causal UWB ToF inside [1, 133] ns */
    omega_cascade_seal_req(r);
}

int main(int argc, char **argv) {
    int kill_d1_pid  = (argc >= 2) ? atoi(argv[1]) : 0;
    int kill_spi_pid = (argc >= 3) ? atoi(argv[2]) : 0;
    const char *spi_dev = (argc >= 4) ? argv[3] : NULL;

    int fd_d0 = open(OMEGA_DEV_D0_TRAP, O_RDWR);
    int fd_d2 = open(OMEGA_DEV_D2_GATE, O_RDWR);
    if (fd_d0 < 0 || fd_d2 < 0) {
        perror("cascade_driver open");
        return EXIT_FAILURE;
    }

    printf("\n=== [PHASE A] 400-CYCLE FSYNC_WAIT -> 5000 mV OPEN (d0 -> d1 -> d2 -> SPI) ===\n");
    fflush(stdout);

    omega_cascade_io_t io;
    for (uint32_t seq = 1u; seq <= 402u; ++seq) {
        make_valid_req(&io.req, seq);
        if (devctl(fd_d0, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) != EOK) {
            perror("devctl /dev/d0_trap");
            return EXIT_FAILURE;
        }
        if (seq == 1u || seq == 400u || seq == 401u || seq == 402u) {
            printf("[driver] seq=%-3u -> verdict=%-15s | %4u mV | omega_y=%4u mV | wn=%016llx | wal=%u\n",
                   io.rep.seq_id,
                   omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv,
                   (unsigned)io.rep.omega_y_mv,
                   (unsigned long long)io.rep.witness_chain_wn,
                   io.rep.ledger_len);
            fflush(stdout);
        }
    }

    printf("\n=== [PHASE A2] CAUSAL TOF GATE (0 ns -> HOLD, 134 ns -> HOLD, 42 ns -> OPEN) ===\n");
    const uint16_t tof_cases[3] = { 0u, 134u, 42u };
    for (int i = 0; i < 3; ++i) {
        make_valid_req(&io.req, 410u + (uint32_t)i);
        io.req.uwb_tof_ns = tof_cases[i];
        io.req.pad[0] = (uint8_t)OMEGA_CVERD_OPEN;
        omega_cascade_seal_req(&io.req);
        if (devctl(fd_d2, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
            printf("[driver] tof=%-3u ns -> verdict=%-4s | %4u mV | reason=%s\n",
                   (unsigned)tof_cases[i],
                   omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv,
                   omega_cascade_reason_name(io.rep.reason_code));
            fflush(stdout);
        }
    }

    if (spi_dev != NULL) {
        printf("\n=== [PHASE A3] DIRECT SPI 63B UNDERFLOW & BAD-CRC REJECTION (%s) ===\n", spi_dev);
        int sfd = open(spi_dev, O_RDWR);
        if (sfd >= 0) {
            struct __attribute__((packed)) { spi_xchng_t hdr; uint8_t data[63]; } x63;
            memset(&x63, 0, sizeof(x63));
            x63.hdr.nbytes = 63u;
            int st63 = devctl(sfd, DCMD_SPI_DATA_XCHNG, &x63, sizeof(x63), NULL);
            printf("[driver] 63B underflow devctl rc=%d (expected EIO=%d) -> %s\n",
                   st63, EIO, (st63 == EIO) ? "PASS" : "FAIL");

            struct __attribute__((packed)) { spi_xchng_t hdr; uint8_t data[128]; } xbad;
            omega_cascade_req_t bad_req;
            make_valid_req(&bad_req, 415u);
            bad_req.crc32 ^= 1u; /* 1-bit CRC corruption */
            xbad.hdr.nbytes = 128u;
            memcpy(xbad.data, &bad_req, 128u);
            (void)devctl(sfd, DCMD_SPI_DATA_XCHNG, &xbad, sizeof(xbad), NULL);

            struct __attribute__((packed)) { spi_xchng_t hdr; uint8_t data[64]; } xpoll;
            memset(&xpoll, 0, sizeof(xpoll));
            xpoll.hdr.nbytes = 64u;
            (void)devctl(sfd, DCMD_SPI_DATA_XCHNG, &xpoll, sizeof(xpoll), NULL);
            omega_cascade_rep_t bad_rep;
            memcpy(&bad_rep, xpoll.data, 64u);
            printf("[driver] 1-bit CRC flip -> verdict=%s | %4u mV | reason=%s -> %s\n",
                   omega_cascade_verdict_name(bad_rep.verdict),
                   (unsigned)bad_rep.actuator_mv,
                   omega_cascade_reason_name(bad_rep.reason_code),
                   (bad_rep.actuator_mv == 0u && bad_rep.reason_code == OMEGA_CRSN_SPI_IO_FAULT) ? "PASS" : "FAIL");
            fflush(stdout);
            close(sfd);
        }
    }

    printf("\n=== [PHASE B] TRAP ANOMALY (score=75) -> ASYNC PULSE TO MIRROR ===\n");
    make_valid_req(&io.req, 420u);
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

    if (kill_spi_pid > 0) {
        printf("\n=== [PHASE E] SPI FAULT INJECTION (`kill -9 %d` on spi_fpga_sim) -> 0 mV FAIL-CLOSED ===\n",
               kill_spi_pid);
        kill((pid_t)kill_spi_pid, SIGKILL);
        usleep(100000);
        make_valid_req(&io.req, 425u);
        io.req.pad[0] = (uint8_t)OMEGA_CVERD_OPEN;
        if (devctl(fd_d2, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
            printf("[driver] seq=%-3u (OPEN with dead SPI) -> verdict=%-4s | %4u mV | reason=%s\n",
                   io.rep.seq_id,
                   omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv,
                   omega_cascade_reason_name(io.rep.reason_code));
            fflush(stdout);
        }
    }

    if (kill_d1_pid > 0) {
        printf("\n=== [PHASE C] LIVE `kill -9 %d` ON d1_guestroom -> WATCHDOG _IO_CLOSE ===\n", kill_d1_pid);
        fflush(stdout);
        kill((pid_t)kill_d1_pid, SIGKILL);
        usleep(100000);

        make_valid_req(&io.req, 430u);
        io.req.pad[0] = (uint8_t)OMEGA_CVERD_OPEN;
        if (devctl(fd_d2, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
            printf("[driver] seq=%-3u (OPEN after kill -9) -> verdict=%-4s | %4u mV | reason=%s | wdg_lock=%u\n",
                   io.rep.seq_id,
                   omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv,
                   omega_cascade_reason_name(io.rep.reason_code),
                   (unsigned)((io.rep.flags_out & OMEGA_OUT_WATCHDOG_LOCKED) != 0));
            fflush(stdout);
        }

        printf("\n=== [PHASE D] TWO-PHASE L01 RESET (ARM -> EARLY REJECT/RESTART -> COOLDOWN -> OK) ===\n");
        /* Phase 1: Arm */
        memset(&io.req, 0, sizeof(io.req));
        io.req.seq_id = 431u;
        io.req.is_l01_reset = 1u;
        omega_compute_l01_key_hash16(OMEGA_L01_KEY_TOKEN, io.req.l01_key_hash16);
        omega_cascade_seal_req(&io.req);
        if (devctl(fd_d2, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
            printf("[driver] seq=%-3u (L01 Phase 1 Arm)    -> verdict=%-4s | %4u mV | reason=%s\n",
                   io.rep.seq_id, omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv, omega_cascade_reason_name(io.rep.reason_code));
        }

        /* Impatient attempt after 50 ms (< 200 ms cooldown) -> MUST reject & restart timer */
        usleep(50000);
        io.req.seq_id = 432u;
        omega_cascade_seal_req(&io.req);
        if (devctl(fd_d2, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
            printf("[driver] seq=%-3u (L01 Early 50ms)     -> verdict=%-4s | %4u mV | reason=%s\n",
                   io.rep.seq_id, omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv, omega_cascade_reason_name(io.rep.reason_code));
        }

        /* Wait 250 ms (> 200 ms after restart) -> Phase 2 confirmation succeeds */
        usleep(250000);
        io.req.seq_id = 433u;
        omega_cascade_seal_req(&io.req);
        if (devctl(fd_d2, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
            printf("[driver] seq=%-3u (L01 Phase 2 +250ms) -> verdict=%-4s | %4u mV | reason=%s | wal=%u\n",
                   io.rep.seq_id, omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv, omega_cascade_reason_name(io.rep.reason_code),
                   io.rep.ledger_len);
            fflush(stdout);
        }

        /* seq=434: d1_guestroom is STILL dead -> OPEN must remain DENIED (0 mV) */
        make_valid_req(&io.req, 434u);
        io.req.pad[0] = (uint8_t)OMEGA_CVERD_OPEN;
        if (devctl(fd_d2, OMEGA_DCMD_CASCADE_EVAL, &io, sizeof(io), NULL) == EOK) {
            printf("[driver] seq=%-3u (OPEN while d1 dead) -> verdict=%-4s | %4u mV | reason=%s | wdg_lock=%u\n",
                   io.rep.seq_id, omega_cascade_verdict_name(io.rep.verdict),
                   (unsigned)io.rep.actuator_mv, omega_cascade_reason_name(io.rep.reason_code),
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
