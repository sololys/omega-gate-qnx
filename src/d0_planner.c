/*
 * Process 1: d0_planner — Low-priority proposal generator (0.00 V DC, zero HW access).
 * Sends 7 canonical test vectors to /dev/omega_gate on QNX 8.0 (or runs locally on host).
 */

#include "omega_gate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNX__
#include <devctl.h>
#include <fcntl.h>
#include <unistd.h>
#define OMEGA_DCMD_EVAL __DIOTF(_DCMD_MISC, 1, omega_cmd_t)
#endif

static void send_and_print(int fd, omega_gate_t *local_gate, const omega_cmd_t *cmd) {
    omega_reply_t rep;
#ifdef __QNX__
    (void)local_gate;
    union {
        omega_cmd_t   in;
        omega_reply_t out;
    } box;
    box.in = *cmd;
    if (devctl(fd, OMEGA_DCMD_EVAL, &box, sizeof(box), NULL) != 0) {
        perror("devctl(/dev/omega_gate)");
        exit(EXIT_FAILURE);
    }
    rep = box.out;
#else
    (void)fd;
    omega_gate_eval(local_gate, cmd, &rep);
#endif
    printf("[d0_planner] seq=%u | %-4s | %4u mV | kill=%u | trap=%u | %-30s | hash=%.12s\n",
           rep.seq_id,
           omega_decision_name(rep.decision),
           (unsigned)rep.voltage_mv,
           (unsigned)rep.kill_latched,
           (unsigned)rep.trap_mirror_strobe,
           omega_reason_name(rep.reason),
           rep.head_hash);
}

int main(void) {
    int fd = -1;
    omega_gate_t local_gate;
    omega_gate_init(&local_gate);

#ifdef __QNX__
    fd = open(OMEGA_DEV_PATH, O_RDWR);
    if (fd < 0) {
        perror("open(/dev/omega_gate)");
        return EXIT_FAILURE;
    }
    printf("[d0_planner] Connected to QNX 8.0 gate at %s\n", OMEGA_DEV_PATH);
#else
    printf("[d0_planner] Running in Linux host simulation mode\n");
#endif

    omega_cmd_t seq[7];
    memset(seq, 0, sizeof(seq));

    /* 1. Valid COMMITTED -> OPEN (5000 mV) */
    seq[0] = (omega_cmd_t){ 1, 1000, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_VIABILITY, 40000, 10000, 0, 1, 15, 0, "" };
    /* 2. Intermediate stage RAW -> ESTIMATE -> HOLD (0 mV) */
    seq[1] = (omega_cmd_t){ 2, 1050, OMEGA_STAGE_ESTIMATE,  OMEGA_STAGE_RAW,       10000,  2000, 0, 1, 20, 0, "" };
    /* 3. Unwitnessed COMMITTED -> HOLD (0 mV) */
    seq[2] = (omega_cmd_t){ 3, 1100, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_VIABILITY, 40000, 10000, 0, 0, 15, 0, "" };
    /* 4. Suspicious anomaly -> TRAP (0 mV + QNX pulse to trap_mirror_daemon) */
    seq[3] = (omega_cmd_t){ 4, 1150, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_VIABILITY, 40000, 10000, 42, 1, 15, 0, "" };
    /* 5. Forbidden shortcut RAW -> COMMITTED -> sticky KILL (0 mV) */
    seq[4] = (omega_cmd_t){ 5, 1200, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_RAW,       40000, 10000, 0, 1, 15, 0, "" };
    /* 6. Valid command while KILL latched -> still KILL (0 mV) */
    seq[5] = (omega_cmd_t){ 6, 1250, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_VIABILITY, 20000,  5000, 0, 1, 20, 0, "" };
    /* 7. Explicit Level-01 operator reset -> append-only return to HOLD (0 mV) */
    seq[6].seq_id = 7;
    seq[6].is_l01_reset = 1;
    strncpy(seq[6].l01_token, OMEGA_L01_KEY_TOKEN, sizeof(seq[6].l01_token) - 1u);

    for (size_t i = 0; i < 7; ++i) {
        send_and_print(fd, &local_gate, &seq[i]);
    }

#ifdef __QNX__
    close(fd);
#else
    printf("[d0_planner] Host SHA-256 ledger integrity: %s (%u entries)\n",
           omega_ledger_verify(&local_gate) ? "PASS" : "FAIL", local_gate.ledger_len);
#endif
    return EXIT_SUCCESS;
}
