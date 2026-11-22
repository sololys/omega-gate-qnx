/*
 * Process 3: trap_mirror_daemon — Isolated mirror chamber receiving non-blocking
 * QNX 8.0 pulses (OMEGA_PULSE_TRAP_CODE) from omega_gate_resmgr.
 */

#include "omega_gate.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef __QNX__
#include <sys/dispatch.h>
#include <sys/neutrino.h>

int main(void) {
    name_attach_t *attach = name_attach(NULL, OMEGA_TRAP_MIRROR_NAME, 0);
    if (!attach) {
        perror("name_attach");
        return EXIT_FAILURE;
    }

    printf("[trap_mirror_daemon] Listening for TRAP pulses on '%s'...\n", OMEGA_TRAP_MIRROR_NAME);
    fflush(stdout);

    struct _pulse pulse;
    uint32_t captured = 0;
    while (1) {
        int rcvid = MsgReceivePulse(attach->chid, &pulse, sizeof(pulse), NULL);
        if (rcvid < 0) {
            perror("MsgReceivePulse");
            break;
        }
        if (pulse.code == OMEGA_PULSE_TRAP_CODE) {
            captured++;
            printf("[trap_mirror_daemon] CAPTURED #%u | anomaly_score=%d | isolated at 0.00 V DC\n",
                   captured, pulse.value.sival_int);
            fflush(stdout);
        }
    }

    name_detach(attach, 0);
    return EXIT_SUCCESS;
}

#else

int main(void) {
    printf("[trap_mirror_daemon] Host C11 stub ready (target QNX 8.0 with `make qnx`).\n");
    return EXIT_SUCCESS;
}

#endif
