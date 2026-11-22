/*
 * ser2_capsule_bridge.c — QNX 8.0 /dev/ser2 <-> /dev/d0_trap 205B Ingress Bridge
 *
 * Reads exact 288-byte omega_capsule_ingress_t frames from a serial device
 * (default /dev/ser2 via devc-ser8250), forwards each frame via
 * devctl(OMEGA_DCMD_CAPSULE205_EVAL) into /dev/d0_trap (SCHED_FIFO prio 20),
 * and writes the exact 64-byte omega_cascade_rep_t back over the serial link.
 */

#include "omega_capsule205b.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNX__

#include <devctl.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return 0;
        got += (size_t)r;
    }
    return 1;
}

static int write_exact(int fd, const uint8_t *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *ser_path = (argc > 1) ? argv[1] : "/dev/ser2";
    int max_frames = (argc > 2) ? atoi(argv[2]) : 0;

    int ser_fd = -1;
    for (int i = 0; i < 40 && ser_fd < 0; ++i) {
        ser_fd = open(ser_path, O_RDWR);
        if (ser_fd < 0) usleep(50000);
    }
    if (ser_fd < 0) {
        perror("ser2_capsule_bridge open serial");
        return EXIT_FAILURE;
    }

    struct termios tio;
    if (tcgetattr(ser_fd, &tio) == 0) {
        cfmakeraw(&tio);
        tio.c_cflag &= ~(unsigned)(IHFLOW | OHFLOW);
        cfsetispeed(&tio, B115200);
        cfsetospeed(&tio, B115200);
        tio.c_cc[VMIN]  = 1;
        tio.c_cc[VTIME] = 0;
        (void)tcsetattr(ser_fd, TCSANOW, &tio);
    }

    int d0_fd = -1;
    for (int i = 0; i < 40 && d0_fd < 0; ++i) {
        d0_fd = open(OMEGA_DEV_D0_TRAP, O_RDWR);
        if (d0_fd < 0) usleep(50000);
    }
    if (d0_fd < 0) {
        perror("ser2_capsule_bridge open /dev/d0_trap");
        close(ser_fd);
        return EXIT_FAILURE;
    }

    printf("[ser2_bridge] Ready on %s -> %s (288B in / 64B out)\n", ser_path, OMEGA_DEV_D0_TRAP);
    fflush(stdout);

    int count = 0;
    while (max_frames <= 0 || count < max_frames) {
        omega_capsule_io_t io;
        int rc = read_exact(ser_fd, (uint8_t *)&io.ingress, sizeof(io.ingress));
        if (rc <= 0) break;

        if (devctl(d0_fd, OMEGA_DCMD_CAPSULE205_EVAL, &io, sizeof(io), NULL) != EOK) {
            memset(&io.rep, 0, sizeof(io.rep));
            io.rep.verdict     = OMEGA_CVERD_KILL;
            io.rep.stop_stage  = 2u;
            io.rep.omega_y_mv  = 5000u;
            io.rep.reason_code = OMEGA_CRSN_KILL_HOSTILE;
        }

        printf("[ser2_bridge] frame=%d seq=%u -> verdict=%s mv=%u rsn=%s\n",
               count,
               (unsigned)io.rep.seq_id,
               omega_cascade_verdict_name(io.rep.verdict),
               (unsigned)io.rep.actuator_mv,
               omega_cascade_reason_name(io.rep.reason_code));
        fflush(stdout);

        if (write_exact(ser_fd, (const uint8_t *)&io.rep, sizeof(io.rep)) <= 0) break;
        count++;
    }

    close(d0_fd);
    close(ser_fd);
    return EXIT_SUCCESS;
}

#else

int main(void) {
    printf("[ser2_bridge] Host stub (cross-compile with QNX 8.0 qcc).\n");
    return EXIT_SUCCESS;
}

#endif
