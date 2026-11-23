/*
 * spi_fpga_sim_resmgr.c — QNX 8.0 SPI Slave Simulator Resource Manager
 *
 * Implements the standard QNX <hw/io-spi.h> devctl interface
 * (DCMD_SPI_SET_CONFIG, DCMD_SPI_GET_DRVINFO, DCMD_SPI_GET_DEVINFO,
 *  DCMD_SPI_DATA_XCHNG) on /dev/spi_fpga_sim (or argv[1]).
 *
 * Protocol:
 *   - 128 B TX : Verifies IEEE 802.3 CRC-32 and causal ToF (1 <= uwb_tof_ns <= 133).
 *                Updates internal 64 B omega_cascade_rep_t and returns previous reply.
 *   -  64 B TX (all 0x00): Read-only MISO status poll returning fresh 64 B reply
 *                without mutating state or asserting error latch.
 *   - Any other length (e.g. 63 B underflow) or non-zero 64 B: sets fail-closed
 *                HOLD (0 mV, OMEGA_CRSN_SPI_IO_FAULT) and returns EIO.
 */

#include "omega_cascade.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __QNX__

#include <devctl.h>
#include <errno.h>
#include <hw/io-spi.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/resmgr.h>
#include <unistd.h>

static spi_cfg_t           g_spi_cfg = {
    .mode = SPI_MODE_WORD_WIDTH_8 | SPI_MODE_CPHA_0 | SPI_MODE_CPOL_0 | SPI_MODE_BODER_MSB,
    .clock_rate = 1000000u
};
static omega_cascade_rep_t g_last_rep;
static uint64_t            g_wn_chain = 0x0070464153455350ULL;
static uint32_t            g_tx_count = 0u;

static bool is_all_zero(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (buf[i] != 0u) return false;
    }
    return true;
}

static int spi_sim_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb) {
    int sts = iofunc_devctl_default(ctp, msg, ocb);
    if (sts != _RESMGR_DEFAULT) return sts;

    switch (msg->i.dcmd) {
        case DCMD_SPI_SET_CONFIG: {
            spi_cfg_t *cfg = (spi_cfg_t *)_DEVCTL_DATA(msg->i);
            g_spi_cfg = *cfg;
            memset(&msg->o, 0, sizeof(msg->o));
            return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o));
        }

        case DCMD_SPI_GET_DRVINFO: {
            spi_drvinfo_t *info = (spi_drvinfo_t *)_DEVCTL_DATA(msg->o);
            memset(info, 0, sizeof(*info));
            info->version = (SPI_VERSION_MAJOR << SPI_VERMAJOR_SHIFT);
            snprintf(info->name, sizeof(info->name), "spi_fpga_sim");
            memset(&msg->o, 0, sizeof(msg->o));
            msg->o.nbytes = sizeof(*info);
            return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + sizeof(*info));
        }

        case DCMD_SPI_GET_DEVINFO: {
            spi_devinfo_t *info = (spi_devinfo_t *)_DEVCTL_DATA(msg->o);
            memset(info, 0, sizeof(*info));
            info->devno = 0;
            snprintf(info->name, sizeof(info->name), "fpga_sim0");
            info->current_clkrate = g_spi_cfg.clock_rate;
            info->cfg = g_spi_cfg;
            memset(&msg->o, 0, sizeof(msg->o));
            msg->o.nbytes = sizeof(*info);
            return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + sizeof(*info));
        }

        case DCMD_SPI_DATA_XCHNG: {
            spi_xchng_t *x = (spi_xchng_t *)_DEVCTL_DATA(msg->i);
            uint32_t n = x->nbytes;
            uint8_t *payload = x->data;

            if (n == 64u && is_all_zero(payload, 64u)) {
                /* Read-only 64 B 0x00 status poll: return fresh g_last_rep */
                memcpy(payload, &g_last_rep, 64u);
                memset(&msg->o, 0, sizeof(msg->o));
                msg->o.nbytes = sizeof(spi_xchng_t) + 64u;
                return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + sizeof(spi_xchng_t) + 64u);
            }

            if (n != 128u) {
                /* Reject truncated/invalid frames (e.g. 63 B underflow) fail-closed */
                memset(&g_last_rep, 0, sizeof(g_last_rep));
                g_last_rep.verdict     = OMEGA_CVERD_HOLD;
                g_last_rep.stop_stage  = 1u;
                g_last_rep.actuator_mv = 0u;
                g_last_rep.omega_y_mv  = 5000u;
                g_last_rep.flags_out   = OMEGA_OUT_CROWBAR_GND | OMEGA_OUT_WATCHDOG_LOCKED;
                g_last_rep.reason_code = OMEGA_CRSN_SPI_IO_FAULT;
                printf("[spi_fpga_sim] REJECT frame len=%u B (expected 128 B or 64 B 0x00) -> EIO\n",
                       (unsigned)n);
                fflush(stdout);
                return EIO;
            }

            omega_cascade_req_t req;
            memcpy(&req, payload, 128u);

            /* Return pipelined previous reply in first 64 B of MISO payload */
            omega_cascade_rep_t prev_rep = g_last_rep;
            memset(payload, 0, 128u);
            memcpy(payload, &prev_rep, 64u);

            /* Evaluate incoming 128 B request */
            omega_cascade_rep_t next_rep;
            memset(&next_rep, 0, sizeof(next_rep));
            next_rep.seq_id     = req.seq_id;
            next_rep.omega_y_mv = 5000u;

            if (!omega_cascade_verify_req(&req)) {
                next_rep.verdict          = OMEGA_CVERD_HOLD;
                next_rep.stop_stage       = 1u;
                next_rep.actuator_mv      = 0u;
                next_rep.flags_out        = OMEGA_OUT_CROWBAR_GND | OMEGA_OUT_WATCHDOG_LOCKED;
                next_rep.reason_code      = OMEGA_CRSN_SPI_IO_FAULT;
                next_rep.witness_chain_wn = g_wn_chain; /* Frozen on CRC error */
                printf("[spi_fpga_sim] CRC-32 MISMATCH on seq=%u -> HOLD (0 mV)\n",
                       (unsigned)req.seq_id);
                fflush(stdout);
            } else if (!omega_tof_causal_ok(req.uwb_tof_ns, req.flags)) {
                next_rep.verdict          = OMEGA_CVERD_HOLD;
                next_rep.stop_stage       = 1u;
                next_rep.actuator_mv      = 0u;
                next_rep.flags_out        = OMEGA_OUT_CROWBAR_GND;
                next_rep.reason_code      = OMEGA_CRSN_TOF_CAUSALITY;
                next_rep.witness_chain_wn = g_wn_chain;
            } else {
                g_wn_chain = ((g_wn_chain << 7) | (g_wn_chain >> 57)) ^ (uint64_t)req.seq_id ^ 0xA5A5u;
                next_rep.verdict          = OMEGA_CVERD_OPEN;
                next_rep.stop_stage       = 0u;
                next_rep.admissible_count = 41u;
                next_rep.actuator_mv      = 5000u;
                next_rep.u_safe_out       = req.u_raw;
                next_rep.flags_out        = OMEGA_OUT_RAIL_5V_EN | OMEGA_OUT_FSYNC_READY;
                next_rep.reason_code      = OMEGA_CRSN_OK;
                next_rep.witness_chain_wn = g_wn_chain;
                g_tx_count++;
            }

            g_last_rep = next_rep;
            memset(&msg->o, 0, sizeof(msg->o));
            msg->o.nbytes = sizeof(spi_xchng_t) + 128u;
            return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + sizeof(spi_xchng_t) + 128u);
        }

        default:
            return ENOTTY;
    }
}

int main(int argc, char **argv) {
    const char *dev_path = (argc > 1) ? argv[1] : "/dev/spi_fpga_sim";

    memset(&g_last_rep, 0, sizeof(g_last_rep));
    g_last_rep.verdict     = OMEGA_CVERD_HOLD;
    g_last_rep.stop_stage  = 1u;
    g_last_rep.actuator_mv = 0u;
    g_last_rep.omega_y_mv  = 5000u;

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
    io_funcs.devctl = spi_sim_devctl;
    iofunc_attr_init(&attr, S_IFNAM | 0666, NULL, NULL);

    if (resmgr_attach(dpp, &rattr, dev_path, _FTYPE_ANY, 0,
                      &connect_funcs, &io_funcs, &attr) == -1) {
        perror("resmgr_attach spi_fpga_sim");
        return EXIT_FAILURE;
    }

    printf("[spi_fpga_sim] Active at %s (DCMD_SPI_DATA_XCHNG 128B/64B) | pid=%d\n",
           dev_path, (int)getpid());
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
    printf("[spi_fpga_sim] Host stub (cross-compile with QNX 8.0 qcc).\n");
    return EXIT_SUCCESS;
}

#endif
