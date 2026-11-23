#ifndef OMEGA_QNX_RT_CAGE_H
#define OMEGA_QNX_RT_CAGE_H

/* ============================================================================
 * qnx_rt_cage.h — QNX Neutrino 8.0 Real-Time Determinism & Privilege Sandbox
 *
 * Provides fail-closed helpers for:
 *   1. Fixed-priority resource manager channels (_NTO_CHF_FIXED_PRIORITY |
 *      _NTO_CHF_DISCONNECT, without _NTO_CHF_UNBLOCK) so lower-priority
 *      clients never drag down d0/d1/d2/spi and procnto enforces immediate
 *      TimerTimeout(ETIMEDOUT) even if a downstream server hangs in STATE_REPLY.
 *   2. Timed synchronous devctl wrapper using CLOCK_MONOTONIC TimerTimeout
 *      (_NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY).
 *   3. Memory pinning via mlockall(MCL_CURRENT | MCL_FUTURE).
 *   4. Post-attach capability drop via procmgr_ability() locking out SPAWN,
 *      FORK, PATHSPACE, IO, and MEM_PHYS permanently.
 * ============================================================================ */

#ifdef __QNXNTO__

#include <devctl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/procmgr.h>
#include <sys/siginfo.h>
#include <time.h>

static inline dispatch_t *omega_qnx_create_fixed_dispatch(void) {
    /* Omit _NTO_CHF_UNBLOCK so procnto breaks STATE_REPLY immediately on TimerTimeout */
    int chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY | _NTO_CHF_DISCONNECT);
    if (chid == -1) {
        perror("ChannelCreate(_NTO_CHF_FIXED_PRIORITY)");
        return NULL;
    }
    dispatch_t *dpp = dispatch_create_channel(chid, 0);
    if (!dpp) {
        perror("dispatch_create_channel(fixed)");
        (void)ChannelDestroy(chid);
        return NULL;
    }
    return dpp;
}

static inline dispatch_t *omega_qnx_create_inherited_dispatch(void) {
    /* Omit _NTO_CHF_UNBLOCK so procnto breaks STATE_REPLY immediately on TimerTimeout */
    int chid = ChannelCreate(_NTO_CHF_DISCONNECT);
    if (chid == -1) {
        perror("ChannelCreate(inherited)");
        return NULL;
    }
    dispatch_t *dpp = dispatch_create_channel(chid, 0);
    if (!dpp) {
        perror("dispatch_create_channel(inherited)");
        (void)ChannelDestroy(chid);
        return NULL;
    }
    return dpp;
}

static inline int omega_qnx_devctl_timed(int fd, int dcmd, void *data_ptr,
                                         size_t nbytes, int *dev_info_ptr,
                                         uint64_t timeout_ns) {
    struct sigevent ev;
    SIGEV_UNBLOCK_INIT(&ev);
    if (TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY,
                     &ev, &timeout_ns, NULL) == -1) {
        return (errno != 0) ? errno : EIO;
    }
    return devctl(fd, dcmd, data_ptr, nbytes, dev_info_ptr);
}

/* Queries QNX 8.0 tickless clock resolution (read-only; 0 = one-shot tickless)
 * and locks process timer tolerance to exact 0 ns (zero coalescing). Must be
 * called while process still holds root abilities BEFORE sandbox lock! */
static inline int omega_qnx_lock_hard_clock(uint32_t *old_period_ns_out,
                                            uint64_t *old_tol_ns_out) {
    struct _clockperiod old_cp;
    memset(&old_cp, 0, sizeof(old_cp));

    if (ClockPeriod(CLOCK_REALTIME, NULL, &old_cp, 0) == -1) {
        if (errno != ENOTSUP) {
            return (errno != 0) ? errno : EPERM;
        }
        if (old_period_ns_out != NULL) {
            *old_period_ns_out = 0u; /* 0 = QNX 8.0 tickless one-shot */
        }
    } else if (old_period_ns_out != NULL) {
        *old_period_ns_out = old_cp.nsec;
    }

    _Uint64t zero_tol = 0u;
    _Uint64t old_tol = 0u;
    if (procmgr_timer_tolerance(0, &zero_tol, &old_tol) == -1) {
        return (errno != 0) ? errno : EPERM;
    }
    if (old_tol_ns_out != NULL) {
        *old_tol_ns_out = (uint64_t)old_tol;
    }
    return EOK;
}

static inline int omega_qnx_lock_memory_and_sandbox(void) {
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        perror("mlockall(MCL_CURRENT|MCL_FUTURE)");
        return -1;
    }
    const unsigned deny_lock = PROCMGR_ADN_ROOT | PROCMGR_AOP_DENY | PROCMGR_AOP_LOCK;
    int rc = procmgr_ability(
        0,
        deny_lock | PROCMGR_AID_SPAWN,
        deny_lock | PROCMGR_AID_FORK,
        deny_lock | PROCMGR_AID_PATHSPACE,
        deny_lock | PROCMGR_AID_IO,
        deny_lock | PROCMGR_AID_MEM_PHYS,
        deny_lock | PROCMGR_AID_CLOCKSET,
        deny_lock | PROCMGR_AID_DEFAULT_TIMER_TOLERANCE,
        PROCMGR_AID_EOL
    );
    if (rc != EOK) {
        fprintf(stderr, "procmgr_ability sandbox failed: rc=%d\n", rc);
        return -1;
    }
    return 0;
}

#endif /* __QNXNTO__ */

#endif /* OMEGA_QNX_RT_CAGE_H */
