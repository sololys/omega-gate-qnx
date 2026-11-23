#ifndef OMEGA_QNX_RT_CAGE_H
#define OMEGA_QNX_RT_CAGE_H

/* ============================================================================
 * qnx_rt_cage.h — QNX Neutrino 8.0 Real-Time Determinism & Privilege Sandbox
 *
 * Provides fail-closed helpers for:
 *   1. Fixed-priority resource manager channels (_NTO_CHF_FIXED_PRIORITY) so
 *      lower-priority clients never drag down d0 (20) / d1 (25) / d2 (30).
 *   2. Priority-inheriting channels (without _NTO_CHF_FIXED_PRIORITY) for
 *      downstream SPI devices so >= prio 30 callers never suffer inversion.
 *   3. Memory pinning via mlockall(MCL_CURRENT | MCL_FUTURE).
 *   4. Post-attach capability drop via procmgr_ability() locking out SPAWN,
 *      FORK, and PATHSPACE while keeping IPC, timers, and clocks active.
 * ============================================================================ */

#ifdef __QNXNTO__

#include <errno.h>
#include <stdio.h>
#include <sys/dispatch.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/procmgr.h>

static inline dispatch_t *omega_qnx_create_fixed_dispatch(void) {
    int chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY | _NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);
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
    int chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);
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
