/*
 * test_d2_hardening.c — Zero-Float C11 Verification of Causal ToF Gate & Two-Phase L01 Reset
 */

#include "omega_cascade.h"

#include <stdio.h>
#include <stdlib.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, name) do { \
    if (cond) { \
        printf("  [PASS] %s\n", name); \
        g_pass++; \
    } else { \
        printf("  [FAIL] %s (line %d)\n", name, __LINE__); \
        g_fail++; \
    } \
} while (0)

int main(void) {
    printf("=== OmegaGate-QNX D2 Hardening Tests (Causal ToF + Two-Phase L01) ===\n");

    /* 1. Causal ToF lower/upper bounds */
    CHECK(!omega_tof_causal_ok(0u, OMEGA_FLAG_UWB_LINK_ACTIVE),
          "TOF_0NS_NONCAUSAL_REJECTED");
    CHECK(!omega_tof_causal_ok(0u, OMEGA_FLAG_UWB_LINK_ACTIVE | OMEGA_FLAG_KPOD_SEALED),
          "TOF_0NS_ACTIVE_UWB_NOT_MASKED_BY_COURIER");
    CHECK(!omega_tof_causal_ok(134u, OMEGA_FLAG_UWB_LINK_ACTIVE),
          "TOF_134NS_BEYOND_20M_REJECTED");
    CHECK(omega_tof_causal_ok(1u, OMEGA_FLAG_UWB_LINK_ACTIVE),
          "TOF_1NS_LOWER_EDGE_ACCEPTED");
    CHECK(omega_tof_causal_ok(42u, OMEGA_FLAG_UWB_LINK_ACTIVE),
          "TOF_42NS_NOMINAL_ACCEPTED");
    CHECK(omega_tof_causal_ok(133u, OMEGA_FLAG_UWB_LINK_ACTIVE),
          "TOF_133NS_UPPER_EDGE_ACCEPTED");
    CHECK(omega_tof_causal_ok(0u, OMEGA_FLAG_KPOD_SEALED),
          "TOF_COURIER_BYPASS_WHEN_UWB_INACTIVE_ACCEPTED");
    CHECK(!omega_tof_causal_ok(0u, 0u),
          "TOF_0NS_NO_FLAGS_REJECTED");

    /* 2. Two-phase L01 reset governor with monotonic cooldown & impatient restart */
    omega_l01_reset_gov_t gov;
    omega_l01_gov_init(&gov, 30000u, 60000u); /* 30 s cooldown, 60 s confirmation window */

    const uint64_t MS = 1000000ULL;
    uint64_t t0 = 10000ULL * MS;

    CHECK(omega_l01_gov_step(&gov, 10u, false, t0) == OMEGA_CRSN_L01_RESET_INVALID,
          "L01_INVALID_KEY_REJECTED");
    CHECK(!gov.armed, "L01_NOT_ARMED_ON_INVALID_KEY");

    /* Phase 1: Arm */
    CHECK(omega_l01_gov_step(&gov, 11u, true, t0) == OMEGA_CRSN_L01_RESET_ARMED,
          "L01_PHASE1_ARMED_AT_0MV");
    CHECK(gov.armed, "L01_STATE_IS_ARMED");

    /* Impatient attempt at t0 + 10 s (< 30 s) -> rejected AND restarts timer to t0 + 10 s! */
    CHECK(omega_l01_gov_step(&gov, 12u, true, t0 + 10000ULL * MS) == OMEGA_CRSN_L01_RESET_COOLDOWN,
          "L01_IMPATIENT_ATTEMPT_10S_REJECTED_AND_RESTARTS_TIMER");

    /* Attempt at t0 + 35 s is only 25 s after restart -> MUST still be rejected! */
    CHECK(omega_l01_gov_step(&gov, 13u, true, t0 + 35000ULL * MS) == OMEGA_CRSN_L01_RESET_COOLDOWN,
          "L01_25S_AFTER_RESTART_STILL_IN_COOLDOWN");

    /* Attempt at t0 + 35 s + 30 s (65 s) with same seq_id=13 -> rejected (non-monotonic seq) */
    CHECK(omega_l01_gov_step(&gov, 13u, true, t0 + 65000ULL * MS) == OMEGA_CRSN_L01_RESET_COOLDOWN,
          "L01_NON_MONOTONIC_SEQ_REJECTED");

    /* Attempt at t0 + 65 s + 31 s (96 s, >= 30 s after last restart) with seq_id=14 -> OK! */
    CHECK(omega_l01_gov_step(&gov, 14u, true, t0 + 96000ULL * MS) == OMEGA_CRSN_L01_RESET_OK,
          "L01_PHASE2_CONFIRMED_AFTER_COOLDOWN");
    CHECK(!gov.armed, "L01_DISARMED_AFTER_OK");

    /* Expiry window check: arm at t1, try at t1 + 95 s (> 30 s + 60 s) -> re-arms to Phase 1 */
    uint64_t t1 = 500000ULL * MS;
    CHECK(omega_l01_gov_step(&gov, 20u, true, t1) == OMEGA_CRSN_L01_RESET_ARMED,
          "L01_REARM_FOR_EXPIRY_TEST");
    CHECK(omega_l01_gov_step(&gov, 21u, true, t1 + 95000ULL * MS) == OMEGA_CRSN_L01_RESET_ARMED,
          "L01_EXPIRED_CONFIRMATION_WINDOW_REARMS");

    printf("=== D2 HARDENING SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
