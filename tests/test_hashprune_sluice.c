/*
 * test_hashprune_sluice.c — Exact 8/8 Parity Verification against
 * the Dual-Rate HashPrune Sluice reference vectors (TestDualRateHashPruneSluice)
 */

#include "omega_cascade.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "  [FAIL] %s (line %d)\n", (msg), __LINE__); \
        g_fail++; \
        return; \
    } \
} while (0)

static const int32_t ORIGIN_2D[HP_MAX_DIM] = {0, 0, 0};
static const int32_t PLANES_2D[2][HP_MAX_DIM] = {
    { HP_Q16_ONE, 0, 0 },
    { 0, HP_Q16_ONE, 0 }
};

static int32_t q16(int v) { return (int32_t)v * HP_Q16_ONE; }

typedef struct {
    uint32_t id;
    int32_t  pos[HP_MAX_DIM];
} cand_t;

/* 1. test_hashprune_order_independence_theorem_3_1 */
static void test_1_order_independence(void) {
    const cand_t cands[4] = {
        { 101, { q16(5),  q16(5),  0 } },
        { 102, { q16(2),  q16(2),  0 } },
        { 103, { q16(-3), q16(4),  0 } },
        { 104, { q16(-1), q16(-1), 0 } }
    };
    hp_reservoir_t a, b;
    hp_reservoir_init(&a, 1, 2, ORIGIN_2D, 2, PLANES_2D, 4);
    hp_reservoir_init(&b, 1, 2, ORIGIN_2D, 2, PLANES_2D, 4);

    for (int i = 0; i < 4; ++i) hp_reservoir_admit(&a, cands[i].id, cands[i].pos, NULL, NULL);
    for (int i = 3; i >= 0; --i) hp_reservoir_admit(&b, cands[i].id, cands[i].pos, NULL, NULL);

    ASSERT_TRUE(hp_reservoir_equal(&a, &b), "forward vs reverse reservoir mismatch");
    uint32_t tid = 0;
    ASSERT_TRUE(hp_reservoir_get_bucket(&a, 3, &tid, NULL) && tid == 102, "bucket 3 winner must be 102");
    printf("  [PASS] T1_hashprune_order_independence_theorem_3_1\n");
    g_pass++;
}

/* 2. test_hashprune_eviction_tiebreak_all_permutations (all 5! = 120 permutations) */
static void permute_and_check(int idx, int perm[5], const cand_t cands[5],
                              bool *has_ref, hp_reservoir_t *ref, bool *ok) {
    if (idx == 5) {
        hp_reservoir_t r;
        hp_reservoir_init(&r, 1, 2, ORIGIN_2D, 2, PLANES_2D, 2);
        for (int i = 0; i < 5; ++i) {
            hp_reservoir_admit(&r, cands[perm[i]].id, cands[perm[i]].pos, NULL, NULL);
        }
        if (!*has_ref) {
            *ref = r;
            *has_ref = true;
        } else if (!hp_reservoir_equal(&r, ref)) {
            *ok = false;
        }
        return;
    }
    for (int i = idx; i < 5; ++i) {
        int tmp = perm[idx]; perm[idx] = perm[i]; perm[i] = tmp;
        permute_and_check(idx + 1, perm, cands, has_ref, ref, ok);
        tmp = perm[idx]; perm[idx] = perm[i]; perm[i] = tmp;
    }
}

static void test_2_eviction_all_120_permutations(void) {
    const cand_t cands[5] = {
        { 10, { q16(3),  q16(4),  0 } },
        { 20, { q16(-3), q16(4),  0 } },
        { 30, { q16(-3), q16(-4), 0 } },
        { 40, { q16(1),  q16(-1), 0 } },
        { 5,  { q16(3),  q16(4),  0 } }
    };
    int perm[5] = {0, 1, 2, 3, 4};
    bool has_ref = false, ok = true;
    hp_reservoir_t ref;
    permute_and_check(0, perm, cands, &has_ref, &ref, &ok);
    ASSERT_TRUE(ok && has_ref && ref.count == 2, "120-permutation invariance failed");
    uint32_t t1 = 0, t3 = 0;
    ASSERT_TRUE(hp_reservoir_get_bucket(&ref, 1, &t1, NULL) && t1 == 40, "expected winner 40 in bucket 1");
    ASSERT_TRUE(hp_reservoir_get_bucket(&ref, 3, &t3, NULL) && t3 == 5, "expected winner 5 in bucket 3");
    printf("  [PASS] T2_hashprune_eviction_tiebreak_all_120_permutations\n");
    g_pass++;
}

/* 3. test_dual_rate_avoids_ledger_spam_on_continuous_steps */
static void test_3_dual_rate_no_ledger_spam(void) {
    hp_reservoir_t r;
    hp_reservoir_init(&r, 1, 2, ORIGIN_2D, 2, PLANES_2D, 4);
    hp_sluice_t s;
    hp_sluice_init(&s, &r, 4LL * HP_Q32_ONE, 10000u, 10LL * HP_Q16_ONE,
                   HP_Q16_ONE, HP_Q16_ONE / 16, 0u);

    const int32_t p[HP_MAX_DIM] = { q16(3), q16(4), 0 };
    ASSERT_TRUE(hp_sluice_step(&s, 10, p, 0u, true, true) == HP_RES_OPEN, "step 1 must OPEN");
    ASSERT_TRUE(s.voltage_mv == 5000u && s.ledger_len == 1u, "5000 mV and 1 ledger entry");
    ASSERT_TRUE(hp_sluice_step(&s, 10, p, 0u, true, true) == HP_RES_CONTINUOUS_PASS, "step 2 CONTINUOUS_PASS");
    ASSERT_TRUE(hp_sluice_step(&s, 10, p, 0u, true, true) == HP_RES_CONTINUOUS_PASS, "step 3 CONTINUOUS_PASS");
    ASSERT_TRUE(s.high_rate_passes == 2u && s.ledger_len == 1u, "0 new hashes on continuous pass");
    printf("  [PASS] T3_dual_rate_avoids_ledger_spam_on_continuous_steps\n");
    g_pass++;
}

/* 4. test_drift_triggers_hold_and_halves_dtau_readmission */
static void test_4_drift_halves_dtau(void) {
    hp_reservoir_t r;
    hp_reservoir_init(&r, 1, 2, ORIGIN_2D, 2, PLANES_2D, 4);
    hp_sluice_t s;
    hp_sluice_init(&s, &r, 4LL * HP_Q32_ONE, 10000u, 10LL * HP_Q16_ONE,
                   HP_Q16_ONE, HP_Q16_ONE / 16, 400u);

    const int32_t p[HP_MAX_DIM] = { q16(5), q16(5), 0 };
    /* pi_drift = 2/100 == 20000 ppm >= 10000 ppm */
    ASSERT_TRUE(hp_sluice_step(&s, 10, p, 20000u, true, true) == HP_RES_HOLD, "drift must HOLD");
    ASSERT_TRUE(s.voltage_mv == 0u && s.dtau_q16 == (HP_Q16_ONE / 2), "0 mV and dtau == 1/2");
    printf("  [PASS] T4_drift_triggers_hold_and_halves_dtau_readmission\n");
    g_pass++;
}

/* 5. test_double_clock_escalates_stalled_hold_without_opening */
static void test_5_double_clock_escalation(void) {
    hp_reservoir_t r;
    hp_reservoir_init(&r, 1, 2, ORIGIN_2D, 2, PLANES_2D, 4);
    hp_sluice_t s;
    hp_sluice_init(&s, &r, 10LL * HP_Q32_ONE, 10000u, 2LL * HP_Q16_ONE,
                   HP_Q16_ONE, HP_Q16_ONE / 16, 400u);

    const int32_t p[HP_MAX_DIM] = { q16(1), q16(1), 0 };
    ASSERT_TRUE(hp_sluice_step(&s, 20, p, 0u, true, false) == HP_RES_HOLD, "tau=1 HOLD");
    ASSERT_TRUE(hp_sluice_step(&s, 20, p, 0u, true, false) == HP_RES_HOLD_ACTIVE, "tau=2 HOLD_ACTIVE");
    ASSERT_TRUE(hp_sluice_step(&s, 20, p, 0u, true, false) == HP_RES_HOLD_ACTIVE, "tau=3 HOLD_ACTIVE");
    ASSERT_TRUE(hp_sluice_step(&s, 20, p, 0u, true, false) == HP_RES_ESCALATED_EXT, "tau=4 ESCALATED_EXT");
    ASSERT_TRUE(s.owner_port == HP_OWNER_P_EXT && s.voltage_mv == 0u && s.ledger_len == 2u, "P_ext, 0 mV, 2 ledger entries");
    printf("  [PASS] T5_double_clock_escalates_stalled_hold_without_opening\n");
    g_pass++;
}

/* 6. test_involution_breach_trips_irreversible_kill_latch */
static void test_6_involution_kill_latch(void) {
    hp_reservoir_t r;
    hp_reservoir_init(&r, 1, 2, ORIGIN_2D, 2, PLANES_2D, 4);
    hp_sluice_t s;
    hp_sluice_init(&s, &r, 4LL * HP_Q32_ONE, 10000u, 10LL * HP_Q16_ONE,
                   HP_Q16_ONE, HP_Q16_ONE / 16, 400u);

    const int32_t p[HP_MAX_DIM] = { q16(5), q16(5), 0 };
    ASSERT_TRUE(hp_sluice_step(&s, 10, p, 0u, false, true) == HP_RES_KILL, "involution breach -> KILL");
    ASSERT_TRUE(s.voltage_mv == 0u, "0 mV on KILL");
    ASSERT_TRUE(hp_sluice_step(&s, 10, p, 0u, true, true) == HP_RES_KILL_LATCHED, "KILL remains latched");
    ASSERT_TRUE(s.voltage_mv == 0u && hp_sluice_verify_ledger(&s), "ledger intact");
    printf("  [PASS] T6_involution_breach_trips_irreversible_kill_latch\n");
    g_pass++;
}

/* 7. test_d1_zeno_underflow_guard_trips_kill */
static void test_7_zeno_underflow_kill(void) {
    hp_reservoir_t r;
    hp_reservoir_init(&r, 1, 2, ORIGIN_2D, 2, PLANES_2D, 4);
    hp_sluice_t s;
    hp_sluice_init(&s, &r, 4LL * HP_Q32_ONE, 10000u, 10LL * HP_Q16_ONE,
                   HP_Q16_ONE, HP_Q16_ONE / 4, 0u);

    const int32_t p[HP_MAX_DIM] = { q16(5), q16(5), 0 };
    ASSERT_TRUE(hp_sluice_step(&s, 10, p, 50000u, true, true) == HP_RES_HOLD, "1 -> 1/2 HOLD");
    ASSERT_TRUE(hp_sluice_step(&s, 10, p, 50000u, true, true) == HP_RES_HOLD, "1/2 -> 1/4 HOLD");
    ASSERT_TRUE(hp_sluice_step(&s, 10, p, 50000u, true, true) == HP_RES_KILL, "1/4 -> 1/8 < 1/4 KILL");
    ASSERT_TRUE(s.latched_kill && hp_sluice_verify_ledger(&s), "Zeno kill latched + ledger OK");
    printf("  [PASS] T7_d1_zeno_underflow_guard_trips_kill\n");
    g_pass++;
}

/* 8. test_d2_patient_fsync_400_cycles_and_d3_tamper_detection */
static void test_8_patient_fsync_400_and_tamper(void) {
    hp_reservoir_t r;
    hp_reservoir_init(&r, 1, 2, ORIGIN_2D, 2, PLANES_2D, 4);
    hp_sluice_t s;
    hp_sluice_init(&s, &r, 4LL * HP_Q32_ONE, 10000u, 1000LL * HP_Q16_ONE,
                   HP_Q16_ONE, HP_Q16_ONE / 16, 400u);

    const int32_t p[HP_MAX_DIM] = { q16(5), q16(5), 0 };
    for (int i = 0; i < 400; ++i) {
        ASSERT_TRUE(hp_sluice_step(&s, 10, p, 0u, true, true) == HP_RES_FSYNC_WAIT, "must FSYNC_WAIT");
        ASSERT_TRUE(s.voltage_mv == 0u, "must remain 0 mV during FSYNC_WAIT");
    }
    ASSERT_TRUE(hp_sluice_step(&s, 10, p, 0u, true, true) == HP_RES_OPEN, "cycle 401 must OPEN");
    ASSERT_TRUE(s.voltage_mv == 5000u && s.ledger_len == 2u && hp_sluice_verify_ledger(&s),
                "5000 mV, 2 ledger entries, verified");

    /* Tamper check */
    s.ledger[0].verdict = (uint8_t)HP_RES_OPEN;
    ASSERT_TRUE(!hp_sluice_verify_ledger(&s), "tampered ledger must fail verification");
    printf("  [PASS] T8_d2_patient_fsync_400_cycles_and_d3_tamper_detection\n");
    g_pass++;
}

/* 9. IEEE 802.3 CRC-32 golden vector ("123456789" -> 0xCBF43926, LE: 26 39 F4 CB) */
static void test_9_crc32_ieee_golden_and_frame_seal(void) {
    uint32_t c = omega_crc32_ieee("123456789", 9);
    ASSERT_TRUE(c == 0xCBF43926u, "CRC-32 golden vector mismatch");
    uint8_t le[4];
    memcpy(le, &c, 4);
    ASSERT_TRUE(le[0] == 0x26u && le[1] == 0x39u && le[2] == 0xF4u && le[3] == 0xCBu,
                "CRC-32 little-endian wire bytes must be 26 39 F4 CB");

    omega_cascade_req_t req;
    memset(&req, 0, sizeof(req));
    req.seq_id = 0x12345678u;
    req.u_raw = 1000;
    omega_cascade_seal_req(&req);
    ASSERT_TRUE(omega_cascade_verify_req(&req), "sealed 128B request must verify");
    req.u_raw ^= 1;
    ASSERT_TRUE(!omega_cascade_verify_req(&req), "1-bit flip must fail CRC-32 verification");
    printf("  [PASS] T9_crc32_ieee_golden_0xCBF43926_and_128B_seal\n");
    g_pass++;
}

int main(void) {
    printf("=== C11 DUAL-RATE HASHPRUNE SLUICE PARITY SUITE (9/9 Vectors) ===\n");
    printf("sizeof(omega_cascade_req_t) = %zu B | sizeof(omega_cascade_rep_t) = %zu B\n",
           sizeof(omega_cascade_req_t), sizeof(omega_cascade_rep_t));
    test_1_order_independence();
    test_2_eviction_all_120_permutations();
    test_3_dual_rate_no_ledger_spam();
    test_4_drift_halves_dtau();
    test_5_double_clock_escalation();
    test_6_involution_kill_latch();
    test_7_zeno_underflow_kill();
    test_8_patient_fsync_400_and_tamper();
    test_9_crc32_ieee_golden_and_frame_seal();
    printf("=== SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
