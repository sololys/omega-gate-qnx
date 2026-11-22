#include "omega_capsule205b.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, name) do { \
    if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
    else      { g_fail++; printf("  [FAIL] %s (line %d)\n", name, __LINE__); } \
} while (0)

/* IEEE-754 binary32 bit constants (zero float literals!) */
#define F32_POS_ZERO       0x00000000u /* +0.0 */
#define F32_NEG_ZERO       0x80000000u /* -0.0 */
#define F32_POS_SUBNORMAL  0x00000001u /* 1.4e-45 */
#define F32_NEG_SMALL      0xBDCCCCCDu /* -0.1 */
#define F32_QNAN           0x7FC00000u /* quiet NaN */
#define F32_POS_INF        0x7F800000u /* +Inf */
#define F32_THERMO_29_21   0x41E9AE14u /* 29.21 nJ */
#define F32_DRIFT_0_005    0x3BA3D70Au /* 0.005 -> 5000 ppm (exact ceiling 5001 if >0.005) */
#define F32_DRIFT_1E_7     0x33D6BF95u /* 1e-7 -> ceiling to 1 ppm */

static void build_valid_ingress(
    omega_capsule_ingress_t *ing,
    uint64_t seq,
    uint8_t prev_fill,
    uint8_t post_fill
) {
    memset(ing, 0, sizeof(*ing));
    ing->capsule.pre.sequence_id            = seq;
    ing->capsule.pre.timestamp_ns           = 1000000000ULL * seq;
    memset(ing->capsule.pre.candidate_hash,  (int)(0x30u + seq), 32u);
    ing->capsule.pre.kernel_drift_f32_bits  = F32_POS_ZERO;
    ing->capsule.pre.gate_decision          = OMEGA_CAP_DEC_OPEN;
    ing->capsule.pre.reason_code            = OMEGA_CAP_FLAG_MAAT_OK;
    memset(ing->capsule.pre.prev_block_hash, prev_fill, 32u);
    memset(ing->capsule.pre.w_pre_hash,      (int)(0x70u + seq), 32u);

    ing->capsule.post.sequence_id             = seq;
    ing->capsule.post.timestamp_ns            = ing->capsule.pre.timestamp_ns + 14000000ULL;
    memcpy(ing->capsule.post.w_pre_hash, ing->capsule.pre.w_pre_hash, 32u);
    ing->capsule.post.hpis_latch_status       = OMEGA_CAP_HPIS_ENGAGED;
    ing->capsule.post.thermo_exhaust_f32_bits = F32_THERMO_29_21;
    ing->capsule.post.final_status            = OMEGA_CAP_FINAL_REALIZED;
    memset(ing->capsule.post.w_post_hash, post_fill, 32u);

    ing->extra_flags = OMEGA_FLAG_UWB_LINK_ACTIVE | OMEGA_FLAG_MB_CALIBRATED | OMEGA_FLAG_ESCROW_50_50;
    ing->uwb_tof_ns  = 50u;
    ing->target_id   = 1u;
    ing->u_raw       = 1000;
    omega_capsule_ingress_seal(ing);
}

int main(void) {
    omega_capsule_ctx_t ctx;
    omega_capsule_ingress_t ing;
    omega_cascade_req_t req;
    omega_capsule_status_t st;

    printf("=== OMEGA 205B WITNESS CAPSULE <-> 128B CASCADE BRIDGE SUITE ===\n");
    omega_capsule_ctx_init(&ctx);

    /* V1: Valid genesis capsule + domain-separated digest + CRC-32 sealed 128B req */
    build_valid_ingress(&ing, 1ULL, 0xAAu, 0xBBu);
    st = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st == OMEGA_CAP_OK && omega_cascade_verify_req(&req) &&
          req.seq_id == 1u && req.pi_drift_ppm == 0u && req.airlock_elapsed_ms == 14u &&
          (req.flags & OMEGA_FLAG_WARRANT_COMPLETE) != 0u && req.intent_digest != 0ULL,
          "V01_VALID_GENESIS_OPEN_AND_SEALED_128B");
    uint64_t digest_seq1 = req.intent_digest;

    /* V2: Valid chained capsule #2 (prev_block_hash == seq1.w_post_hash = 0xBB) + -0.0 canonicalization */
    build_valid_ingress(&ing, 2ULL, 0xBBu, 0xCCu);
    ing.capsule.pre.kernel_drift_f32_bits = F32_NEG_ZERO;
    omega_capsule_ingress_seal(&ing);
    st = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st == OMEGA_CAP_OK && req.pi_drift_ppm == 0u && req.intent_digest != digest_seq1,
          "V02_CHAINED_CAPSULE_AND_NEG_ZERO_CANONICAL");

    /* V3: 1-bit tamper in post.w_pre_hash -> ERR_HASH_INVOLUTION + fail-closed KILL */
    build_valid_ingress(&ing, 3ULL, 0xCCu, 0xDDu);
    ing.capsule.post.w_pre_hash[0] ^= 0x01u;
    omega_capsule_ingress_seal(&ing);
    st = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st == OMEGA_CAP_ERR_HASH_INVOL && (req.flags & OMEGA_FLAG_NOMOS_VIOLATION) != 0u &&
          req.anomaly_score == 100 && omega_cascade_verify_req(&req),
          "V03_1BIT_W_PRE_HASH_TAMPER_FAIL_CLOSED");

    /* V4: Sequence replay attack (seq == 2 <= last_seq_id) */
    build_valid_ingress(&ing, 2ULL, 0xCCu, 0xDDu);
    st = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st == OMEGA_CAP_ERR_REPLAY && req.anomaly_score == 100,
          "V04_SEQUENCE_REPLAY_REJECTED");

    /* V5: Broken prev_block_hash chain fork (0x99 != 0xCC) */
    build_valid_ingress(&ing, 3ULL, 0x99u, 0xDDu);
    st = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st == OMEGA_CAP_ERR_CHAIN_FORK && req.anomaly_score == 100,
          "V05_CHAIN_FORK_PREV_BLOCK_MISMATCH");

    /* V6: Causal decay timeout (dt_ns > 30.0 s) */
    build_valid_ingress(&ing, 3ULL, 0xCCu, 0xDDu);
    ing.capsule.post.timestamp_ns = ing.capsule.pre.timestamp_ns + 30000000001ULL;
    omega_capsule_ingress_seal(&ing);
    st = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st == OMEGA_CAP_ERR_TIME_BUDGET && req.anomaly_score == 100,
          "V06_TTL_OVER_30S_REJECTED");

    /* V7: Belnap 4-valued paradox Q_LP = Omega(1,1) */
    build_valid_ingress(&ing, 3ULL, 0xCCu, 0xDDu);
    ing.capsule.pre.reason_code = OMEGA_CAP_FLAG_MAAT_OK | OMEGA_CAP_FLAG_BELNAP_OMEGA;
    omega_capsule_ingress_seal(&ing);
    st = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st == OMEGA_CAP_ERR_BELNAP_OMEGA && req.anomaly_score == 100,
          "V07_BELNAP_OMEGA_PARADOX_KILL");

    /* V8: HPIS interlock mismatch (OPEN with hpis_latch == 0) */
    build_valid_ingress(&ing, 3ULL, 0xCCu, 0xDDu);
    ing.capsule.post.hpis_latch_status = OMEGA_CAP_HPIS_ISOLATED;
    omega_capsule_ingress_seal(&ing);
    st = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st == OMEGA_CAP_ERR_HPIS_MISMATCH && req.anomaly_score == 100,
          "V08_HPIS_INTERLOCK_MISMATCH_KILL");

    /* V9: Landauer zero / subnormal / NaN exhaust on byte 168..171 */
    build_valid_ingress(&ing, 3ULL, 0xCCu, 0xDDu);
    ing.capsule.post.thermo_exhaust_f32_bits = F32_POS_ZERO;
    omega_capsule_ingress_seal(&ing);
    omega_capsule_status_t st_zero = omega_capsule205b_ingest(&ctx, &ing, &req);
    ing.capsule.post.thermo_exhaust_f32_bits = F32_POS_SUBNORMAL;
    omega_capsule_ingress_seal(&ing);
    omega_capsule_status_t st_sub = omega_capsule205b_ingest(&ctx, &ing, &req);
    ing.capsule.post.thermo_exhaust_f32_bits = F32_QNAN;
    omega_capsule_ingress_seal(&ing);
    omega_capsule_status_t st_nan = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st_zero == OMEGA_CAP_ERR_THERMO_LANDAUER &&
          st_sub  == OMEGA_CAP_ERR_THERMO_LANDAUER &&
          st_nan  == OMEGA_CAP_ERR_THERMO_LANDAUER,
          "V09_LANDAUER_ZERO_SUBNORMAL_NAN_REJECTED");

    /* V10: IEEE-754 NaN / +Inf / negative drift on byte 48..51 */
    build_valid_ingress(&ing, 3ULL, 0xCCu, 0xDDu);
    ing.capsule.pre.kernel_drift_f32_bits = F32_QNAN;
    omega_capsule_ingress_seal(&ing);
    omega_capsule_status_t st_dnan = omega_capsule205b_ingest(&ctx, &ing, &req);
    ing.capsule.pre.kernel_drift_f32_bits = F32_POS_INF;
    omega_capsule_ingress_seal(&ing);
    omega_capsule_status_t st_dinf = omega_capsule205b_ingest(&ctx, &ing, &req);
    ing.capsule.pre.kernel_drift_f32_bits = F32_NEG_SMALL;
    omega_capsule_ingress_seal(&ing);
    omega_capsule_status_t st_dneg = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st_dnan == OMEGA_CAP_ERR_DRIFT_IEEE754 &&
          st_dinf == OMEGA_CAP_ERR_DRIFT_IEEE754 &&
          st_dneg == OMEGA_CAP_ERR_DRIFT_IEEE754,
          "V10_DRIFT_NAN_INF_NEGATIVE_REJECTED");

    /* V11: Conservative ceiling 0-float conversion (1e-7 -> 1 ppm, 0.005 -> >=5000 ppm) */
    uint32_t ppm_tiny = 0u, ppm_halfpct = 0u;
    bool ok1 = omega_ieee754_f32_to_ppm_ceil(F32_DRIFT_1E_7, &ppm_tiny);
    bool ok2 = omega_ieee754_f32_to_ppm_ceil(F32_DRIFT_0_005, &ppm_halfpct);
    build_valid_ingress(&ing, 3ULL, 0xCCu, 0xDDu);
    ing.capsule.pre.kernel_drift_f32_bits = F32_DRIFT_0_005;
    omega_capsule_ingress_seal(&ing);
    st = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(ok1 && ppm_tiny == 1u && ok2 && (ppm_halfpct == 5000u || ppm_halfpct == 5001u) &&
          st == OMEGA_CAP_OK && req.pi_drift_ppm == ppm_halfpct,
          "V11_CEILING_INTEGER_IEEE754_TO_PPM");

    /* V12: Corrupted ingress CRC-32 rejected without advancing chain ctx */
    build_valid_ingress(&ing, 4ULL, 0xDDu, 0xEEu);
    ing.crc32 ^= 0x00000001u;
    st = omega_capsule205b_ingest(&ctx, &ing, &req);
    CHECK(st == OMEGA_CAP_ERR_INGRESS_CRC && ctx.last_seq_id == 3ULL,
          "V12_INGRESS_CRC_CORRUPTION_FAIL_CLOSED");

    printf("=== CAPSULE205B BRIDGE SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
