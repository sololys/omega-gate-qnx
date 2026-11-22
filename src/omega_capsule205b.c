#include "omega_capsule205b.h"
#include "sha256_zero_dep.h"

#include <string.h>

static bool ct_eq_32(const uint8_t a[32], const uint8_t b[32]) {
    uint8_t diff = 0u;
    for (size_t i = 0; i < 32u; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0u;
}

static bool ct_nonzero_32(const uint8_t a[32]) {
    uint8_t acc = 0u;
    for (size_t i = 0; i < 32u; ++i) {
        acc |= a[i];
    }
    return acc != 0u;
}

static uint64_t read_le64(const uint8_t p[8]) {
    return ((uint64_t)p[0])       |
           ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

void omega_capsule_ctx_init(omega_capsule_ctx_t *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
}

void omega_capsule_ingress_seal(omega_capsule_ingress_t *ing) {
    if (!ing) return;
    ing->crc32 = omega_crc32_ieee(ing, offsetof(omega_capsule_ingress_t, crc32));
}

bool omega_capsule_ingress_verify_crc(const omega_capsule_ingress_t *ing) {
    if (!ing) return false;
    uint32_t expected = omega_crc32_ieee(ing, offsetof(omega_capsule_ingress_t, crc32));
    return expected == ing->crc32;
}

bool omega_ieee754_f32_landauer_positive(uint32_t raw_bits) {
    uint32_t sign = (raw_bits >> 31) & 1u;
    uint32_t exp  = (raw_bits >> 23) & 0xFFu;
    /* Strictly positive normalized finite float32: rejects +-0.0, subnormals, neg, Inf, NaN */
    return (sign == 0u) && (exp != 0x00u) && (exp != 0xFFu);
}

bool omega_ieee754_f32_to_ppm_ceil(uint32_t raw_bits, uint32_t *out_ppm) {
    if (!out_ppm) return false;
    uint32_t sign = (raw_bits >> 31) & 1u;
    uint32_t exp  = (raw_bits >> 23) & 0xFFu;
    uint32_t mant = raw_bits & 0x7FFFFFu;

    /* Reject NaN and +/-Inf */
    if (exp == 0xFFu) {
        *out_ppm = UINT32_MAX;
        return false;
    }
    /* Canonicalize both +0.0 and -0.0 to 0 ppm */
    if (exp == 0x00u && mant == 0u) {
        *out_ppm = 0u;
        return true;
    }
    /* Reject strictly negative drift */
    if (sign != 0u) {
        *out_ppm = UINT32_MAX;
        return false;
    }
    /* Positive subnormal (< 1.18e-38): conservative ceiling -> 1 ppm */
    if (exp == 0x00u) {
        *out_ppm = 1u;
        return true;
    }

    /* Normal positive binary32: val = (2^23 + mant) * 2^(exp - 150)
     * ppm = ceil(val * 1_000_000) in pure uint64_t integer arithmetic. */
    uint64_t sig = ((uint64_t)1u << 23) | (uint64_t)mant; /* < 2^24 */
    uint64_t num = sig * 1000000ULL;                      /* < 2^44 */
    int shift = (int)exp - 150;

    if (shift >= 0) {
        if (shift >= 20) {
            *out_ppm = UINT32_MAX;
            return true;
        }
        uint64_t scaled = num << (unsigned)shift;
        *out_ppm = (scaled > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)scaled;
        return true;
    }

    unsigned rshift = (unsigned)(-shift);
    if (rshift >= 64u) {
        *out_ppm = 1u; /* strictly positive -> ceiling to 1 ppm */
        return true;
    }
    uint64_t q   = num >> rshift;
    uint64_t rem = num & (((uint64_t)1u << rshift) - 1ULL);
    uint64_t res = q + (rem ? 1ULL : 0ULL);
    *out_ppm = (res > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)res;
    return true;
}

static uint64_t domain_separated_intent_digest(const omega_capsule205b_t *cap) {
    static const uint8_t DOMAIN_TAG[15] = "OMEGA_CAP205_V1";
    sha256_ctx_t sctx;
    uint8_t digest[32];
    sha256_init(&sctx);
    sha256_update(&sctx, DOMAIN_TAG, sizeof(DOMAIN_TAG));
    sha256_update(&sctx, cap->pre.candidate_hash, 32u);
    sha256_update(&sctx, cap->pre.prev_block_hash, 32u);
    sha256_update(&sctx, cap->pre.w_pre_hash, 32u);
    sha256_update(&sctx, cap->post.w_post_hash, 32u);
    sha256_final(&sctx, digest);
    return read_le64(digest);
}

static void populate_base_req(const omega_capsule_ingress_t *ing, omega_cascade_req_t *req) {
    memset(req, 0, sizeof(*req));
    req->seq_id              = (uint32_t)(ing->capsule.pre.sequence_id & 0xFFFFFFFFULL);
    req->timestamp_ns        = ing->capsule.pre.timestamp_ns;
    req->stage               = 1u;
    req->prev_stage          = 0u;
    req->pos_x_q16           = ing->pos_x_q16;
    req->pos_y_q16           = ing->pos_y_q16;
    req->pos_z_q16           = ing->pos_z_q16;
    req->target_id           = ing->target_id;
    req->somatic_weight_q016 = ing->somatic_weight_q016;
    req->q_nm                = ing->q_nm;
    req->v_mm_s              = ing->v_mm_s;
    req->u_raw               = ing->u_raw;
    req->state_s             = ing->state_s;
    req->f_f_state_s         = ing->f_f_state_s;
    req->info_loss_delta     = ing->info_loss_delta;
    req->uwb_tof_ns          = ing->uwb_tof_ns;
    req->proj_state_s        = ing->proj_state_s;
    req->proj_citizen_c      = ing->proj_citizen_c;
    req->earned_merit_delta  = ing->earned_merit_delta;
    req->obstacle_dist_q16   = ((uint32_t)ing->obstacle_dist_q8) << 8;
    req->intent_digest       = domain_separated_intent_digest(&ing->capsule);
    req->is_l01_reset        = ing->is_l01_reset;
    memcpy(req->l01_key_hash16, ing->l01_key_hash16, 16u);
    req->anomaly_score       = ing->anomaly_score;
}

static omega_capsule_status_t fail_closed_req(
    omega_cascade_req_t   *req,
    omega_capsule_status_t err
) {
    req->flags         = OMEGA_FLAG_NOMOS_VIOLATION;
    req->anomaly_score = 100; /* Forces immediate KILL (0 mV) in /dev/d0_trap */
    req->is_l01_reset  = 0u;
    omega_cascade_seal_req(req);
    return err;
}

omega_capsule_status_t omega_capsule205b_ingest(
    omega_capsule_ctx_t           *ctx,
    const omega_capsule_ingress_t *ing,
    omega_cascade_req_t           *out_req
) {
    if (!ctx || !ing || !out_req) {
        return OMEGA_CAP_ERR_NULL;
    }

    populate_base_req(ing, out_req);

    /* 1. Ingress transport CRC-32 check */
    if (!omega_capsule_ingress_verify_crc(ing)) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_INGRESS_CRC);
    }

    const omega_witness_pre_t  *pre  = &ing->capsule.pre;
    const omega_witness_post_t *post = &ing->capsule.post;

    /* 2. Sequence linkage & strict monotonic anti-replay */
    if (pre->sequence_id != post->sequence_id) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_SEQ_MISMATCH);
    }
    if (pre->sequence_id == 0ULL || (ctx->has_committed && pre->sequence_id <= ctx->last_seq_id)) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_REPLAY);
    }

    /* 3. Non-zero cryptographic anchors & constant-time 256-bit involution */
    if (!ct_nonzero_32(pre->w_pre_hash) || !ct_nonzero_32(pre->candidate_hash)) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_ZERO_ANCHOR);
    }
    if (!ct_eq_32(pre->w_pre_hash, post->w_pre_hash)) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_HASH_INVOL);
    }

    /* 4. Cryptographic block-chain continuity after genesis capsule */
    if (ctx->has_committed && !ct_eq_32(pre->prev_block_hash, ctx->last_w_post_hash)) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_CHAIN_FORK);
    }

    /* 5. Causal time budget (0 <= dt_ns <= 30.0 s) */
    if (post->timestamp_ns < pre->timestamp_ns) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_TIME_BUDGET);
    }
    uint64_t dt_ns = post->timestamp_ns - pre->timestamp_ns;
    if (dt_ns > OMEGA_CAP_MAX_DECAY_NS) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_TIME_BUDGET);
    }

    /* 6. Belnap paradox & cobordism / Ma'at structural flags */
    if ((pre->reason_code & OMEGA_CAP_FLAG_BELNAP_OMEGA) != 0u) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_BELNAP_OMEGA);
    }
    if (((pre->reason_code & OMEGA_CAP_FLAG_D1D2_NONZERO) != 0u) ||
        ((pre->reason_code & OMEGA_CAP_FLAG_MAAT_OK) == 0u)) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_COBORDISM_MAAT);
    }

    /* 7. HPIS interlock consistency */
    if (pre->gate_decision == OMEGA_CAP_DEC_OPEN &&
        (post->hpis_latch_status != OMEGA_CAP_HPIS_ENGAGED ||
         post->final_status != OMEGA_CAP_FINAL_REALIZED)) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_HPIS_MISMATCH);
    }

    /* 8. Landauer strictly positive normalized finite thermo_exhaust_nJ (byte 168..171) */
    if (!omega_ieee754_f32_landauer_positive(post->thermo_exhaust_f32_bits)) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_THERMO_LANDAUER);
    }

    /* 9. Conservative ceiling 0-float IEEE-754 drift -> pi_drift_ppm (byte 48..51) */
    uint32_t drift_ppm = 0u;
    if (!omega_ieee754_f32_to_ppm_ceil(pre->kernel_drift_f32_bits, &drift_ppm)) {
        return fail_closed_req(out_req, OMEGA_CAP_ERR_DRIFT_IEEE754);
    }

    /* Validated capsule: map cleanly to 128B omega_cascade_req_t */
    out_req->pi_drift_ppm = drift_ppm;
    uint64_t dt_ms = dt_ns / 1000000ULL;
    out_req->airlock_elapsed_ms = (dt_ms > 65535ULL) ? 65535u : (uint16_t)dt_ms;
    /* Keep Door14 guestroom horizon counter bounded (actual airlock ms is in airlock_elapsed_ms) */
    out_req->elapsed_cycles     = 10u;

    uint16_t flags = (uint16_t)(ing->extra_flags & (
        OMEGA_FLAG_UWB_LINK_ACTIVE |
        OMEGA_FLAG_KPOD_SEALED     |
        OMEGA_FLAG_MB_CALIBRATED   |
        OMEGA_FLAG_ESCROW_50_50    |
        OMEGA_FLAG_CRISIS_A5_ACTIVE|
        OMEGA_FLAG_EXT_DEADLINE    |
        OMEGA_FLAG_L01_AVG_INIT
    ));
    /* Note: bit 15 is zero_friction_back on RTL; involution is carried by bit 4+5 (CPT + REVERSE_CLOSED) */
    flags |= OMEGA_FLAG_INTENT_VALID    |
             OMEGA_FLAG_WITNESS_OK      |
             OMEGA_FLAG_CPT_SYMMETRY_OK |
             OMEGA_FLAG_REVERSE_CLOSED;

    if (pre->gate_decision == OMEGA_CAP_DEC_OPEN) {
        flags |= OMEGA_FLAG_WARRANT_COMPLETE;
    } else if (pre->gate_decision == OMEGA_CAP_DEC_HOLD) {
        flags |= OMEGA_FLAG_CRISIS_A5_ACTIVE;
    } else {
        flags |= OMEGA_FLAG_NOMOS_VIOLATION;
        out_req->anomaly_score = 100;
    }

    out_req->flags = flags;
    omega_cascade_seal_req(out_req);

    /* Advance stateful chain anchor ONLY on valid capsule */
    ctx->last_seq_id   = pre->sequence_id;
    ctx->has_committed = true;
    memcpy(ctx->last_w_post_hash, post->w_post_hash, 32u);
    return OMEGA_CAP_OK;
}

const char *omega_capsule_status_name(omega_capsule_status_t st) {
    switch (st) {
        case OMEGA_CAP_OK:                  return "CAP_OK";
        case OMEGA_CAP_ERR_NULL:            return "ERR_NULL";
        case OMEGA_CAP_ERR_INGRESS_CRC:     return "ERR_INGRESS_CRC";
        case OMEGA_CAP_ERR_SEQ_MISMATCH:    return "ERR_SEQ_MISMATCH";
        case OMEGA_CAP_ERR_REPLAY:          return "ERR_REPLAY";
        case OMEGA_CAP_ERR_HASH_INVOL:      return "ERR_HASH_INVOLUTION";
        case OMEGA_CAP_ERR_ZERO_ANCHOR:     return "ERR_ZERO_ANCHOR";
        case OMEGA_CAP_ERR_CHAIN_FORK:      return "ERR_CHAIN_FORK";
        case OMEGA_CAP_ERR_TIME_BUDGET:     return "ERR_TIME_BUDGET";
        case OMEGA_CAP_ERR_BELNAP_OMEGA:    return "ERR_BELNAP_OMEGA";
        case OMEGA_CAP_ERR_COBORDISM_MAAT:  return "ERR_COBORDISM_MAAT";
        case OMEGA_CAP_ERR_HPIS_MISMATCH:   return "ERR_HPIS_MISMATCH";
        case OMEGA_CAP_ERR_THERMO_LANDAUER: return "ERR_THERMO_LANDAUER";
        case OMEGA_CAP_ERR_DRIFT_IEEE754:   return "ERR_DRIFT_IEEE754";
        default:                            return "ERR_UNKNOWN";
    }
}
