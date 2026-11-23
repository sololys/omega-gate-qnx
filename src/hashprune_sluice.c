/*
 * hashprune_sluice.c — Zero-Float C11 Port of Dual-Rate HashPrune Sluice
 *
 * Parity target: L1 Dual-Rate HashPrune Sluice specification (0-float)
 *   - Exact Q16.16 coordinates & tau/dtau (int32_t / int64_t)
 *   - Exact int64_t Q32.32 squared distances (zero rounding error)
 *   - Exact decimal ppm for pi_drift & epsilon_drift (1/100 == 10000 ppm)
 *   - Append-only SHA-256 witness ledger (sha256_zero_dep.c)
 */

#include "omega_cascade.h"
#include "sha256_zero_dep.h"

#include <stdio.h>
#include <string.h>

static int64_t hp_dot_q32(uint32_t dim, const int32_t a[HP_MAX_DIM], const int32_t b[HP_MAX_DIM]) {
    int64_t acc = 0;
    for (uint32_t i = 0; i < dim; ++i) {
        acc += (int64_t)a[i] * (int64_t)b[i];
    }
    return acc;
}

static uint32_t hp_compute_bucket(const hp_reservoir_t *r, const int32_t delta[HP_MAX_DIM]) {
    uint32_t mask = 0;
    for (uint32_t idx = 0; idx < r->num_planes; ++idx) {
        if (hp_dot_q32(r->dim, r->planes_q16[idx], delta) >= 0) {
            mask |= (1u << idx);
        }
    }
    return mask;
}

void hp_reservoir_init(hp_reservoir_t *r, uint32_t node_id, uint32_t dim,
                       const int32_t origin_q16[HP_MAX_DIM],
                       uint32_t num_planes,
                       const int32_t planes_q16[][HP_MAX_DIM],
                       uint32_t l_max) {
    memset(r, 0, sizeof(*r));
    r->node_id = node_id;
    r->dim = (dim > HP_MAX_DIM) ? HP_MAX_DIM : dim;
    for (uint32_t i = 0; i < r->dim; ++i) {
        r->origin_q16[i] = origin_q16[i];
    }
    r->num_planes = (num_planes > HP_MAX_PLANES) ? HP_MAX_PLANES : num_planes;
    for (uint32_t p = 0; p < r->num_planes; ++p) {
        for (uint32_t i = 0; i < r->dim; ++i) {
            r->planes_q16[p][i] = planes_q16[p][i];
        }
    }
    r->l_max = (l_max > HP_MAX_BUCKETS) ? HP_MAX_BUCKETS : ((l_max == 0) ? 1u : l_max);
}

static int hp_find_bucket_slot(const hp_reservoir_t *r, uint32_t mask) {
    for (uint32_t i = 0; i < HP_MAX_BUCKETS; ++i) {
        if (r->slots[i].occupied && r->slots[i].bucket_mask == mask) {
            return (int)i;
        }
    }
    return -1;
}

static int hp_find_free_slot(const hp_reservoir_t *r) {
    for (uint32_t i = 0; i < HP_MAX_BUCKETS; ++i) {
        if (!r->slots[i].occupied) {
            return (int)i;
        }
    }
    return -1;
}

bool hp_reservoir_admit(hp_reservoir_t *r, uint32_t target_id,
                        const int32_t target_pos_q16[HP_MAX_DIM],
                        uint32_t *out_winner_id, int64_t *out_dist_sq_q32) {
    int32_t delta[HP_MAX_DIM] = {0, 0, 0};
    for (uint32_t i = 0; i < r->dim; ++i) {
        delta[i] = target_pos_q16[i] - r->origin_q16[i];
    }
    int64_t dist_sq = hp_dot_q32(r->dim, delta, delta);
    uint32_t bucket = hp_compute_bucket(r, delta);

    /* 1. Collision gate in existing angular bucket (Theorem 3.1 deterministic tie-break) */
    int existing = hp_find_bucket_slot(r, bucket);
    if (existing >= 0) {
        hp_bucket_slot_t *inc = &r->slots[existing];
        bool better = (dist_sq < inc->dist_sq_q32) ||
                      (dist_sq == inc->dist_sq_q32 && target_id < inc->target_id);
        if (better) {
            inc->target_id = target_id;
            inc->dist_sq_q32 = dist_sq;
            if (out_winner_id) *out_winner_id = target_id;
            if (out_dist_sq_q32) *out_dist_sq_q32 = dist_sq;
            return true;
        }
        if (out_winner_id) *out_winner_id = inc->target_id;
        if (out_dist_sq_q32) *out_dist_sq_q32 = inc->dist_sq_q32;
        return false;
    }

    /* 2. New bucket under l_max capacity */
    if (r->count < r->l_max) {
        int slot = hp_find_free_slot(r);
        if (slot >= 0) {
            r->slots[slot].occupied = true;
            r->slots[slot].bucket_mask = bucket;
            r->slots[slot].target_id = target_id;
            r->slots[slot].dist_sq_q32 = dist_sq;
            r->count++;
            if (out_winner_id) *out_winner_id = target_id;
            if (out_dist_sq_q32) *out_dist_sq_q32 = dist_sq;
            return true;
        }
    }

    /* 3. Reservoir full: evict globally worst (dist_sq, target_id) lexicographically */
    int worst_idx = -1;
    for (uint32_t i = 0; i < HP_MAX_BUCKETS; ++i) {
        if (!r->slots[i].occupied) continue;
        if (worst_idx < 0 ||
            r->slots[i].dist_sq_q32 > r->slots[worst_idx].dist_sq_q32 ||
            (r->slots[i].dist_sq_q32 == r->slots[worst_idx].dist_sq_q32 &&
             r->slots[i].target_id > r->slots[worst_idx].target_id)) {
            worst_idx = (int)i;
        }
    }

    if (worst_idx >= 0) {
        hp_bucket_slot_t *w = &r->slots[worst_idx];
        bool better_than_worst = (dist_sq < w->dist_sq_q32) ||
                                 (dist_sq == w->dist_sq_q32 && target_id < w->target_id);
        if (better_than_worst) {
            w->bucket_mask = bucket;
            w->target_id = target_id;
            w->dist_sq_q32 = dist_sq;
            if (out_winner_id) *out_winner_id = target_id;
            if (out_dist_sq_q32) *out_dist_sq_q32 = dist_sq;
            return true;
        }
    }

    if (out_winner_id) *out_winner_id = target_id;
    if (out_dist_sq_q32) *out_dist_sq_q32 = dist_sq;
    return false;
}

bool hp_reservoir_min_dist_sq(const hp_reservoir_t *r, int64_t *out_min_q32) {
    bool found = false;
    int64_t best = 0;
    for (uint32_t i = 0; i < HP_MAX_BUCKETS; ++i) {
        if (!r->slots[i].occupied) continue;
        if (!found || r->slots[i].dist_sq_q32 < best) {
            best = r->slots[i].dist_sq_q32;
            found = true;
        }
    }
    if (found && out_min_q32) {
        *out_min_q32 = best;
    }
    return found;
}

bool hp_reservoir_get_bucket(const hp_reservoir_t *r, uint32_t mask,
                             uint32_t *out_target_id, int64_t *out_dist_sq_q32) {
    int idx = hp_find_bucket_slot(r, mask);
    if (idx < 0) return false;
    if (out_target_id) *out_target_id = r->slots[idx].target_id;
    if (out_dist_sq_q32) *out_dist_sq_q32 = r->slots[idx].dist_sq_q32;
    return true;
}

bool hp_reservoir_equal(const hp_reservoir_t *a, const hp_reservoir_t *b) {
    if (a->count != b->count) return false;
    for (uint32_t i = 0; i < HP_MAX_BUCKETS; ++i) {
        if (!a->slots[i].occupied) continue;
        uint32_t tid = 0;
        int64_t d2 = 0;
        if (!hp_reservoir_get_bucket(b, a->slots[i].bucket_mask, &tid, &d2)) {
            return false;
        }
        if (tid != a->slots[i].target_id || d2 != a->slots[i].dist_sq_q32) {
            return false;
        }
    }
    return true;
}

/* ============================================================================
 * Dual-Rate Governance Sluice
 * ============================================================================ */

static void hp_hash_entry(const hp_witness_entry_t *e, uint8_t out_hash[32]) {
    uint8_t buf[160];
    int n = snprintf((char *)buf, sizeof(buf), "%u|%u|%u|%u|%lld|%d|%s",
                     e->seq, (unsigned)e->rate_domain, (unsigned)e->owner_port,
                     (unsigned)e->verdict, (long long)e->tau_q16,
                     (int)e->dtau_q16, e->delta_k);
    if (n < 0) n = 0;
    if ((size_t)n >= sizeof(buf)) n = (int)(sizeof(buf) - 1);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, buf, (size_t)n);
    sha256_update(&ctx, e->prev_hash, 32);
    sha256_final(&ctx, out_hash);
}

static void hp_seal_witness(hp_sluice_t *s, hp_rate_domain_t domain,
                            uint8_t verdict, const char *delta_k) {
    hp_witness_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.seq = s->ledger_len + 1u;
    entry.rate_domain = (uint8_t)domain;
    entry.owner_port = (uint8_t)s->owner_port;
    entry.verdict = verdict;
    entry.tau_q16 = s->tau_now_q16;
    entry.dtau_q16 = s->dtau_q16;
    snprintf(entry.delta_k, sizeof(entry.delta_k), "%s", delta_k ? delta_k : "");
    memcpy(entry.prev_hash, s->head_hash, 32);
    hp_hash_entry(&entry, entry.entry_hash);

    memcpy(s->head_hash, entry.entry_hash, 32);
    if (s->ledger_len < HP_MAX_LEDGER_ENTRIES) {
        s->ledger[s->ledger_len] = entry;
    }
    s->ledger_len++;
}

void hp_sluice_init(hp_sluice_t *s,
                    const hp_reservoir_t *reservoir,
                    int64_t safe_dist_sq_min_q32,
                    uint32_t epsilon_drift_ppm,
                    int64_t tau_max_hold_q16,
                    int32_t dtau_initial_q16,
                    int32_t dtau_min_q16,
                    uint32_t min_fsync_cycles) {
    memset(s, 0, sizeof(*s));
    s->reservoir = *reservoir;
    s->safe_dist_sq_min_q32 = safe_dist_sq_min_q32;
    s->epsilon_drift_ppm = epsilon_drift_ppm;
    s->tau_max_hold_q16 = tau_max_hold_q16;
    s->dtau_q16 = dtau_initial_q16;
    s->dtau_min_q16 = dtau_min_q16;
    s->min_fsync_cycles = min_fsync_cycles;
    s->voltage_mv = 0;
    s->owner_port = HP_OWNER_P_INT;
}

static hp_step_result_t hp_trip_kill(hp_sluice_t *s, const char *reason) {
    s->latched_kill = true;
    s->voltage_mv = 0;
    s->owner_port = HP_OWNER_HARDWARE_CROWBAR;
    hp_seal_witness(s, HP_RATE_KILL_LATCH, (uint8_t)HP_RES_KILL, reason);
    return HP_RES_KILL;
}

static hp_step_result_t hp_enter_hold(hp_sluice_t *s, const char *reason) {
    if (!reason || reason[0] == '\0') {
        s->voltage_mv = 0;
        s->owner_port = HP_OWNER_P_EXT;
        hp_seal_witness(s, HP_RATE_CLOCK_ESCALATION, (uint8_t)HP_RES_ESCALATED_EXT,
                        "SILENT_HOLD_FORBIDDEN");
        return HP_RES_ESCALATED_EXT;
    }
    s->voltage_mv = 0;
    if (!s->has_hold_since) {
        s->has_hold_since = true;
        s->hold_since_q16 = s->tau_now_q16;
    }
    snprintf(s->hold_reason, sizeof(s->hold_reason), "%s", reason);
    hp_seal_witness(s, HP_RATE_LOW_EVENT, (uint8_t)HP_RES_HOLD, reason);
    return HP_RES_HOLD;
}

static bool hp_check_stalled_hold(hp_sluice_t *s) {
    if (!s->has_hold_since) return false;
    int64_t stalled = s->tau_now_q16 - s->hold_since_q16;
    if (s->owner_port == HP_OWNER_P_INT && stalled > s->tau_max_hold_q16) {
        s->owner_port = HP_OWNER_P_EXT;
        s->voltage_mv = 0;
        hp_seal_witness(s, HP_RATE_CLOCK_ESCALATION, (uint8_t)HP_RES_ESCALATED_EXT,
                        "STALLED_HOLD_NEVER_OPENS_BY_TIME");
        return true;
    }
    return false;
}

hp_step_result_t hp_sluice_step(hp_sluice_t *s,
                                uint32_t target_id,
                                const int32_t target_pos_q16[HP_MAX_DIM],
                                uint32_t pi_drift_ppm,
                                bool involution_ok,
                                bool human_l01_witness) {
    /* 0. Hardware crowbar latch cannot be cleared by ordinary steps */
    if (s->latched_kill) {
        s->voltage_mv = 0;
        return HP_RES_KILL_LATCHED;
    }

    s->tau_now_q16 += (int64_t)s->dtau_q16;

    /* 1. Involution check F(F(s)) == s */
    if (!involution_ok) {
        return hp_trip_kill(s, "INVOLUTION_BREACH_F2_NEQ_I");
    }

    /* 2. Drift threshold -> HOLD + halve dtau (with D1 Zeno guard) */
    if (pi_drift_ppm >= s->epsilon_drift_ppm) {
        s->fsync_pending = false;
        s->fsync_cycles_waited = 0;
        int32_t next_dtau = s->dtau_q16 >> 1;
        if (next_dtau < s->dtau_min_q16) {
            return hp_trip_kill(s, "DTAU_UNDERFLOW_ZENO_TRAP");
        }
        s->dtau_q16 = next_dtau;
        return hp_enter_hold(s, "DRIFT_EXCEEDED_DTAU_HALVED");
    }

    /* 3. Update HashPrune reservoir (O(1)) */
    bool topology_changed = hp_reservoir_admit(&s->reservoir, target_id, target_pos_q16, NULL, NULL);
    int64_t min_d2_q32 = 0;
    bool has_min = hp_reservoir_min_dist_sq(&s->reservoir, &min_d2_q32);

    /* 4. Double-Clock escalation BEFORE repeating barrier HOLD */
    if (hp_check_stalled_hold(s)) {
        s->fsync_pending = false;
        s->fsync_cycles_waited = 0;
        return HP_RES_ESCALATED_EXT;
    }

    /* 5. Safety barrier g(x) <= 0 */
    if (has_min && min_d2_q32 < s->safe_dist_sq_min_q32) {
        s->fsync_pending = false;
        s->fsync_cycles_waited = 0;
        if (s->has_hold_since) {
            s->voltage_mv = 0;
            return HP_RES_HOLD_ACTIVE;
        }
        return hp_enter_hold(s, "BARRIER_PROXIMITY");
    }

    /* 6. Active HOLD requires explicit L01 human witness to exit */
    if (s->has_hold_since && !human_l01_witness) {
        s->voltage_mv = 0;
        return HP_RES_HOLD_ACTIVE;
    }

    /* 7. Continuous micro-step without topological event (0 new hashes) */
    if (!topology_changed && s->voltage_mv == 5000u) {
        s->high_rate_passes++;
        return HP_RES_CONTINUOUS_PASS;
    }

    /* 8. Turning point or re-opening -> witness + D2 patient fsync */
    if (!human_l01_witness) {
        s->fsync_pending = false;
        s->fsync_cycles_waited = 0;
        return hp_enter_hold(s, "MISSING_HUMAN_L01_WITNESS");
    }

    if (s->min_fsync_cycles > 0u && s->voltage_mv == 0u) {
        if (!s->fsync_pending) {
            s->fsync_pending = true;
            s->fsync_cycles_waited = 1u;
            hp_seal_witness(s, HP_RATE_LOW_EVENT, (uint8_t)HP_RES_HOLD,
                            "INTENT_SEALED_FSYNC_WAIT");
            return HP_RES_FSYNC_WAIT;
        }
        if (s->fsync_cycles_waited < s->min_fsync_cycles) {
            s->fsync_cycles_waited++;
            return HP_RES_FSYNC_WAIT;
        }
    }

    s->fsync_pending = false;
    s->fsync_cycles_waited = 0;
    s->has_hold_since = false;
    s->hold_reason[0] = '\0';
    s->voltage_mv = 5000u;
    hp_seal_witness(s, HP_RATE_LOW_EVENT, (uint8_t)HP_RES_OPEN, "VERIFIED_TOPOLOGY");
    return HP_RES_OPEN;
}

bool hp_sluice_verify_ledger(const hp_sluice_t *s) {
    uint8_t expected_prev[32];
    memset(expected_prev, 0, sizeof(expected_prev));
    uint32_t check_n = (s->ledger_len < HP_MAX_LEDGER_ENTRIES) ? s->ledger_len : HP_MAX_LEDGER_ENTRIES;
    for (uint32_t i = 0; i < check_n; ++i) {
        const hp_witness_entry_t *e = &s->ledger[i];
        if (e->seq != (i + 1u)) return false;
        if (memcmp(e->prev_hash, expected_prev, 32) != 0) return false;
        uint8_t recomputed[32];
        hp_hash_entry(e, recomputed);
        if (memcmp(recomputed, e->entry_hash, 32) != 0) return false;
        memcpy(expected_prev, e->entry_hash, 32);
    }
    return true;
}

const char *hp_step_result_name(hp_step_result_t r) {
    switch (r) {
        case HP_RES_OPEN:            return "OPEN";
        case HP_RES_CONTINUOUS_PASS: return "CONTINUOUS_PASS";
        case HP_RES_HOLD:            return "HOLD";
        case HP_RES_HOLD_ACTIVE:     return "HOLD_ACTIVE";
        case HP_RES_FSYNC_WAIT:      return "FSYNC_WAIT";
        case HP_RES_ESCALATED_EXT:   return "ESCALATED_EXT";
        case HP_RES_KILL:            return "KILL";
        case HP_RES_KILL_LATCHED:    return "KILL_LATCHED";
        default:                     return "UNKNOWN";
    }
}

const char *omega_peer_name(uint32_t peer_id) {
    switch (peer_id) {
        case OMEGA_PEER_D0_TRAP:      return "d0_trap";
        case OMEGA_PEER_D1_GUESTROOM: return "d1_guestroom";
        case OMEGA_PEER_TRAP_MIRROR:  return "trap_mirror_daemon";
        default:                      return "unknown_peer";
    }
}

const char *omega_cascade_verdict_name(uint8_t v) {
    switch (v) {
        case OMEGA_CVERD_HOLD:            return "HOLD";
        case OMEGA_CVERD_OPEN:            return "OPEN";
        case OMEGA_CVERD_TRAP:            return "TRAP";
        case OMEGA_CVERD_KILL:            return "KILL";
        case OMEGA_CVERD_FSYNC_WAIT:      return "FSYNC_WAIT";
        case OMEGA_CVERD_ESCALATED_EXT:   return "ESCALATED_EXT";
        case OMEGA_CVERD_CONTINUOUS_PASS: return "CONTINUOUS_PASS";
        default:                          return "UNKNOWN";
    }
}

const char *omega_cascade_reason_name(uint32_t r) {
    switch (r) {
        case OMEGA_CRSN_OK:                 return "OK";
        case OMEGA_CRSN_FSYNC_WAITING:      return "FSYNC_WAITING";
        case OMEGA_CRSN_CONTINUOUS_PASS:    return "CONTINUOUS_PASS";
        case OMEGA_CRSN_HOLD_DRIFT:         return "HOLD_DRIFT";
        case OMEGA_CRSN_HOLD_BARRIER:       return "HOLD_BARRIER";
        case OMEGA_CRSN_HOLD_NO_WITNESS:    return "HOLD_NO_WITNESS";
        case OMEGA_CRSN_HOLD_AIRLOCK:       return "HOLD_AIRLOCK";
        case OMEGA_CRSN_ESCALATED_STALLED:  return "ESCALATED_STALLED";
        case OMEGA_CRSN_TRAP_MIRROR:        return "TRAP_MIRROR";
        case OMEGA_CRSN_KILL_INVOLUTION:    return "KILL_INVOLUTION";
        case OMEGA_CRSN_KILL_ZENO_DTAU:     return "KILL_ZENO_DTAU";
        case OMEGA_CRSN_KILL_POINCARE:      return "KILL_POINCARE";
        case OMEGA_CRSN_KILL_HOSTILE:       return "KILL_HOSTILE";
        case OMEGA_CRSN_KILL_LATCHED:       return "KILL_LATCHED";
        case OMEGA_CRSN_WATCHDOG_PEER_DEAD: return "WATCHDOG_PEER_DEAD";
        case OMEGA_CRSN_WATCHDOG_TIMEOUT:   return "WATCHDOG_TIMEOUT";
        case OMEGA_CRSN_WATCHDOG_LOCKED:    return "WATCHDOG_LOCKED";
        case OMEGA_CRSN_L01_RESET_OK:       return "L01_RESET_OK";
        case OMEGA_CRSN_L01_RESET_INVALID:  return "L01_RESET_INVALID";
        case OMEGA_CRSN_TOF_CAUSALITY:      return "TOF_CAUSALITY";
        case OMEGA_CRSN_L01_RESET_ARMED:    return "L01_RESET_ARMED";
        case OMEGA_CRSN_L01_RESET_COOLDOWN: return "L01_RESET_COOLDOWN";
        case OMEGA_CRSN_SPI_IO_FAULT:       return "SPI_IO_FAULT";
        default:                            return "UNKNOWN";
    }
}

void omega_compute_l01_key_hash16(const char *token, uint8_t out16[16]) {
    uint8_t digest[32];
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)token, strlen(token));
    sha256_final(&ctx, digest);
    memcpy(out16, digest, 16);
}

/* IEEE 802.3 / ISO-HDLC CRC-32 (reflected poly 0xEDB88320, init/xorout 0xFFFFFFFF) */
uint32_t omega_crc32_ieee(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t)p[i];
        for (int b = 0; b < 8; ++b) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

void omega_cascade_seal_req(omega_cascade_req_t *req) {
    req->crc32 = omega_crc32_ieee(req, offsetof(omega_cascade_req_t, crc32));
}

bool omega_cascade_verify_req(const omega_cascade_req_t *req) {
    uint32_t expected = omega_crc32_ieee(req, offsetof(omega_cascade_req_t, crc32));
    return req->crc32 == expected;
}

bool omega_tof_causal_ok(uint16_t uwb_tof_ns, uint16_t flags) {
    bool uwb_active  = (flags & OMEGA_FLAG_UWB_LINK_ACTIVE) != 0;
    bool kpod_sealed = (flags & OMEGA_FLAG_KPOD_SEALED) != 0;

    /* Active UWB link reporting 0 ns is a non-causal (spacelike) breach: never masked */
    if (uwb_active && uwb_tof_ns < OMEGA_TOF_MIN_NS) {
        return false;
    }
    if (uwb_tof_ns >= OMEGA_TOF_MIN_NS && uwb_tof_ns <= OMEGA_TOF_MAX_NS) {
        return true;
    }
    /* Physical courier bypass only when UWB link is inactive */
    if (!uwb_active && kpod_sealed) {
        return true;
    }
    return false;
}

void omega_l01_gov_init(omega_l01_reset_gov_t *gov, uint32_t cooldown_ms, uint32_t expiry_ms) {
    if (!gov) return;
    gov->armed        = false;
    gov->armed_at_ns  = 0ULL;
    gov->armed_seq_id = 0u;
    gov->cooldown_ns  = (uint64_t)cooldown_ms * 1000000ULL;
    gov->expiry_ns    = (uint64_t)expiry_ms * 1000000ULL;
}

omega_cascade_reason_t omega_l01_gov_step(
    omega_l01_reset_gov_t *gov,
    uint32_t seq_id,
    bool key_valid,
    uint64_t now_ns
) {
    if (!gov || !key_valid) {
        return OMEGA_CRSN_L01_RESET_INVALID;
    }

    if (!gov->armed) {
        gov->armed        = true;
        gov->armed_at_ns  = now_ns;
        gov->armed_seq_id = seq_id;
        return OMEGA_CRSN_L01_RESET_ARMED;
    }

    /* Phase 2 requires strictly increasing seq_id */
    if (seq_id <= gov->armed_seq_id) {
        gov->armed_at_ns  = now_ns;
        gov->armed_seq_id = seq_id;
        return OMEGA_CRSN_L01_RESET_COOLDOWN;
    }

    uint64_t elapsed_ns = (now_ns >= gov->armed_at_ns) ? (now_ns - gov->armed_at_ns) : 0ULL;

    /* Impatient attempt before cooldown expires: reject and restart cooldown timer */
    if (elapsed_ns < gov->cooldown_ns) {
        gov->armed_at_ns  = now_ns;
        gov->armed_seq_id = seq_id;
        return OMEGA_CRSN_L01_RESET_COOLDOWN;
    }

    /* Confirmation window expired: re-arm from Phase 1 */
    if (gov->expiry_ns > 0ULL && elapsed_ns > (gov->cooldown_ns + gov->expiry_ns)) {
        gov->armed_at_ns  = now_ns;
        gov->armed_seq_id = seq_id;
        return OMEGA_CRSN_L01_RESET_ARMED;
    }

    /* Phase 2 confirmed within valid window -> release latch */
    gov->armed        = false;
    gov->armed_at_ns  = 0ULL;
    gov->armed_seq_id = 0u;
    return OMEGA_CRSN_L01_RESET_OK;
}
