/*
 * Zero-float C11 consequence gate core (OmegaGate-QNX).
 * Mirrors robot_trap_gate.sv and robot_trap_omega_gate.py with exact integer math.
 */

#include "omega_gate.h"
#include "sha256_zero_dep.h"
#include <stdio.h>
#include <string.h>

static int32_t i32_abs_clamped(int32_t v) {
    if (v == INT32_MIN) {
        return INT32_MAX;
    }
    return (v < 0) ? -v : v;
}

const char *omega_decision_name(omega_decision_t d) {
    switch (d) {
        case OMEGA_DEC_HOLD: return "HOLD";
        case OMEGA_DEC_OPEN: return "OPEN";
        case OMEGA_DEC_TRAP: return "TRAP";
        case OMEGA_DEC_KILL: return "KILL";
        default:             return "UNKNOWN";
    }
}

const char *omega_reason_name(omega_reason_t r) {
    switch (r) {
        case OMEGA_RSN_IDLE_HOLD:       return "IDLE_HOLD";
        case OMEGA_RSN_OPEN_PULSE:      return "AUTHORIZED_5000MV_PULSE";
        case OMEGA_RSN_INTERMEDIATE:    return "INTERMEDIATE_STAGE_HOLD";
        case OMEGA_RSN_EARLY_NO_WIT:    return "UNWITNESSED_OR_EARLY_HOLD";
        case OMEGA_RSN_TRAP_MIRROR:     return "SHUNTED_TO_MIRROR_CHAMBER";
        case OMEGA_RSN_KILL_SHORTCUT:   return "FORBIDDEN_SHORTCUT_TYPE_BREACH";
        case OMEGA_RSN_KILL_REPLAY:     return "TIMING_LAW_REPLAY_ATTACK";
        case OMEGA_RSN_KILL_LIGHTCONE:  return "LIGHTCONE_EXPIRED";
        case OMEGA_RSN_KILL_GUILLOTINE: return "TORQUE_OR_JERK_GUILLOTINE";
        case OMEGA_RSN_KILL_HOSTILE:    return "HOSTILE_ANOMALY_KILL";
        case OMEGA_RSN_KILL_LATCHED:    return "KILL_LATCHED_REQUIRES_L01_RESET";
        case OMEGA_RSN_L01_RESET:       return "L01_AUTHORIZED_RESET_TO_HOLD";
        case OMEGA_RSN_INVALID_KEY:     return "INVALID_L01_RESET_KEY";
        default:                        return "UNKNOWN_REASON";
    }
}

static void ledger_hash_record(const omega_witness_t *w, char out_hex[65]) {
    char buf[256];
    int n = snprintf(
        buf, sizeof(buf),
        "%u|%u|%s|%u|%s|%s",
        w->index,
        w->seq_id,
        omega_decision_name(w->decision),
        (unsigned)w->voltage_mv,
        omega_reason_name(w->reason),
        w->prev_hash
    );
    if (n < 0) {
        n = 0;
    } else if ((size_t)n >= sizeof(buf)) {
        n = (int)(sizeof(buf) - 1u);
    }
    sha256_hex((const uint8_t *)buf, (size_t)n, out_hex);
}

static void ledger_append(omega_gate_t *g, uint32_t seq_id, omega_decision_t dec,
                          omega_reason_t rsn, uint16_t voltage_mv) {
    if (g->ledger_len >= OMEGA_MAX_LEDGER_ENTRIES) {
        /* Fail-closed: ledger saturation latches KILL */
        g->kill_latched = true;
        return;
    }
    omega_witness_t *w = &g->ledger[g->ledger_len];
    w->index = g->ledger_len;
    w->seq_id = seq_id;
    w->decision = dec;
    w->reason = rsn;
    w->voltage_mv = voltage_mv;
    memcpy(w->prev_hash, g->head_hash, 65u);
    ledger_hash_record(w, w->record_hash);
    memcpy(g->head_hash, w->record_hash, 65u);
    g->ledger_len++;
}

void omega_gate_init(omega_gate_t *g) {
    memset(g, 0, sizeof(*g));
    memset(g->head_hash, '0', 64u);
    g->head_hash[64] = '\0';
    g->rail_state = OMEGA_RAIL_CLAMPED;
}

static void fill_rail_outputs(const omega_gate_t *g, uint8_t *rail_5v_en, uint8_t *crowbar_gnd) {
    /* Mutual exclusion invariant: rail_5v_en * crowbar_gnd == 0 ALWAYS */
    *rail_5v_en  = (g->rail_state == OMEGA_RAIL_PULSE_5V && !g->kill_latched) ? 1u : 0u;
    *crowbar_gnd = (g->rail_state == OMEGA_RAIL_CLAMPED  || g->kill_latched) ? 1u : 0u;
}

void omega_gate_tick_deadtime(omega_gate_t *g, uint8_t *rail_5v_en, uint8_t *crowbar_gnd) {
    if (g->kill_latched) {
        g->rail_state = OMEGA_RAIL_CLAMPED;
        g->deadtime_cnt = 0u;
    } else if (g->rail_state == OMEGA_RAIL_DEADTIME) {
        if (g->deadtime_cnt == 0u) {
            g->rail_state = OMEGA_RAIL_PULSE_5V;
        } else {
            g->deadtime_cnt--;
        }
    } else if (g->rail_state == OMEGA_RAIL_PULSE_5V) {
        g->rail_state = OMEGA_RAIL_CLAMPED;
    }
    fill_rail_outputs(g, rail_5v_en, crowbar_gnd);
}

bool omega_gate_l01_reset(omega_gate_t *g, const char *token) {
    if (token == NULL || strncmp(token, OMEGA_L01_KEY_TOKEN, 32u) != 0) {
        ledger_append(g, g->last_seq_id, OMEGA_DEC_KILL, OMEGA_RSN_INVALID_KEY, 0u);
        return false;
    }
    g->kill_latched = false;
    g->has_prev_ts = false;
    g->rail_state = OMEGA_RAIL_CLAMPED;
    g->deadtime_cnt = 0u;
    ledger_append(g, g->last_seq_id, OMEGA_DEC_HOLD, OMEGA_RSN_L01_RESET, 0u);
    return true;
}

void omega_gate_eval(omega_gate_t *g, const omega_cmd_t *cmd, omega_reply_t *out) {
    memset(out, 0, sizeof(*out));
    out->seq_id = cmd->seq_id;

    /* Explicit L01 physical operator reset path (append-only) */
    if (cmd->is_l01_reset) {
        bool ok = omega_gate_l01_reset(g, cmd->l01_token);
        out->decision = ok ? OMEGA_DEC_HOLD : OMEGA_DEC_KILL;
        out->reason = ok ? OMEGA_RSN_L01_RESET : OMEGA_RSN_INVALID_KEY;
        out->voltage_mv = 0u;
        out->kill_latched = g->kill_latched ? 1u : 0u;
        fill_rail_outputs(g, &out->rail_5v_en, &out->crowbar_gnd);
        out->ledger_len = g->ledger_len;
        memcpy(out->head_hash, g->head_hash, 65u);
        return;
    }

    omega_decision_t dec = OMEGA_DEC_HOLD;
    omega_reason_t rsn = OMEGA_RSN_IDLE_HOLD;
    uint16_t mv = 0u;

    /* 0. Sticky KILL latch cannot be cleared by ordinary commands */
    if (g->kill_latched) {
        dec = OMEGA_DEC_KILL;
        rsn = OMEGA_RSN_KILL_LATCHED;
        g->rail_state = OMEGA_RAIL_CLAMPED;
    } else {
        /* 1. Type-chain guard (no shortcuts, no wraparound) */
        bool shortcut = (cmd->prev_stage >= OMEGA_STAGE_COMMITTED) ||
                        (cmd->stage != (uint8_t)(cmd->prev_stage + 1u));

        /* 2. Timing Law (anti-replay on seq_id & timestamp, lightcone <= 133 ns) */
        bool replay = (cmd->seq_id <= g->last_seq_id) ||
                      (cmd->timestamp_ns == 0u) ||
                      (g->has_prev_ts && cmd->timestamp_ns <= g->last_ts_ns);
        bool lightcone = g->has_prev_ts &&
                         (cmd->timestamp_ns > g->last_ts_ns) &&
                         ((cmd->timestamp_ns - g->last_ts_ns) > OMEGA_LIGHTCONE_MAX_NS);

        /* 3. Physical envelopes (Torque <= 80 Nm, Jerk <= 25 rad/s^3) */
        bool guillotine = (i32_abs_clamped(cmd->torque_mnm) > OMEGA_MAX_TORQUE_MNM) ||
                          (i32_abs_clamped(cmd->jerk_mrad_s3) > OMEGA_MAX_JERK_MRAD_S3);

        /* 4. Hostile or negative anomaly */
        bool hostile = (cmd->anomaly_score < 0) || (cmd->anomaly_score >= OMEGA_KILL_ANOMALY_TH);

        if (shortcut || replay || lightcone || guillotine || hostile) {
            g->kill_latched = true;
            g->rail_state = OMEGA_RAIL_CLAMPED;
            dec = OMEGA_DEC_KILL;
            if (shortcut)        rsn = OMEGA_RSN_KILL_SHORTCUT;
            else if (replay)     rsn = OMEGA_RSN_KILL_REPLAY;
            else if (lightcone)  rsn = OMEGA_RSN_KILL_LIGHTCONE;
            else if (guillotine) rsn = OMEGA_RSN_KILL_GUILLOTINE;
            else                 rsn = OMEGA_RSN_KILL_HOSTILE;
        } else if (cmd->anomaly_score > 0) {
            /* TRAP -> shunt to mirror chamber at 0 mV */
            g->trap_count++;
            g->last_ts_ns = cmd->timestamp_ns;
            g->has_prev_ts = true;
            g->last_seq_id = cmd->seq_id;
            g->rail_state = OMEGA_RAIL_CLAMPED;
            dec = OMEGA_DEC_TRAP;
            rsn = OMEGA_RSN_TRAP_MIRROR;
            out->trap_mirror_strobe = 1u;
        } else if (cmd->stage != OMEGA_STAGE_COMMITTED) {
            /* Intermediate stage never energizes 5.00 V */
            g->last_ts_ns = cmd->timestamp_ns;
            g->has_prev_ts = true;
            g->last_seq_id = cmd->seq_id;
            g->rail_state = OMEGA_RAIL_CLAMPED;
            dec = OMEGA_DEC_HOLD;
            rsn = OMEGA_RSN_INTERMEDIATE;
        } else if (cmd->airlock_elapsed_ms < OMEGA_MIN_AIRLOCK_MS || !cmd->witness_ok) {
            /* Early or unwitnessed -> HOLD (0 mV) */
            g->last_ts_ns = cmd->timestamp_ns;
            g->has_prev_ts = true;
            g->last_seq_id = cmd->seq_id;
            g->rail_state = OMEGA_RAIL_CLAMPED;
            dec = OMEGA_DEC_HOLD;
            rsn = OMEGA_RSN_EARLY_NO_WIT;
        } else {
            /* Authorized OPEN -> enter 2-cycle deadtime before 5.00 V pulse */
            g->last_ts_ns = cmd->timestamp_ns;
            g->has_prev_ts = true;
            g->last_seq_id = cmd->seq_id;
            g->rail_state = OMEGA_RAIL_DEADTIME;
            g->deadtime_cnt = (OMEGA_DEADTIME_CYCLES > 0u) ? (uint8_t)(OMEGA_DEADTIME_CYCLES - 1u) : 0u;
            dec = OMEGA_DEC_OPEN;
            rsn = OMEGA_RSN_OPEN_PULSE;
            mv = 5000u;
        }
    }

    ledger_append(g, cmd->seq_id, dec, rsn, mv);
    out->decision = dec;
    out->reason = rsn;
    out->voltage_mv = mv;
    out->kill_latched = g->kill_latched ? 1u : 0u;
    fill_rail_outputs(g, &out->rail_5v_en, &out->crowbar_gnd);
    out->ledger_len = g->ledger_len;
    memcpy(out->head_hash, g->head_hash, 65u);
}

bool omega_ledger_verify(const omega_gate_t *g) {
    char expected_prev[65];
    memset(expected_prev, '0', 64u);
    expected_prev[64] = '\0';

    for (uint32_t i = 0; i < g->ledger_len; ++i) {
        const omega_witness_t *w = &g->ledger[i];
        if (w->index != i || memcmp(w->prev_hash, expected_prev, 65u) != 0) {
            return false;
        }
        char recomputed[65];
        ledger_hash_record(w, recomputed);
        if (memcmp(recomputed, w->record_hash, 65u) != 0) {
            return false;
        }
        memcpy(expected_prev, w->record_hash, 65u);
    }
    return true;
}
