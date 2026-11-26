#ifndef OMEGA_OMG8_SLUICE_H
#define OMEGA_OMG8_SLUICE_H

#include "omega_gate.h"
#include "sha256_zero_dep.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ============================================================================
 * OmegaGate-QNX "OMG8" v1.1 64-Byte Multi-Channel Sluice & Isolated TRAP Bank
 *
 * Strictly integer-only C11 (0 IEEE-754 FP types or instructions, 0 malloc).
 * Mirrors the dual-core 8/8-DSP iCE40UP5K-SG48 silicon contract:
 *   - 1024 independent SPRAM-mapped channels (channel_id 0..1023)
 *   - Separate 1024-slot isolated TRAP forensic ring (no return valve to HOLD)
 *   - Bit-exact Q8.24 octave + 58-bit isqrt + 4th-order Taylor ln(1+s) bound
 *   - Pairwise Hamming distance >= 4 across HOLD (0x3C), OPEN (0xA5),
 *     TRAP (0x5A), and KILL (0x00)
 * ============================================================================ */

#define OMEGA_DEV_OMG8_GATE          "/dev/omg8_gate"
#define OMEGA_PRIO_OMG8_GATE         25

#define OMEGA_OMG8_MAGIC             0x4F4D4738u /* "OMG8" */
#define OMEGA_OMG8_VERSION           0x0101u     /* v1.1 */

#define OMEGA_OMG8_MAX_CHANNELS      1024u
#define OMEGA_OMG8_TRAP_RING_CAP     1024u
#define OMEGA_OMG8_MAX_RTL_CYCLES    80u

/* Gate states with pairwise Hamming distance >= 4 */
#define OMEGA_OMG8_STATE_HOLD        0x3Cu /* 0011_1100: 0.00 V reversible phase space */
#define OMEGA_OMG8_STATE_OPEN        0xA5u /* 1010_0101: 5.00 V 1-cycle strobe */
#define OMEGA_OMG8_STATE_TRAP        0x5Au /* 0101_1010: 0.00 V isolated mirror chamber */
#define OMEGA_OMG8_STATE_KILL        0x00u /* 0000_0000: 0.00 V sticky crowbar latch */

/* Byte 7 (bru_mirror_flags): [1:0]=bru_top_state, bit 2=mirror_ok, [7:3]=0 */
#define OMEGA_OMG8_BRU_HOLD          0x00u
#define OMEGA_OMG8_BRU_OPEN          0x01u
#define OMEGA_OMG8_BRU_KILL          0x02u
#define OMEGA_OMG8_BRU_STATE_MASK    0x03u
#define OMEGA_OMG8_MIRROR_OK_BIT     0x04u
#define OMEGA_OMG8_BRU_RESERVED_MASK 0xF8u

/* Error bitmask (uint16_t err_flags, byte 28..29) */
#define OMEGA_OMG8_ERR_NONE          0x0000u
#define OMEGA_OMG8_ERR_MARGIN_UNDER  0x0001u
#define OMEGA_OMG8_ERR_NO_WITNESS    0x0002u
#define OMEGA_OMG8_ERR_TIMEOUT       0x0004u
#define OMEGA_OMG8_ERR_PARITY        0x0008u
#define OMEGA_OMG8_ERR_MIRROR_TRAP   0x0010u

/* Q8.24 integer logarithm constants (1.0 == 1 << 24) */
#define OMEGA_Q24_ONE                0x01000000u
#define OMEGA_Q24_QUARTER            0x00400000u
#define OMEGA_Q24_LN2_LOWER          0x00B17217u
#define OMEGA_Q24_INV3_Q32           0x55555555ULL

/* Hardware port 0xE9 output bitmask (0 shoot-through: bit 0 & bit 1 never both 1) */
#define OMEGA_OMG8_HW_HOLD_0V        0x00u
#define OMEGA_OMG8_HW_OPEN_5V        0x01u
#define OMEGA_OMG8_HW_KILL_CROWBAR   0x02u
#define OMEGA_OMG8_HW_TRAP_SHUNT     0x04u

/* Locked 64-byte "OMG8" v1.1 wire & SPRAM frame */
typedef struct __attribute__((packed)) {
    uint32_t magic;              /*  0.. 3 [ 4 B]: 0x4F4D4738u ("OMG8") */
    uint16_t version;            /*  4.. 5 [ 2 B]: 0x0101u (v1.1) */
    uint8_t  gate_state;         /*  6     [ 1 B]: 0x3C / 0xA5 / 0x5A / 0x00 */
    uint8_t  bru_mirror_flags;   /*  7     [ 1 B]: [1:0]=top_state, [2]=mirror_ok, [7:3]=0 */
    uint64_t seq_cycle;          /*  8..15 [ 8 B]: strictly monotonic clock cycle / seq */
    uint32_t s_q24;              /* 16..19 [ 4 B]: input s >= 0 in Q8.24 */
    uint32_t ln_out_q24;         /* 20..23 [ 4 B]: lower bound L(s) <= ln(1+s) in Q8.24 */
    uint32_t threshold_q24;      /* 24..27 [ 4 B]: required lower threshold in Q8.24 */
    uint16_t err_flags;          /* 28..29 [ 2 B]: OMEGA_OMG8_ERR_* bitmask */
    uint16_t rtl_cycles;         /* 30..31 [ 2 B]: measured silicon cycle count (1..80) */
    uint64_t witness_nonce;      /* 32..39 [ 8 B]: strictly increasing per channel */
    uint16_t channel_id;         /* 40..41 [ 2 B]: channel index 0..1023 */
    uint8_t  l01_witness_tag[6]; /* 42..47 [ 6 B]: 48-bit Level 01 witness binding */
    uint8_t  prev_wal_trunc[12]; /* 48..59 [12 B]: 96-bit SHA-256 WAL chain anchor */
    uint32_t crc32;              /* 60..63 [ 4 B]: IEEE 802.3 CRC-32 over byte 0..59 */
} omega_omg8_frame_t;

_Static_assert(sizeof(omega_omg8_frame_t) == 64,
               "KILL: omega_omg8_frame_t must be exactly 64 bytes");
_Static_assert(offsetof(omega_omg8_frame_t, seq_cycle) == 8,
               "KILL: seq_cycle must sit at offset 8");
_Static_assert(offsetof(omega_omg8_frame_t, witness_nonce) == 32,
               "KILL: witness_nonce must sit at offset 32");
_Static_assert(offsetof(omega_omg8_frame_t, channel_id) == 40,
               "KILL: channel_id must sit at offset 40");
_Static_assert(offsetof(omega_omg8_frame_t, prev_wal_trunc) == 48,
               "KILL: prev_wal_trunc must sit at offset 48");
_Static_assert(offsetof(omega_omg8_frame_t, crc32) == 60,
               "KILL: crc32 must sit at offset 60");

typedef union {
    omega_omg8_frame_t req;
    omega_omg8_frame_t rep;
} omega_omg8_io_t;

typedef struct {
    uint16_t channel_id;    /* 0..1023, or 0xFFFFu to clear global + all channels */
    uint16_t reserved;
    char     l01_token[32]; /* Must match OMEGA_L01_KEY_TOKEN */
    uint8_t  status_out;    /* 1 = reset accepted -> HOLD (0x3C), 0 = rejected */
    uint8_t  pad[3];
} omega_omg8_l01_reset_t;

typedef struct {
    uint32_t trap_count;
    uint32_t trap_overflow_kills;
    uint32_t oob_channel_kills;
    uint32_t pulse_sent_count;
    uint8_t  global_kill_latched;
    uint8_t  last_trap_state;
    uint16_t last_trap_channel;
} omega_omg8_status_t;

#ifdef __QNX__
#include <devctl.h>
#define OMEGA_DCMD_OMG8_EVAL      __DIOTF(_DCMD_MISC, 14, omega_omg8_io_t)
#define OMEGA_DCMD_OMG8_L01_RESET __DIOTF(_DCMD_MISC, 15, omega_omg8_l01_reset_t)
#define OMEGA_DCMD_OMG8_STATUS    __DIOF(_DCMD_MISC,  16, omega_omg8_status_t)
#endif

/* Per-channel isolated context (mirrors 1024 SPRAM slots, 0 heap allocation) */
typedef struct {
    bool     kill_latched;
    bool     trap_latched;
    bool     nonce_consumed_ever;
    uint64_t last_nonce;
    uint64_t last_seq_cycle;
    uint32_t ledger_len;
    uint8_t  wal_head[32];
} omega_omg8_chan_ctx_t;

/* Full 1024-channel + 1024-slot isolated TRAP bank */
typedef struct {
    bool                  global_kill_latched;
    uint32_t              trap_count;
    uint32_t              trap_overflow_kills;
    uint32_t              oob_channel_kills;
    uint32_t              pulse_sent_count;
    uint16_t              last_trap_channel;
    omega_omg8_chan_ctx_t channels[OMEGA_OMG8_MAX_CHANNELS];
    omega_omg8_frame_t    trap_ring[OMEGA_OMG8_TRAP_RING_CAP];
} omega_omg8_bank_t;

/* IEEE 802.3 CRC-32 (reflected polynomial 0xEDB88320) over exact byte slice */
static inline uint32_t omega_omg8_crc32_ieee(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0u; i < len; ++i) {
        crc ^= (uint32_t)data[i];
        for (uint32_t b = 0u; b < 8u; ++b) {
            uint32_t mask = (uint32_t)(-(int32_t)(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static inline void omega_omg8_seal_crc(omega_omg8_frame_t *f) {
    f->crc32 = omega_omg8_crc32_ieee((const uint8_t *)f, 60u);
}

static inline bool omega_omg8_verify_crc(const omega_omg8_frame_t *f) {
    return f->crc32 == omega_omg8_crc32_ieee((const uint8_t *)f, 60u);
}

/* Bit-exact 58-bit integer square root matching ln1p_lower_gate_q24.sv */
static inline uint32_t omega_omg8_isqrt_u58(uint64_t n) {
    uint64_t root = 0ULL;
    uint64_t bit  = 1ULL << 48;
    while (bit != 0ULL) {
        if (n >= (root + bit)) {
            n -= (root + bit);
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    return (uint32_t)root;
}

/* Bit-exact Q8.24 lower bound L(s) <= ln(1 + s) + exact silicon cycle count */
static inline uint32_t omega_omg8_ln1p_lower_q24(uint32_t s_q24, uint16_t *out_cycles) {
    uint64_t one_plus_r = (uint64_t)OMEGA_Q24_ONE + (uint64_t)s_q24;
    uint32_t k_oct  = 0u;
    uint32_t m_sqrt = 0u;

    while (one_plus_r >= 0x002000000ULL) {
        one_plus_r >>= 1;
        k_oct++;
    }

    while (((uint32_t)one_plus_r - OMEGA_Q24_ONE) > OMEGA_Q24_QUARTER) {
        uint64_t scaled = one_plus_r << 24;
        one_plus_r = (uint64_t)omega_omg8_isqrt_u58(scaled);
        m_sqrt++;
    }

    uint32_t r_val  = (uint32_t)one_plus_r - OMEGA_Q24_ONE;
    uint32_t r2_q24 = (uint32_t)(((uint64_t)r_val  * (uint64_t)r_val) >> 24);
    uint32_t r3_q24 = (uint32_t)(((uint64_t)r2_q24 * (uint64_t)r_val) >> 24);
    uint32_t r4_q24 = (uint32_t)(((uint64_t)r3_q24 * (uint64_t)r_val) >> 24);

    uint32_t r3_div3 = (uint32_t)(((uint64_t)r3_q24 * OMEGA_Q24_INV3_Q32) >> 32);
    uint32_t t_pos   = r_val + r3_div3;
    uint32_t t_neg   = (((r2_q24 << 1) + r4_q24) >> 2) + 1u;
    uint32_t taylor  = (t_pos > t_neg) ? (t_pos - t_neg) : 0u;

    if (out_cycles != NULL) {
        *out_cycles = (uint16_t)(8u + k_oct + (27u * m_sqrt));
    }
    return (k_oct * OMEGA_Q24_LN2_LOWER) + (taylor << m_sqrt);
}

static inline void omega_omg8_bank_init(omega_omg8_bank_t *bank) {
    memset(bank, 0, sizeof(*bank));
}

static inline void omega_omg8_chan_wal_advance(
    omega_omg8_chan_ctx_t    *ch,
    const omega_omg8_frame_t *frame_no_crc
) {
    sha256_ctx_t sctx;
    sha256_init(&sctx);
    sha256_update(&sctx, ch->wal_head, 32u);
    sha256_update(&sctx, (const uint8_t *)frame_no_crc, 60u);
    sha256_final(&sctx, ch->wal_head);
    ch->ledger_len++;
}

static inline bool omega_omg8_l01_reset(
    omega_omg8_bank_t *bank,
    uint16_t           channel_id,
    const char        *l01_token
) {
    if (l01_token == NULL || strncmp(l01_token, OMEGA_L01_KEY_TOKEN, 32u) != 0) {
        return false;
    }
    if (channel_id == 0xFFFFu) {
        bank->global_kill_latched = false;
        bank->trap_count = 0u;
        for (uint32_t i = 0u; i < OMEGA_OMG8_MAX_CHANNELS; ++i) {
            bank->channels[i].kill_latched = false;
            bank->channels[i].trap_latched = false;
        }
        return true;
    }
    if (channel_id >= OMEGA_OMG8_MAX_CHANNELS) {
        return false;
    }
    omega_omg8_chan_ctx_t *ch = &bank->channels[channel_id];
    ch->kill_latched = false;
    ch->trap_latched = false;

    omega_omg8_frame_t rst_rec;
    memset(&rst_rec, 0, sizeof(rst_rec));
    rst_rec.magic      = OMEGA_OMG8_MAGIC;
    rst_rec.version    = OMEGA_OMG8_VERSION;
    rst_rec.gate_state = OMEGA_OMG8_STATE_HOLD;
    rst_rec.channel_id = channel_id;
    memcpy(rst_rec.prev_wal_trunc, ch->wal_head, 12u);
    omega_omg8_chan_wal_advance(ch, &rst_rec);
    return true;
}

/* Core deterministic evaluation over 1024 channels + isolated 1024-slot TRAP ring */
static inline void omega_omg8_eval_frame(
    omega_omg8_bank_t        *bank,
    const omega_omg8_frame_t *in,
    omega_omg8_frame_t       *out,
    bool                     *out_fired_trap
) {
    if (out_fired_trap != NULL) {
        *out_fired_trap = false;
    }

    memcpy(out, in, sizeof(*out));
    out->magic      = OMEGA_OMG8_MAGIC;
    out->version    = OMEGA_OMG8_VERSION;
    out->ln_out_q24 = 0u;
    out->rtl_cycles = 1u;
    out->err_flags  = OMEGA_OMG8_ERR_NONE;

    /* 0. Global sticky KILL latch (e.g. from TRAP ring overflow or OOB channel attack) */
    if (bank->global_kill_latched) {
        out->gate_state = OMEGA_OMG8_STATE_KILL;
        out->err_flags  = OMEGA_OMG8_ERR_PARITY;
        omega_omg8_seal_crc(out);
        return;
    }

    /* 1. Channel bounds check (0..1023) before indexing SPRAM bank */
    if (in->channel_id >= OMEGA_OMG8_MAX_CHANNELS) {
        bank->global_kill_latched = true;
        bank->oob_channel_kills++;
        out->gate_state = OMEGA_OMG8_STATE_KILL;
        out->err_flags  = OMEGA_OMG8_ERR_PARITY;
        omega_omg8_seal_crc(out);
        return;
    }

    omega_omg8_chan_ctx_t *ch = &bank->channels[in->channel_id];
    memcpy(out->prev_wal_trunc, ch->wal_head, 12u);

    /* 2. Frame integrity: magic, version, IEEE CRC-32, and reserved flag bits */
    if (in->magic != OMEGA_OMG8_MAGIC ||
        in->version != OMEGA_OMG8_VERSION ||
        !omega_omg8_verify_crc(in) ||
        (in->bru_mirror_flags & OMEGA_OMG8_BRU_RESERVED_MASK) != 0u) {
        ch->kill_latched = true;
        out->gate_state  = OMEGA_OMG8_STATE_KILL;
        out->err_flags   = OMEGA_OMG8_ERR_PARITY;
        omega_omg8_chan_wal_advance(ch, out);
        memcpy(out->prev_wal_trunc, ch->wal_head, 12u);
        omega_omg8_seal_crc(out);
        return;
    }

    /* 3. Per-channel sticky KILL or no-return TRAP isolation check */
    if (ch->kill_latched) {
        out->gate_state = OMEGA_OMG8_STATE_KILL;
        out->err_flags  = OMEGA_OMG8_ERR_NONE;
        omega_omg8_chan_wal_advance(ch, out);
        memcpy(out->prev_wal_trunc, ch->wal_head, 12u);
        omega_omg8_seal_crc(out);
        return;
    }
    if (ch->trap_latched) {
        /* No return valve from TRAP to HOLD or OPEN without explicit L01 reset */
        out->gate_state = OMEGA_OMG8_STATE_TRAP;
        out->err_flags  = OMEGA_OMG8_ERR_MIRROR_TRAP;
        omega_omg8_chan_wal_advance(ch, out);
        memcpy(out->prev_wal_trunc, ch->wal_head, 12u);
        omega_omg8_seal_crc(out);
        return;
    }

    /* 4. Strictly increasing monotonic seq_cycle and witness_nonce per channel */
    bool seq_ok   = (!ch->nonce_consumed_ever) || (in->seq_cycle > ch->last_seq_cycle);
    bool nonce_ok = (in->witness_nonce != 0ULL) &&
                    ((!ch->nonce_consumed_ever) || (in->witness_nonce > ch->last_nonce));
    if (!seq_ok || !nonce_ok) {
        ch->kill_latched = true;
        out->gate_state  = OMEGA_OMG8_STATE_KILL;
        out->err_flags   = OMEGA_OMG8_ERR_NO_WITNESS;
        omega_omg8_chan_wal_advance(ch, out);
        memcpy(out->prev_wal_trunc, ch->wal_head, 12u);
        omega_omg8_seal_crc(out);
        return;
    }

    uint8_t bru_state = (uint8_t)(in->bru_mirror_flags & OMEGA_OMG8_BRU_STATE_MASK);
    bool    mirror_ok = ((in->bru_mirror_flags & OMEGA_OMG8_MIRROR_OK_BIT) != 0u);

    /* Outer operativbru_top KILL (saturation / ToF violation) -> immediate channel KILL */
    if (bru_state == OMEGA_OMG8_BRU_KILL || bru_state == 0x03u) {
        ch->kill_latched = true;
        out->gate_state  = OMEGA_OMG8_STATE_KILL;
        out->err_flags   = OMEGA_OMG8_ERR_PARITY;
        omega_omg8_chan_wal_advance(ch, out);
        memcpy(out->prev_wal_trunc, ch->wal_head, 12u);
        omega_omg8_seal_crc(out);
        return;
    }

    /* 5. Evaluate Q8.24 ln(1+s) lower bound and cycle watchdog */
    uint16_t cyc = 0u;
    uint32_t ln_val = omega_omg8_ln1p_lower_q24(in->s_q24, &cyc);
    out->ln_out_q24 = ln_val;
    out->rtl_cycles = cyc;

    if (cyc > OMEGA_OMG8_MAX_RTL_CYCLES) {
        ch->kill_latched = true;
        out->gate_state  = OMEGA_OMG8_STATE_KILL;
        out->err_flags   = OMEGA_OMG8_ERR_TIMEOUT;
        omega_omg8_chan_wal_advance(ch, out);
        memcpy(out->prev_wal_trunc, ch->wal_head, 12u);
        omega_omg8_seal_crc(out);
        return;
    }

    if (ln_val < in->threshold_q24) {
        ch->kill_latched = true;
        out->gate_state  = OMEGA_OMG8_STATE_KILL;
        out->err_flags   = OMEGA_OMG8_ERR_MARGIN_UNDER;
        omega_omg8_chan_wal_advance(ch, out);
        memcpy(out->prev_wal_trunc, ch->wal_head, 12u);
        omega_omg8_seal_crc(out);
        return;
    }

    /* 6. Projection hit (ln_val >= threshold_q24), but mirror_ok == 0 or bru_top_state == HOLD:
     *    Shunt into isolated TRAP chamber (0x5A) with zero return valve; if TRAP ring is
     *    full (1024/1024), fail closed into sticky global GATE_STATE_KILL (0x00). */
    if (!mirror_ok || bru_state == OMEGA_OMG8_BRU_HOLD) {
        if (bank->trap_count >= OMEGA_OMG8_TRAP_RING_CAP) {
            bank->global_kill_latched = true;
            bank->trap_overflow_kills++;
            ch->kill_latched = true;
            out->gate_state  = OMEGA_OMG8_STATE_KILL;
            out->err_flags   = OMEGA_OMG8_ERR_MIRROR_TRAP;
            omega_omg8_chan_wal_advance(ch, out);
            memcpy(out->prev_wal_trunc, ch->wal_head, 12u);
            omega_omg8_seal_crc(out);
            return;
        }

        ch->trap_latched       = true;
        ch->last_nonce         = in->witness_nonce;
        ch->last_seq_cycle     = in->seq_cycle;
        ch->nonce_consumed_ever= true;

        out->gate_state = OMEGA_OMG8_STATE_TRAP;
        out->err_flags  = OMEGA_OMG8_ERR_MIRROR_TRAP;
        omega_omg8_chan_wal_advance(ch, out);
        memcpy(out->prev_wal_trunc, ch->wal_head, 12u);
        omega_omg8_seal_crc(out);

        bank->trap_ring[bank->trap_count] = *out;
        bank->trap_count++;
        bank->last_trap_channel = in->channel_id;
        if (out_fired_trap != NULL) {
            *out_fired_trap = true;
        }
        return;
    }

    /* 7. All outer optical, phase-mirror, nonce, and ln(1+s) invariants satisfied -> OPEN (0xA5) */
    ch->last_nonce          = in->witness_nonce;
    ch->last_seq_cycle      = in->seq_cycle;
    ch->nonce_consumed_ever = true;
    out->gate_state         = OMEGA_OMG8_STATE_OPEN;
    out->err_flags          = OMEGA_OMG8_ERR_NONE;

    omega_omg8_chan_wal_advance(ch, out);
    memcpy(out->prev_wal_trunc, ch->wal_head, 12u);
    omega_omg8_seal_crc(out);
}

#endif /* OMEGA_OMG8_SLUICE_H */
