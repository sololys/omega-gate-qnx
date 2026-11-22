#ifndef OMEGA_CAPSULE205B_H
#define OMEGA_CAPSULE205B_H

#include "omega_cascade.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * OmegaGate-QNX 205-Byte Witness Capsule <-> 128-Byte Cascade Ingress (0-Float)
 *
 * Strictly integer-only C11 (zero float/double types or arithmetic).
 * Wire layout is 100% little-endian matching:
 *   - WitnessPreCommit  (119 B: <QQ32sfBH32s32s)
 *   - WitnessPostCommit ( 86 B: <QQ32sBfB32s)
 *   - CapsuleFrame205B  (205 B contiguous)
 *   - Ingress envelope  (288 B = 205 B capsule + kinematics/L01 + IEEE CRC-32)
 * ============================================================================ */

/* Gate decision codes (byte 52) */
#define OMEGA_CAP_DEC_OPEN                0x01u
#define OMEGA_CAP_DEC_HOLD                0x02u
#define OMEGA_CAP_DEC_KILL                0x03u

/* Reason / cobordism / Belnap flags (byte 53..54) */
#define OMEGA_CAP_FLAG_D1D2_NONZERO       (1u << 0) /* must be 0 */
#define OMEGA_CAP_FLAG_MAAT_OK            (1u << 1) /* must be 1 */
#define OMEGA_CAP_FLAG_BELNAP_OMEGA       (1u << 5) /* must be 0 */

/* HPIS latch & final status (byte 167, byte 172) */
#define OMEGA_CAP_HPIS_ISOLATED           0x00u
#define OMEGA_CAP_HPIS_ENGAGED            0x01u
#define OMEGA_CAP_FINAL_REALIZED          0x01u
#define OMEGA_CAP_FINAL_TERMINATED        0x0Fu

/* Max causal decay budget (30.0 s in ns) */
#define OMEGA_CAP_MAX_DECAY_NS            30000000000ULL

typedef enum {
    OMEGA_CAP_OK                 = 0,
    OMEGA_CAP_ERR_NULL           = 1,
    OMEGA_CAP_ERR_INGRESS_CRC    = 2,
    OMEGA_CAP_ERR_SEQ_MISMATCH   = 3,
    OMEGA_CAP_ERR_REPLAY         = 4,
    OMEGA_CAP_ERR_HASH_INVOL     = 5,
    OMEGA_CAP_ERR_ZERO_ANCHOR    = 6,
    OMEGA_CAP_ERR_CHAIN_FORK     = 7,
    OMEGA_CAP_ERR_TIME_BUDGET    = 8,
    OMEGA_CAP_ERR_BELNAP_OMEGA   = 9,
    OMEGA_CAP_ERR_COBORDISM_MAAT = 10,
    OMEGA_CAP_ERR_HPIS_MISMATCH  = 11,
    OMEGA_CAP_ERR_THERMO_LANDAUER= 12,
    OMEGA_CAP_ERR_DRIFT_IEEE754  = 13
} omega_capsule_status_t;

typedef struct __attribute__((packed)) {
    uint64_t sequence_id;            /* [0..7]     8 B */
    uint64_t timestamp_ns;           /* [8..15]    8 B */
    uint8_t  candidate_hash[32];     /* [16..47]  32 B */
    uint32_t kernel_drift_f32_bits;  /* [48..51]   4 B (raw IEEE-754 bits, 0-float!) */
    uint8_t  gate_decision;          /* [52]       1 B */
    uint16_t reason_code;            /* [53..54]   2 B */
    uint8_t  prev_block_hash[32];    /* [55..86]  32 B */
    uint8_t  w_pre_hash[32];         /* [87..118] 32 B */
} omega_witness_pre_t;

typedef struct __attribute__((packed)) {
    uint64_t sequence_id;            /* [119..126] 8 B */
    uint64_t timestamp_ns;           /* [127..134] 8 B */
    uint8_t  w_pre_hash[32];         /* [135..166] 32 B */
    uint8_t  hpis_latch_status;      /* [167]      1 B */
    uint32_t thermo_exhaust_f32_bits;/* [168..171] 4 B (raw IEEE-754 bits, 0-float!) */
    uint8_t  final_status;           /* [172]      1 B */
    uint8_t  w_post_hash[32];        /* [173..204] 32 B */
} omega_witness_post_t;

typedef struct __attribute__((packed)) {
    omega_witness_pre_t  pre;        /* [0..118]  119 B */
    omega_witness_post_t post;       /* [119..204] 86 B */
} omega_capsule205b_t;

/* Lossless 288-byte ingress envelope: untouched 205 B capsule + kinematics + CRC-32 */
typedef struct __attribute__((packed)) {
    omega_capsule205b_t capsule;            /* [0..204]   205 B */
    uint8_t             is_l01_reset;       /* [205]        1 B */
    uint16_t            extra_flags;        /* [206..207]   2 B (UWB/KPOD/MB/Escrow/A5) */
    int32_t             pos_x_q16;          /* [208..211]   4 B */
    int32_t             pos_y_q16;          /* [212..215]   4 B */
    int32_t             pos_z_q16;          /* [216..219]   4 B */
    int32_t             q_nm;               /* [220..223]   4 B */
    int32_t             v_mm_s;             /* [224..227]   4 B */
    int32_t             u_raw;              /* [228..231]   4 B */
    int32_t             state_s;            /* [232..235]   4 B */
    int32_t             f_f_state_s;        /* [236..239]   4 B */
    int32_t             proj_state_s;       /* [240..243]   4 B */
    int32_t             proj_citizen_c;     /* [244..247]   4 B */
    uint32_t            target_id;          /* [248..251]   4 B */
    uint32_t            earned_merit_delta; /* [252..255]   4 B */
    uint16_t            uwb_tof_ns;         /* [256..257]   2 B */
    uint16_t            somatic_weight_q016;/* [258..259]   2 B */
    uint16_t            info_loss_delta;    /* [260..261]   2 B */
    uint16_t            obstacle_dist_q8;   /* [262..263]   2 B (physical clearance Q8.8) */
    uint8_t             l01_key_hash16[16]; /* [264..279]  16 B */
    int32_t             anomaly_score;      /* [280..283]   4 B */
    uint32_t            crc32;              /* [284..287]   4 B (IEEE 802.3 over 0..283) */
} omega_capsule_ingress_t;

_Static_assert(sizeof(omega_witness_pre_t)     == 119, "omega_witness_pre_t must be 119 bytes");
_Static_assert(sizeof(omega_witness_post_t)    == 86,  "omega_witness_post_t must be 86 bytes");
_Static_assert(sizeof(omega_capsule205b_t)     == 205, "omega_capsule205b_t must be 205 bytes");
_Static_assert(sizeof(omega_capsule_ingress_t) == 288, "omega_capsule_ingress_t must be 288 bytes");

typedef struct {
    uint64_t last_seq_id;
    uint8_t  last_w_post_hash[32];
    bool     has_committed;
} omega_capsule_ctx_t;

typedef union {
    omega_capsule_ingress_t ingress;
    omega_cascade_rep_t     rep;
} omega_capsule_io_t;

#ifdef __QNX__
#include <devctl.h>
#define OMEGA_DCMD_CAPSULE205_EVAL __DIOTF(_DCMD_MISC, 13, omega_capsule_io_t)
#endif

void omega_capsule_ctx_init(omega_capsule_ctx_t *ctx);
void omega_capsule_ingress_seal(omega_capsule_ingress_t *ing);
bool omega_capsule_ingress_verify_crc(const omega_capsule_ingress_t *ing);

/* Pure integer IEEE-754 binary32 guards (zero float instructions) */
bool omega_ieee754_f32_landauer_positive(uint32_t raw_bits);
bool omega_ieee754_f32_to_ppm_ceil(uint32_t raw_bits, uint32_t *out_ppm);

/* Stateful 205B witness verifier -> sealed 128B omega_cascade_req_t */
omega_capsule_status_t omega_capsule205b_ingest(
    omega_capsule_ctx_t           *ctx,
    const omega_capsule_ingress_t *ing,
    omega_cascade_req_t           *out_req
);

const char *omega_capsule_status_name(omega_capsule_status_t st);

#endif /* OMEGA_CAPSULE205B_H */
