#ifndef OMEGA_CASCADE_H
#define OMEGA_CASCADE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * OmegaGate-QNX 128B / 64B Cascade Bus Contract (Zero-Float C11)
 *
 * Connects:
 *   [D0: /dev/d0_trap (prio 20)]
 *     -> [D1: /dev/d1_guestroom (prio 25) + Dual-Rate HashPrune Sluice]
 *     -> [D2/D3: /dev/d2_gate (prio 30) + Watchdog + SHA-256 WAL]
 *     -> [Future Phase B: FPGA SPI 128B/64B wrapper -> sequential_stop_cascade_top.sv]
 * ============================================================================ */

/* QNX 8.0 SCHED_FIFO priorities (within standard 1..63 range) */
#define OMEGA_PRIO_D2_GATE        30
#define OMEGA_PRIO_D1_GUESTROOM   25
#define OMEGA_PRIO_D0_TRAP        20
#define OMEGA_PRIO_TRAP_MIRROR    15

/* QNX 8.0 resource manager paths */
#define OMEGA_DEV_D0_TRAP         "/dev/d0_trap"
#define OMEGA_DEV_D1_GUESTROOM    "/dev/d1_guestroom"
#define OMEGA_DEV_D2_GATE         "/dev/d2_gate"
#define OMEGA_CASCADE_MIRROR_NAME "omega_cascade_mirror"

/* Watchdog timing (ms) */
#define OMEGA_WDG_TICK_MS         100u
#define OMEGA_WDG_HB_INTERVAL_MS  50u
#define OMEGA_WDG_TIMEOUT_MS      250u

/* Peer IDs registered in d2_gate extended OCB */
typedef enum {
    OMEGA_PEER_NONE         = 0,
    OMEGA_PEER_D0_TRAP      = 1,
    OMEGA_PEER_D1_GUESTROOM = 2,
    OMEGA_PEER_TRAP_MIRROR  = 3
} omega_peer_id_t;

/* Request control flags (16-bit bitmask in omega_cascade_req_t.flags) */
#define OMEGA_FLAG_INTENT_VALID        (1u << 0)
#define OMEGA_FLAG_NOMOS_VIOLATION     (1u << 1)
#define OMEGA_FLAG_WARRANT_COMPLETE    (1u << 2)
#define OMEGA_FLAG_WITNESS_OK          (1u << 3)
#define OMEGA_FLAG_CPT_SYMMETRY_OK     (1u << 4)
#define OMEGA_FLAG_REVERSE_CLOSED      (1u << 5)
#define OMEGA_FLAG_D2_COMMITTED        (1u << 6)
#define OMEGA_FLAG_CLAIM_REVERSIBLE    (1u << 7)
#define OMEGA_FLAG_UWB_LINK_ACTIVE     (1u << 8)
#define OMEGA_FLAG_KPOD_SEALED         (1u << 9)
#define OMEGA_FLAG_MB_CALIBRATED       (1u << 10)
#define OMEGA_FLAG_ESCROW_50_50        (1u << 11)
#define OMEGA_FLAG_CRISIS_A5_ACTIVE    (1u << 12)
#define OMEGA_FLAG_EXT_DEADLINE        (1u << 13)
#define OMEGA_FLAG_L01_AVG_INIT        (1u << 14)
#define OMEGA_FLAG_INVOLUTION_OK       (1u << 15)

/* Reply output flags (8-bit bitmask in omega_cascade_rep_t.flags_out) */
#define OMEGA_OUT_RAIL_5V_EN           (1u << 0)
#define OMEGA_OUT_CROWBAR_GND          (1u << 1)
#define OMEGA_OUT_SNUBBER_DUMP         (1u << 2)
#define OMEGA_OUT_FSYNC_READY          (1u << 3)
#define OMEGA_OUT_TRAP_STROBE          (1u << 4)
#define OMEGA_OUT_KILL_LATCHED         (1u << 5)
#define OMEGA_OUT_WATCHDOG_LOCKED      (1u << 6)

/* Cascade verdicts (anything != OPEN maps strictly to 0 mV HOLD/KILL on RTL) */
typedef enum {
    OMEGA_CVERD_HOLD            = 0,
    OMEGA_CVERD_OPEN            = 1,
    OMEGA_CVERD_TRAP            = 2,
    OMEGA_CVERD_KILL            = 3,
    OMEGA_CVERD_FSYNC_WAIT      = 4,
    OMEGA_CVERD_ESCALATED_EXT   = 5,
    OMEGA_CVERD_CONTINUOUS_PASS = 6
} omega_cascade_verdict_t;

/* Cascade reason codes */
typedef enum {
    OMEGA_CRSN_OK                  = 0,
    OMEGA_CRSN_FSYNC_WAITING       = 1,
    OMEGA_CRSN_CONTINUOUS_PASS     = 2,
    OMEGA_CRSN_HOLD_DRIFT          = 3,
    OMEGA_CRSN_HOLD_BARRIER        = 4,
    OMEGA_CRSN_HOLD_NO_WITNESS     = 5,
    OMEGA_CRSN_HOLD_AIRLOCK        = 6,
    OMEGA_CRSN_ESCALATED_STALLED   = 7,
    OMEGA_CRSN_TRAP_MIRROR         = 8,
    OMEGA_CRSN_KILL_INVOLUTION     = 9,
    OMEGA_CRSN_KILL_ZENO_DTAU      = 10,
    OMEGA_CRSN_KILL_POINCARE       = 11,
    OMEGA_CRSN_KILL_HOSTILE        = 12,
    OMEGA_CRSN_KILL_LATCHED        = 13,
    OMEGA_CRSN_WATCHDOG_PEER_DEAD  = 14,
    OMEGA_CRSN_WATCHDOG_TIMEOUT    = 15,
    OMEGA_CRSN_WATCHDOG_LOCKED     = 16,
    OMEGA_CRSN_L01_RESET_OK        = 17,
    OMEGA_CRSN_L01_RESET_INVALID   = 18
} omega_cascade_reason_t;

/* 128 bytes exact (2 cache lines) — Request over MsgSend and SPI */
typedef struct __attribute__((packed)) {
    uint32_t seq_id;
    uint64_t timestamp_ns;
    uint8_t  stage;                 /* 0=RAW .. 4=COMMITTED */
    uint8_t  prev_stage;
    uint16_t flags;                 /* OMEGA_FLAG_* */
    /* D0 + HashPrune + Trap (32 B) */
    int32_t  pos_x_q16;
    int32_t  pos_y_q16;
    int32_t  pos_z_q16;
    uint32_t target_id;
    int32_t  torque_mnm;
    int32_t  jerk_mrad_s3;
    int32_t  anomaly_score;
    uint16_t somatic_weight_q016;
    uint16_t airlock_elapsed_ms;
    /* CPCA-B / Pi_K + Drift (16 B) */
    int32_t  q_nm;
    int32_t  v_mm_s;
    int32_t  u_raw;
    uint32_t pi_drift_ppm;          /* Exact decimal ppm: 1/100 == 10000 */
    /* D1 Involution + ToF (16 B) */
    int32_t  state_s;
    int32_t  f_f_state_s;
    uint32_t elapsed_cycles;
    uint16_t info_loss_delta;
    uint16_t uwb_tof_ns;
    /* D2/D3 + Digest (24 B) */
    int32_t  proj_state_s;
    int32_t  proj_citizen_c;
    uint32_t earned_merit_delta;
    uint32_t obstacle_dist_q16;     /* Physical clearance distance to nearest obstacle (Q16.16) */
    uint64_t intent_digest;
    /* L01 physical key + frame CRC (24 B) */
    uint8_t  is_l01_reset;
    uint8_t  pad[3];
    uint8_t  l01_key_hash16[16];
    uint32_t crc32;
} omega_cascade_req_t;

/* 64 bytes exact — Reply over MsgReply and SPI return */
typedef struct __attribute__((packed)) {
    uint32_t seq_id;
    uint8_t  verdict;               /* omega_cascade_verdict_t */
    uint8_t  stop_stage;            /* 0=OPEN, 1=HOLD, 2=KILL */
    uint8_t  admissible_count;      /* |A(x)| in [0..41] */
    uint8_t  flags_out;             /* OMEGA_OUT_* */
    uint16_t actuator_mv;           /* 0 or 5000 */
    uint16_t omega_y_mv;            /* Always 5000 (orthogonal rail) */
    int32_t  u_safe_out;
    uint32_t reason_code;           /* omega_cascade_reason_t */
    uint32_t ledger_len;
    uint64_t witness_chain_wn;
    uint8_t  head_hash[32];         /* Raw 32-byte SHA-256 */
} omega_cascade_rep_t;

_Static_assert(sizeof(omega_cascade_req_t) == 128, "omega_cascade_req_t must be exactly 128 bytes");
_Static_assert(sizeof(omega_cascade_rep_t) == 64,  "omega_cascade_rep_t must be exactly 64 bytes");

/* Peer registration / heartbeat payload for /dev/d2_gate */
typedef struct {
    uint32_t peer_id;
    int32_t  peer_pid;
} omega_peer_hello_t;

/* Union used by QNX devctl() for 128B in / 64B out */
typedef union {
    omega_cascade_req_t req;
    omega_cascade_rep_t rep;
} omega_cascade_io_t;

#ifdef __QNX__
#include <devctl.h>
#define OMEGA_DCMD_CASCADE_EVAL   __DIOTF(_DCMD_MISC, 10, omega_cascade_io_t)
#define OMEGA_DCMD_PEER_REGISTER  __DIOT(_DCMD_MISC,  11, omega_peer_hello_t)
#define OMEGA_DCMD_PEER_HEARTBEAT __DIOT(_DCMD_MISC,  12, omega_peer_hello_t)
#endif

/* ============================================================================
 * Dual-Rate HashPrune Sluice (Zero-Float C11 Port of dual_rate_hashprune_sluice.py)
 *   - Coordinates & tau/dtau in Q16.16 (1.0 == 65536)
 *   - Squared distances in int64_t Q32.32 (1.0 == 1LL << 32, 0 rounding error)
 *   - Drift pi_drift & epsilon_drift in exact decimal ppm (1/100 == 10000)
 * ============================================================================ */

#define HP_Q16_ONE             ((int32_t)65536)
#define HP_Q32_ONE             ((int64_t)1LL << 32)
#define HP_MAX_DIM             3u
#define HP_MAX_PLANES          8u
#define HP_MAX_BUCKETS         32u
#define HP_MAX_LEDGER_ENTRIES  128u

typedef enum {
    HP_OWNER_P_INT            = 0,
    HP_OWNER_P_EXT            = 1,
    HP_OWNER_HARDWARE_CROWBAR = 2
} hp_owner_port_t;

typedef enum {
    HP_RATE_LOW_EVENT         = 0,
    HP_RATE_CLOCK_ESCALATION  = 1,
    HP_RATE_KILL_LATCH        = 2
} hp_rate_domain_t;

typedef enum {
    HP_RES_OPEN               = 0,
    HP_RES_CONTINUOUS_PASS    = 1,
    HP_RES_HOLD               = 2,
    HP_RES_HOLD_ACTIVE        = 3,
    HP_RES_FSYNC_WAIT         = 4,
    HP_RES_ESCALATED_EXT      = 5,
    HP_RES_KILL               = 6,
    HP_RES_KILL_LATCHED       = 7
} hp_step_result_t;

typedef struct {
    bool     occupied;
    uint32_t bucket_mask;
    uint32_t target_id;
    int64_t  dist_sq_q32;
} hp_bucket_slot_t;

typedef struct {
    uint32_t         node_id;
    uint32_t         dim;
    int32_t          origin_q16[HP_MAX_DIM];
    uint32_t         num_planes;
    int32_t          planes_q16[HP_MAX_PLANES][HP_MAX_DIM];
    uint32_t         l_max;
    uint32_t         count;
    hp_bucket_slot_t slots[HP_MAX_BUCKETS];
} hp_reservoir_t;

typedef struct {
    uint32_t         seq;
    uint8_t          rate_domain;
    uint8_t          owner_port;
    uint8_t          verdict;
    uint8_t          reserved;
    int64_t          tau_q16;
    int32_t          dtau_q16;
    char             delta_k[64];
    uint8_t          prev_hash[32];
    uint8_t          entry_hash[32];
} hp_witness_entry_t;

typedef struct {
    hp_reservoir_t     reservoir;
    int64_t            safe_dist_sq_min_q32;
    uint32_t           epsilon_drift_ppm;
    int64_t            tau_max_hold_q16;
    int32_t            dtau_q16;
    int32_t            dtau_min_q16;
    uint32_t           min_fsync_cycles;

    int64_t            tau_now_q16;
    uint16_t           voltage_mv;
    bool               latched_kill;
    hp_owner_port_t    owner_port;
    bool               has_hold_since;
    int64_t            hold_since_q16;
    char               hold_reason[64];
    uint32_t           high_rate_passes;
    bool               fsync_pending;
    uint32_t           fsync_cycles_waited;
    uint32_t           ledger_len;
    uint8_t            head_hash[32];
    hp_witness_entry_t ledger[HP_MAX_LEDGER_ENTRIES];
} hp_sluice_t;

/* Reservoir API */
void hp_reservoir_init(hp_reservoir_t *r, uint32_t node_id, uint32_t dim,
                       const int32_t origin_q16[HP_MAX_DIM],
                       uint32_t num_planes,
                       const int32_t planes_q16[][HP_MAX_DIM],
                       uint32_t l_max);
bool hp_reservoir_admit(hp_reservoir_t *r, uint32_t target_id,
                        const int32_t target_pos_q16[HP_MAX_DIM],
                        uint32_t *out_winner_id, int64_t *out_dist_sq_q32);
bool hp_reservoir_min_dist_sq(const hp_reservoir_t *r, int64_t *out_min_q32);
bool hp_reservoir_equal(const hp_reservoir_t *a, const hp_reservoir_t *b);
bool hp_reservoir_get_bucket(const hp_reservoir_t *r, uint32_t mask,
                             uint32_t *out_target_id, int64_t *out_dist_sq_q32);

/* Dual-Rate Governance Sluice API */
void hp_sluice_init(hp_sluice_t *s,
                    const hp_reservoir_t *reservoir,
                    int64_t safe_dist_sq_min_q32,
                    uint32_t epsilon_drift_ppm,
                    int64_t tau_max_hold_q16,
                    int32_t dtau_initial_q16,
                    int32_t dtau_min_q16,
                    uint32_t min_fsync_cycles);
hp_step_result_t hp_sluice_step(hp_sluice_t *s,
                                uint32_t target_id,
                                const int32_t target_pos_q16[HP_MAX_DIM],
                                uint32_t pi_drift_ppm,
                                bool involution_ok,
                                bool human_l01_witness);
bool hp_sluice_verify_ledger(const hp_sluice_t *s);
const char *hp_step_result_name(hp_step_result_t r);
const char *omega_peer_name(uint32_t peer_id);
const char *omega_cascade_verdict_name(uint8_t v);
const char *omega_cascade_reason_name(uint32_t r);

/* Canonical 16-byte L01 key digest & IEEE 802.3 CRC-32 helpers */
void omega_compute_l01_key_hash16(const char *token, uint8_t out16[16]);
uint32_t omega_crc32_ieee(const void *data, size_t len);
void omega_cascade_seal_req(omega_cascade_req_t *req);
bool omega_cascade_verify_req(const omega_cascade_req_t *req);

#endif /* OMEGA_CASCADE_H */
