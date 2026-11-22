#ifndef OMEGA_GATE_H
#define OMEGA_GATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Canonical hardware & timing limits (strict zero-float integer units) */
#define OMEGA_MAX_TORQUE_MNM     80000    /* 80.0 Nm */
#define OMEGA_MAX_JERK_MRAD_S3   25000    /* 25.0 rad/s^3 */
#define OMEGA_LIGHTCONE_MAX_NS   133u     /* ~133.4 ns */
#define OMEGA_MIN_AIRLOCK_MS     14u      /* 14 ms maturation airlock */
#define OMEGA_KILL_ANOMALY_TH    100      /* >= 100 or < 0 -> KILL */
#define OMEGA_DEADTIME_CYCLES    2u       /* 2 cycles = 10 ns @ 200 MHz */
#define OMEGA_MAX_LEDGER_ENTRIES 256u
#define OMEGA_L01_KEY_TOKEN      "RISOR_L01_PHYSICAL_KEY"

/* QNX 8.0 device & IPC channel names */
#define OMEGA_DEV_PATH           "/dev/omega_gate"
#define OMEGA_TRAP_MIRROR_NAME   "omega_trap_mirror"
#define OMEGA_PULSE_TRAP_CODE    (1)

typedef enum {
    OMEGA_STAGE_RAW       = 0,
    OMEGA_STAGE_ESTIMATE  = 1,
    OMEGA_STAGE_STRUCT    = 2,
    OMEGA_STAGE_VIABILITY = 3,
    OMEGA_STAGE_COMMITTED = 4
} omega_stage_t;

/* Subsumption order: KILL > TRAP > HOLD > OPEN */
typedef enum {
    OMEGA_DEC_HOLD = 0,  /* 0 mV DC */
    OMEGA_DEC_OPEN = 1,  /* 5000 mV DC (after deadtime) */
    OMEGA_DEC_TRAP = 2,  /* 0 mV DC (mirror chamber) */
    OMEGA_DEC_KILL = 3   /* 0 mV DC (latched crowbar) */
} omega_decision_t;

typedef enum {
    OMEGA_RSN_IDLE_HOLD       = 0,
    OMEGA_RSN_OPEN_PULSE      = 1,
    OMEGA_RSN_INTERMEDIATE    = 2,
    OMEGA_RSN_EARLY_NO_WIT    = 3,
    OMEGA_RSN_TRAP_MIRROR     = 4,
    OMEGA_RSN_KILL_SHORTCUT   = 5,
    OMEGA_RSN_KILL_REPLAY     = 6,
    OMEGA_RSN_KILL_LIGHTCONE  = 7,
    OMEGA_RSN_KILL_GUILLOTINE = 8,
    OMEGA_RSN_KILL_HOSTILE    = 9,
    OMEGA_RSN_KILL_LATCHED    = 10,
    OMEGA_RSN_L01_RESET       = 11,
    OMEGA_RSN_INVALID_KEY     = 12,
    OMEGA_RSN_KILL_POINCARE   = 13
} omega_reason_t;

typedef enum {
    OMEGA_RAIL_CLAMPED  = 0, /* Q_low=1, Q_high=0 */
    OMEGA_RAIL_DEADTIME = 1, /* Q_low=0, Q_high=0 */
    OMEGA_RAIL_PULSE_5V = 2  /* Q_low=0, Q_high=1 (1 cycle) */
} omega_rail_state_t;

typedef struct {
    uint32_t seq_id;
    uint32_t timestamp_ns;
    uint8_t  stage;
    uint8_t  prev_stage;
    int32_t  torque_mnm;
    int32_t  jerk_mrad_s3;
    int32_t  pos_x_q16;          /* Poincare ball B^3 coordinate x in Q16.16 (0x10000 = 1.0) */
    int32_t  pos_y_q16;          /* Poincare ball B^3 coordinate y in Q16.16 */
    int32_t  pos_z_q16;          /* Poincare ball B^3 coordinate z in Q16.16 */
    int32_t  anomaly_score;
    uint8_t  witness_ok;
    uint16_t airlock_elapsed_ms;
    uint8_t  is_l01_reset;
    char     l01_token[32];
} omega_cmd_t;

typedef struct {
    uint32_t         seq_id;
    omega_decision_t decision;
    omega_reason_t   reason;
    uint16_t         voltage_mv;
    uint8_t          rail_5v_en;
    uint8_t          crowbar_gnd;
    uint8_t          trap_mirror_strobe;
    uint8_t          kill_latched;
    uint32_t         ledger_len;
    char             head_hash[65];
} omega_reply_t;

typedef struct {
    uint32_t         index;
    uint32_t         seq_id;
    omega_decision_t decision;
    omega_reason_t   reason;
    uint16_t         voltage_mv;
    char             prev_hash[65];
    char             record_hash[65];
} omega_witness_t;

typedef struct {
    bool               kill_latched;
    bool               has_prev_ts;
    uint32_t           last_ts_ns;
    uint32_t           last_seq_id;
    omega_rail_state_t rail_state;
    uint8_t            deadtime_cnt;
    uint32_t           trap_count;
    uint32_t           ledger_len;
    char               head_hash[65];
    omega_witness_t    ledger[OMEGA_MAX_LEDGER_ENTRIES];
} omega_gate_t;

void omega_gate_init(omega_gate_t *g);
void omega_gate_eval(omega_gate_t *g, const omega_cmd_t *cmd, omega_reply_t *out);
void omega_gate_tick_deadtime(omega_gate_t *g, uint8_t *rail_5v_en, uint8_t *crowbar_gnd);
bool omega_gate_l01_reset(omega_gate_t *g, const char *token);
bool omega_ledger_verify(const omega_gate_t *g);
const char *omega_decision_name(omega_decision_t d);
const char *omega_reason_name(omega_reason_t r);

#endif /* OMEGA_GATE_H */
