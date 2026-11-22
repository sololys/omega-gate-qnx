/*
 * Complete zero-float C11 unit verification suite for OmegaGate-QNX.
 * Compiles with: gcc -std=c11 -Wall -Wextra -Werror
 */

#include "omega_gate.h"
#include "sha256_zero_dep.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, bool cond) {
    if (cond) {
        printf("PASS | %s\n", name);
        g_pass++;
    } else {
        printf("FAIL | %s\n", name);
        g_fail++;
    }
}

int main(void) {
    /* T0: FIPS 180-4 SHA-256 known-answer test ("abc") */
    char hex[65];
    sha256_hex((const uint8_t *)"abc", 3u, hex);
    check("T0_SHA256_FIPS_ABC",
          strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);

    omega_gate_t g;
    omega_reply_t r;
    omega_gate_init(&g);

    /* T1: Valid COMMITTED -> OPEN (5000 mV) + 2-cycle deadtime + 1-cycle 5V pulse + return to clamp */
    omega_cmd_t c1 = { 1, 1000, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_VIABILITY, 40000, 10000, 0, 1, 15, 0, "" };
    omega_gate_eval(&g, &c1, &r);
    check("T1A_OPEN_DEADTIME_CYCLE1",
          r.decision == OMEGA_DEC_OPEN && r.voltage_mv == 5000u && r.rail_5v_en == 0u && r.crowbar_gnd == 0u);

    uint8_t qh = 0, ql = 0;
    omega_gate_tick_deadtime(&g, &qh, &ql);
    check("T1B_DEADTIME_CYCLE2", qh == 0u && ql == 0u);

    omega_gate_tick_deadtime(&g, &qh, &ql);
    check("T1C_SINGLE_5V_PULSE", qh == 1u && ql == 0u);

    omega_gate_tick_deadtime(&g, &qh, &ql);
    check("T1D_RETURN_TO_CLAMP", qh == 0u && ql == 1u);

    /* T2: Intermediate stage RAW -> ESTIMATE -> HOLD (0 mV) */
    omega_cmd_t c2 = { 2, 1050, OMEGA_STAGE_ESTIMATE, OMEGA_STAGE_RAW, 10000, 1000, 0, 1, 20, 0, "" };
    omega_gate_eval(&g, &c2, &r);
    check("T2_INTERMEDIATE_HOLD_0V",
          r.decision == OMEGA_DEC_HOLD && r.voltage_mv == 0u && r.reason == OMEGA_RSN_INTERMEDIATE);

    /* T3: Unwitnessed COMMITTED -> HOLD (0 mV) */
    omega_cmd_t c3 = { 3, 1100, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_VIABILITY, 40000, 10000, 0, 0, 15, 0, "" };
    omega_gate_eval(&g, &c3, &r);
    check("T3_UNWITNESSED_HOLD_0V",
          r.decision == OMEGA_DEC_HOLD && r.voltage_mv == 0u && r.reason == OMEGA_RSN_EARLY_NO_WIT);

    /* T4: Suspicious anomaly -> TRAP + mirror strobe (0 mV) */
    omega_cmd_t c4 = { 4, 1150, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_VIABILITY, 40000, 10000, 42, 1, 15, 0, "" };
    omega_gate_eval(&g, &c4, &r);
    check("T4_TRAP_MIRROR_STROBE",
          r.decision == OMEGA_DEC_TRAP && r.voltage_mv == 0u && r.trap_mirror_strobe == 1u && g.trap_count == 1u);

    /* T5: Forbidden shortcut RAW -> COMMITTED -> sticky KILL (0 mV) */
    omega_cmd_t c5 = { 5, 1200, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_RAW, 40000, 10000, 0, 1, 15, 0, "" };
    omega_gate_eval(&g, &c5, &r);
    check("T5_SHORTCUT_STICKY_KILL",
          r.decision == OMEGA_DEC_KILL && r.voltage_mv == 0u && r.kill_latched == 1u && r.reason == OMEGA_RSN_KILL_SHORTCUT);

    /* T6: Valid command after KILL -> remains latched KILL */
    omega_cmd_t c6 = { 6, 1250, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_VIABILITY, 10000, 1000, 0, 1, 20, 0, "" };
    omega_gate_eval(&g, &c6, &r);
    check("T6_KILL_PERSISTS",
          r.decision == OMEGA_DEC_KILL && r.kill_latched == 1u && r.reason == OMEGA_RSN_KILL_LATCHED);

    /* T7: Wrong L01 key rejected; valid L01 key resets to HOLD (append-only) */
    check("T7A_WRONG_L01_KEY_REJECTED", !omega_gate_l01_reset(&g, "WRONG_KEY") && g.kill_latched);
    check("T7B_VALID_L01_KEY_RESETS", omega_gate_l01_reset(&g, OMEGA_L01_KEY_TOKEN) && !g.kill_latched);

    /* T8: Lightcone expiry (> 133 ns) -> KILL */
    omega_cmd_t c8a = { 7, 2000, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_VIABILITY, 10000, 1000, 0, 1, 15, 0, "" };
    omega_cmd_t c8b = { 8, 2134, OMEGA_STAGE_COMMITTED, OMEGA_STAGE_VIABILITY, 10000, 1000, 0, 1, 15, 0, "" };
    omega_gate_eval(&g, &c8a, &r);
    omega_gate_eval(&g, &c8b, &r);
    check("T8_LIGHTCONE_EXPIRED_KILL",
          r.decision == OMEGA_DEC_KILL && r.reason == OMEGA_RSN_KILL_LIGHTCONE);

    /* T9: SHA-256 ledger integrity + tamper detection */
    check("T9A_LEDGER_INTACT", omega_ledger_verify(&g) && g.ledger_len == 10u);
    g.ledger[0].voltage_mv = 1234u;
    check("T9B_LEDGER_TAMPER_CAUGHT", !omega_ledger_verify(&g));

    printf("SUMMARY | omega_gate_qnx_c11 | PASS=%d FAIL=%d\n", g_pass, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
