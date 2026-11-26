/*
 * test_omg8_sluice.c — Host C11 & Live QNX 8.0 /dev/omg8_gate Verification Suite
 *
 * When invoked without arguments: runs deterministic in-memory unit verification
 * of all 5 "OMG8" v1.1 invariants (gcc host and QNX target).
 * When invoked with `--live-qnx /dev/omg8_gate`: executes the full 5-scenario
 * end-to-end IPC & CLOCK_MONOTONIC benchmark over live QNX Neutrino 8.0 devctl().
 */

#ifndef __QNX__
#define _POSIX_C_SOURCE 200809L
#endif

#include "omega_omg8_sluice.h"
#ifdef __QNX__
#include "qnx_rt_cage.h"
#include <fcntl.h>
#include <unistd.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t mono_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint32_t popcount8(uint8_t x) {
    uint32_t c = 0u;
    while (x != 0u) {
        c += (x & 1u);
        x >>= 1;
    }
    return c;
}

static void build_valid_req(
    omega_omg8_frame_t *req,
    uint16_t            ch,
    uint64_t            seq,
    uint64_t            nonce,
    uint32_t            s_q24,
    uint32_t            thr_q24,
    uint8_t             bru_flags
) {
    memset(req, 0, sizeof(*req));
    req->magic            = OMEGA_OMG8_MAGIC;
    req->version          = OMEGA_OMG8_VERSION;
    req->gate_state       = OMEGA_OMG8_STATE_HOLD;
    req->bru_mirror_flags = bru_flags;
    req->seq_cycle        = seq;
    req->s_q24            = s_q24;
    req->threshold_q24    = thr_q24;
    req->witness_nonce    = nonce;
    req->channel_id       = ch;
    omega_omg8_seal_crc(req);
}

static int run_in_memory_suite(void) {
    /* 0. Verify pairwise Hamming distance >= 4 across all 4 gate states */
    const uint8_t states[4] = {
        OMEGA_OMG8_STATE_HOLD,
        OMEGA_OMG8_STATE_OPEN,
        OMEGA_OMG8_STATE_TRAP,
        OMEGA_OMG8_STATE_KILL
    };
    for (int i = 0; i < 4; ++i) {
        for (int j = i + 1; j < 4; ++j) {
            uint32_t hd = popcount8((uint8_t)(states[i] ^ states[j]));
            assert(hd >= 4u);
        }
    }

    /* Verify Q8.24 seam monotonicity at 1/4, 9/16, 1.0, 3.0, 255.99999994 */
    uint16_t cyc = 0u;
    assert(omega_omg8_ln1p_lower_q24(0x00000000u, &cyc) == 0u);
    assert(omega_omg8_ln1p_lower_q24(0x003FFFFFu, &cyc) < omega_omg8_ln1p_lower_q24(0x00400000u, &cyc));
    assert(omega_omg8_ln1p_lower_q24(0x00400000u, &cyc) < omega_omg8_ln1p_lower_q24(0x00400001u, &cyc));
    assert(omega_omg8_ln1p_lower_q24(0x008FFFFFu, &cyc) < omega_omg8_ln1p_lower_q24(0x00900000u, &cyc));
    assert(omega_omg8_ln1p_lower_q24(0x00FFFFFFu, &cyc) < omega_omg8_ln1p_lower_q24(0x01000000u, &cyc));
    assert(omega_omg8_ln1p_lower_q24(0x03000000u, &cyc) == 0x0162E42Eu);

    static omega_omg8_bank_t bank;
    omega_omg8_bank_init(&bank);

    /* (1) 1 000 independent channels (ch 0..999) with isolated nonce and WAL state */
    uint64_t t0 = mono_now_ns();
    for (uint16_t ch = 0u; ch < 1000u; ++ch) {
        omega_omg8_frame_t req, rep;
        bool trap = false;
        build_valid_req(
            &req,
            ch,
            1ULL,
            1000ULL + (uint64_t)ch,
            0x03000000u, /* s = 3.0 -> L(3) = 2*ln(2)_lower = 0x0162E42E */
            0x01000000u, /* threshold = 1.0 */
            OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT
        );
        omega_omg8_eval_frame(&bank, &req, &rep, &trap);
        assert(!trap);
        assert(rep.gate_state == OMEGA_OMG8_STATE_OPEN);
        assert(rep.ln_out_q24 == 0x0162E42Eu);
        assert(omega_omg8_verify_crc(&rep));
        assert(bank.channels[ch].last_nonce == (1000ULL + (uint64_t)ch));
        assert(bank.channels[ch].ledger_len == 1u);
        if (ch > 0u) {
            assert(memcmp(bank.channels[ch].wal_head, bank.channels[ch - 1u].wal_head, 32u) != 0);
        }
    }
    uint64_t dt_mem_ns = mono_now_ns() - t0;

    /* (2) Replay attack on a single channel (ch=42): KILL only on ch=42, neighbors 41 & 43 untouched */
    {
        omega_omg8_frame_t req_replay, rep_replay, req_n1, rep_n1, req_n2, rep_n2;
        bool trap = false;
        build_valid_req(&req_replay, 42u, 2ULL, 1042ULL, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        omega_omg8_eval_frame(&bank, &req_replay, &rep_replay, &trap);
        assert(rep_replay.gate_state == OMEGA_OMG8_STATE_KILL);
        assert(rep_replay.err_flags == OMEGA_OMG8_ERR_NO_WITNESS);
        assert(bank.channels[42].kill_latched);

        /* Even a fresh higher nonce on ch=42 stays sticky KILL */
        build_valid_req(&req_replay, 42u, 3ULL, 9999ULL, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        omega_omg8_eval_frame(&bank, &req_replay, &rep_replay, &trap);
        assert(rep_replay.gate_state == OMEGA_OMG8_STATE_KILL);

        /* Neighbors ch=41 and ch=43 remain 100% healthy OPEN */
        build_valid_req(&req_n1, 41u, 2ULL, 2041ULL, 0x07000000u, 0x02000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        omega_omg8_eval_frame(&bank, &req_n1, &rep_n1, &trap);
        assert(rep_n1.gate_state == OMEGA_OMG8_STATE_OPEN);

        build_valid_req(&req_n2, 43u, 2ULL, 2043ULL, 0x07000000u, 0x02000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        omega_omg8_eval_frame(&bank, &req_n2, &rep_n2, &trap);
        assert(rep_n2.gate_state == OMEGA_OMG8_STATE_OPEN);

        /* Authenticated L01 reset restores ch=42 to HOLD */
        assert(!omega_omg8_l01_reset(&bank, 42u, "WRONG_KEY"));
        assert(omega_omg8_l01_reset(&bank, 42u, OMEGA_L01_KEY_TOKEN));
        assert(!bank.channels[42].kill_latched);
    }

    /* (3) Phase-mirror collision (mirror_ok == 0 -> 0x5A TRAP in trap_ring, no return to HOLD) */
    {
        omega_omg8_frame_t req_trap, rep_trap, req_after, rep_after;
        bool trap = false;
        build_valid_req(&req_trap, 7u, 2ULL, 5007ULL, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN /* mirror_ok == 0! */);
        omega_omg8_eval_frame(&bank, &req_trap, &rep_trap, &trap);
        assert(trap);
        assert(rep_trap.gate_state == OMEGA_OMG8_STATE_TRAP);
        assert(rep_trap.err_flags == OMEGA_OMG8_ERR_MIRROR_TRAP);
        assert(bank.trap_count == 1u);
        assert(bank.trap_ring[0].channel_id == 7u);
        assert(bank.trap_ring[0].gate_state == OMEGA_OMG8_STATE_TRAP);

        /* Subsequent valid frame on ch=7 cannot return to HOLD or OPEN */
        build_valid_req(&req_after, 7u, 3ULL, 6007ULL, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        omega_omg8_eval_frame(&bank, &req_after, &rep_after, &trap);
        assert(!trap);
        assert(rep_after.gate_state == OMEGA_OMG8_STATE_TRAP);
    }

    /* (4) Fill TRAP chamber to 1024/1024, then #1025 triggers fail-closed sticky KILL */
    {
        omega_omg8_bank_init(&bank);
        for (uint16_t i = 0u; i < OMEGA_OMG8_TRAP_RING_CAP; ++i) {
            omega_omg8_frame_t req, rep;
            bool trap = false;
            build_valid_req(&req, i, 1ULL, 100ULL + i, 0x03000000u, 0x01000000u,
                            OMEGA_OMG8_BRU_HOLD | OMEGA_OMG8_MIRROR_OK_BIT /* bru_top_state==0 on hit -> TRAP */);
            omega_omg8_eval_frame(&bank, &req, &rep, &trap);
            assert(trap);
            assert(rep.gate_state == OMEGA_OMG8_STATE_TRAP);
        }
        assert(bank.trap_count == 1024u);
        assert(!bank.global_kill_latched);

        /* Reset ch=0 trap latch via L01 without clearing trap_ring? Wait: reset ch=0 alone so it can emit #1025 */
        assert(omega_omg8_l01_reset(&bank, 0u, OMEGA_L01_KEY_TOKEN));
        assert(bank.trap_count == 1024u);

        omega_omg8_frame_t req_1025, rep_1025;
        bool trap_1025 = false;
        build_valid_req(&req_1025, 0u, 2ULL, 9000ULL, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN /* mirror_ok == 0 -> #1025 TRAP overflow -> KILL! */);
        omega_omg8_eval_frame(&bank, &req_1025, &rep_1025, &trap_1025);
        assert(!trap_1025);
        assert(rep_1025.gate_state == OMEGA_OMG8_STATE_KILL);
        assert(rep_1025.err_flags == OMEGA_OMG8_ERR_MIRROR_TRAP);
        assert(bank.global_kill_latched);
        assert(bank.trap_overflow_kills == 1u);
        assert(bank.trap_count == 1024u);

        /* (5) Global 0xFFFFu L01 reset preserves forensic trap_ring & appends WAL reset records */
        omega_omg8_frame_t saved_trap_first = bank.trap_ring[0];
        omega_omg8_frame_t saved_trap_last  = bank.trap_ring[1023];
        uint8_t  pre_wal_ch0[32];
        uint8_t  pre_wal_ch1023[32];
        uint8_t  zero_hash[32] = {0};
        uint32_t pre_len_ch0    = bank.channels[0].ledger_len;
        uint32_t pre_len_ch1023 = bank.channels[1023].ledger_len;
        memcpy(pre_wal_ch0, bank.channels[0].wal_head, 32u);
        memcpy(pre_wal_ch1023, bank.channels[1023].wal_head, 32u);

        assert(!omega_omg8_l01_reset(&bank, 0xFFFFu, "WRONG_KEY"));
        assert(bank.global_kill_latched);

        assert(omega_omg8_l01_reset(&bank, 0xFFFFu, OMEGA_L01_KEY_TOKEN));
        assert(!bank.global_kill_latched);
        assert(bank.global_reset_epochs == 1u);
        assert(bank.trap_archived_count == 1024u);
        assert(bank.trap_count == 0u);
        assert(memcmp(bank.trap_epoch_sha256, zero_hash, 32u) != 0);
        assert(memcmp(bank.global_wal_head, zero_hash, 32u) != 0);

        /* Forensic frames in trap_ring remain intact in RAM (never wiped on reset) */
        assert(memcmp(&bank.trap_ring[0], &saved_trap_first, sizeof(saved_trap_first)) == 0);
        assert(memcmp(&bank.trap_ring[1023], &saved_trap_last, sizeof(saved_trap_last)) == 0);

        /* Explicit L01 reset WAL entry appended across channels without weakening nonce replay guard */
        assert(bank.channels[0].ledger_len == pre_len_ch0 + 1u);
        assert(bank.channels[1023].ledger_len == pre_len_ch1023 + 1u);
        assert(memcmp(bank.channels[0].wal_head, pre_wal_ch0, 32u) != 0);
        assert(memcmp(bank.channels[1023].wal_head, pre_wal_ch1023, 32u) != 0);
        assert(!bank.channels[0].kill_latched);
        assert(!bank.channels[1023].trap_latched);

        omega_omg8_frame_t req_stale, rep_stale, req_fresh, rep_fresh;
        bool trap_post = false;
        build_valid_req(&req_stale, 1u, 1ULL, 101ULL /* replay <= consumed */, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        omega_omg8_eval_frame(&bank, &req_stale, &rep_stale, &trap_post);
        assert(rep_stale.gate_state == OMEGA_OMG8_STATE_KILL);
        assert(rep_stale.err_flags == OMEGA_OMG8_ERR_NO_WITNESS);

        build_valid_req(&req_fresh, 2u, 2ULL, 9502ULL, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        omega_omg8_eval_frame(&bank, &req_fresh, &rep_fresh, &trap_post);
        assert(!trap_post);
        assert(rep_fresh.gate_state == OMEGA_OMG8_STATE_OPEN);
    }

    printf("[PASS] test_omg8_sluice (in-memory): 64B v1.1 contract, 1000-ch isolation (%llu ns), replay KILL, TRAP no-return, 1024->1025 overflow KILL, append-only global L01 reset verified.\n",
           (unsigned long long)dt_mem_ns);
    return 0;
}

#ifdef __QNX__
static int run_live_qnx_suite(const char *dev_path) {
    int fd = open(dev_path, O_RDWR);
    if (fd < 0) {
        perror("open /dev/omg8_gate");
        return 1;
    }

    const uint64_t ipc_budget_ns = 20000000ULL; /* 20 ms per synchronous hop */

    /* (1) & (5) 1 000 independent channels over live QNX devctl() + CLOCK_MONOTONIC timing */
    uint8_t prev_wal_sample[12] = {0};
    uint64_t t_start = mono_now_ns();
    for (uint16_t ch = 0u; ch < 1000u; ++ch) {
        omega_omg8_io_t io;
        build_valid_req(
            &io.req,
            ch,
            1ULL,
            10000ULL + (uint64_t)ch,
            0x03000000u,
            0x01000000u,
            OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT
        );
        int rc = omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_EVAL, &io, sizeof(io), NULL, ipc_budget_ns);
        assert(rc == EOK);
        assert(io.rep.gate_state == OMEGA_OMG8_STATE_OPEN);
        assert(io.rep.ln_out_q24 == 0x0162E42Eu);
        assert(omega_omg8_verify_crc(&io.rep));
        if (ch > 0u) {
            assert(memcmp(io.rep.prev_wal_trunc, prev_wal_sample, 12u) != 0);
        }
        memcpy(prev_wal_sample, io.rep.prev_wal_trunc, 12u);
    }
    uint64_t dt_1000_ns = mono_now_ns() - t_start;
    uint64_t ns_per_eval = dt_1000_ns / 1000ULL;
    uint64_t evals_per_sec = (dt_1000_ns > 0ULL) ? (1000000000000ULL / dt_1000_ns) : 0ULL;

    /* (2) Replay attack on ch=500 -> KILL on ch=500 only; ch=499 & ch=501 stay OPEN */
    {
        omega_omg8_io_t io_rep, io_499, io_501;
        build_valid_req(&io_rep.req, 500u, 2ULL, 10500ULL /* replay <= 10500 */, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_EVAL, &io_rep, sizeof(io_rep), NULL, ipc_budget_ns) == EOK);
        assert(io_rep.rep.gate_state == OMEGA_OMG8_STATE_KILL);
        assert(io_rep.rep.err_flags == OMEGA_OMG8_ERR_NO_WITNESS);

        build_valid_req(&io_499.req, 499u, 2ULL, 20499ULL, 0x07000000u, 0x02000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_EVAL, &io_499, sizeof(io_499), NULL, ipc_budget_ns) == EOK);
        assert(io_499.rep.gate_state == OMEGA_OMG8_STATE_OPEN);

        build_valid_req(&io_501.req, 501u, 2ULL, 20501ULL, 0x07000000u, 0x02000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_EVAL, &io_501, sizeof(io_501), NULL, ipc_budget_ns) == EOK);
        assert(io_501.rep.gate_state == OMEGA_OMG8_STATE_OPEN);
    }

    /* (3) Phase-mirror collision on ch=1000 (mirror_ok == 0 -> 0x5A TRAP, no return to HOLD) */
    {
        omega_omg8_io_t io_trap, io_retry;
        build_valid_req(&io_trap.req, 1000u, 1ULL, 31000ULL, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN /* mirror_ok == 0 */);
        assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_EVAL, &io_trap, sizeof(io_trap), NULL, ipc_budget_ns) == EOK);
        assert(io_trap.rep.gate_state == OMEGA_OMG8_STATE_TRAP);

        build_valid_req(&io_retry.req, 1000u, 2ULL, 32000ULL, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN | OMEGA_OMG8_MIRROR_OK_BIT);
        assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_EVAL, &io_retry, sizeof(io_retry), NULL, ipc_budget_ns) == EOK);
        assert(io_retry.rep.gate_state == OMEGA_OMG8_STATE_TRAP);
    }

    /* (4) Fill remaining 1023 TRAP slots (ch 0..999 + 1001..1023) -> 1024/1024, then #1025 -> KILL */
    {
        /* Reset ch=500 first so all 0..999 + 1001..1023 can trap cleanly */
        omega_omg8_l01_reset_t rst500;
        memset(&rst500, 0, sizeof(rst500));
        rst500.channel_id = 500u;
        strncpy(rst500.l01_token, OMEGA_L01_KEY_TOKEN, sizeof(rst500.l01_token) - 1u);
        assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_L01_RESET, &rst500, sizeof(rst500), NULL, ipc_budget_ns) == EOK);
        assert(rst500.status_out == 1u);

        for (uint16_t ch = 0u; ch < 1024u; ++ch) {
            if (ch == 1000u) continue; /* already trapped in test (3) -> total becomes 1 + 1023 = 1024 */
            omega_omg8_io_t io_t;
            build_valid_req(&io_t.req, ch, 10ULL, 50000ULL + (uint64_t)ch, 0x03000000u, 0x01000000u,
                            OMEGA_OMG8_BRU_OPEN /* mirror_ok == 0 -> TRAP */);
            assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_EVAL, &io_t, sizeof(io_t), NULL, ipc_budget_ns) == EOK);
            assert(io_t.rep.gate_state == OMEGA_OMG8_STATE_TRAP);
        }

        omega_omg8_status_t st;
        memset(&st, 0, sizeof(st));
        assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_STATUS, &st, sizeof(st), NULL, ipc_budget_ns) == EOK);
        assert(st.trap_count == 1024u);
        assert(st.global_kill_latched == 0u);

        /* Release ch=0 locally so it can submit the 1025th TRAP -> triggers global fail-closed KILL */
        omega_omg8_l01_reset_t rst0;
        memset(&rst0, 0, sizeof(rst0));
        rst0.channel_id = 0u;
        strncpy(rst0.l01_token, OMEGA_L01_KEY_TOKEN, sizeof(rst0.l01_token) - 1u);
        assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_L01_RESET, &rst0, sizeof(rst0), NULL, ipc_budget_ns) == EOK);

        omega_omg8_io_t io_1025;
        build_valid_req(&io_1025.req, 0u, 11ULL, 90000ULL, 0x03000000u, 0x01000000u,
                        OMEGA_OMG8_BRU_OPEN /* mirror_ok == 0 -> 1025th TRAP -> KILL */);
        assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_EVAL, &io_1025, sizeof(io_1025), NULL, ipc_budget_ns) == EOK);
        assert(io_1025.rep.gate_state == OMEGA_OMG8_STATE_KILL);
        assert(io_1025.rep.err_flags == OMEGA_OMG8_ERR_MIRROR_TRAP);

        memset(&st, 0, sizeof(st));
        assert(omega_qnx_devctl_timed(fd, OMEGA_DCMD_OMG8_STATUS, &st, sizeof(st), NULL, ipc_budget_ns) == EOK);
        assert(st.trap_count == 1024u);
        assert(st.trap_overflow_kills == 1u);
        assert(st.global_kill_latched == 1u);

        printf("[QNX8_LIVE_OMG8_PASS] 1000_ch_total_ns=%llu | per_eval_ns=%llu | throughput_eval_s=%llu | trap_ring=%u/1024 | overflow_kill=%u | pulses_sent=%u\n",
               (unsigned long long)dt_1000_ns,
               (unsigned long long)ns_per_eval,
               (unsigned long long)evals_per_sec,
               (unsigned)st.trap_count,
               (unsigned)st.trap_overflow_kills,
               (unsigned)st.pulse_sent_count);
        fflush(stdout);
    }

    close(fd);
    return 0;
}
#endif

int main(int argc, char **argv) {
    int rc = run_in_memory_suite();
    if (rc != 0) {
        return rc;
    }
#ifdef __QNX__
    if (argc >= 3 && strcmp(argv[1], "--live-qnx") == 0) {
        return run_live_qnx_suite(argv[2]);
    }
#else
    (void)argc;
    (void)argv;
#endif
    return 0;
}
