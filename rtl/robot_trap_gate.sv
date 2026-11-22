// =============================================================================
// L1/L1.5 Syntetiserbar RTL: Robot Trap-Port (Omega-Gate) med Dødtidslås
// Standard: IEEE 1800-2012 (iverilog -g2012 -Wall / yosys clean)
// Epistemisk grense: INSPIRED_BY != IMPLEMENTS != PROVES
// =============================================================================
`default_nettype none

module robot_trap_gate #(
    parameter logic [31:0] MAX_TORQUE_MNM   = 32'd80_000, // 80.0 Nm
    parameter logic [31:0] MAX_JERK_MRAD_S3 = 32'd25_000, // 25.0 rad/s^3
    parameter logic [31:0] LIGHTCONE_MAX_NS = 32'd133,    // ~133.4 ns
    parameter logic [15:0] MIN_AIRLOCK_MS   = 16'd14,     // 14 ms dvalesluse
    parameter logic [7:0]  KILL_ANOMALY_TH  = 8'd100,     // >=100 -> KILL
    parameter logic [1:0]  DEADTIME_CYCLES  = 2'd2        // 2 sykluser = 10 ns @ 200 MHz
) (
    input  wire        clk,
    input  wire        rst_n,               // Aktiv-lav power-on reset
    input  wire        l01_phys_key_i,      // Fysisk L01-nøkkel for gjenåpning etter KILL

    // Innkommende kommandokapsel (D0 -> D1)
    input  wire        cmd_valid_i,
    input  wire [2:0]  stage_i,             // 0=RAW, 1=EST, 2=STRUCT, 3=VIAB, 4=COMMIT
    input  wire [2:0]  prev_stage_i,
    input  wire [31:0] timestamp_ns_i,
    input  wire [31:0] torque_abs_mnm_i,
    input  wire [31:0] jerk_abs_mrad_s3_i,
    input  wire [7:0]  anomaly_score_i,
    input  wire        witness_ok_i,        // Eksternt vitne (W = 1)
    input  wire [15:0] airlock_elapsed_ms_i,

    // Utganger (D2 -> D3)
    output logic [1:0] gate_decision_o,     // 00=HOLD, 01=OPEN, 10=TRAP, 11=KILL
    output logic       rail_5v_en_o,        // Q_high: 5.00 V DC engangspuls
    output logic       crowbar_gnd_o,       // Q_low : 0.00 V DC jordingsklemme
    output logic       trap_mirror_strobe_o,// Sender anomali til lukket speilkammer
    output logic       kill_latched_o,      // Permanent låst inntil l01_phys_key_i
    output logic [3:0] reason_code_o        // Deterministisk årsakskode for vitnelogg
);
    timeunit 1ns;
    timeprecision 1ps;

    // Beslutningskoder
    localparam logic [1:0] DEC_HOLD = 2'b00;
    localparam logic [1:0] DEC_OPEN = 2'b01;
    localparam logic [1:0] DEC_TRAP = 2'b10;
    localparam logic [1:0] DEC_KILL = 2'b11;

    // Årsakskoder for append-only vitnelogg
    localparam logic [3:0] RSN_IDLE_HOLD       = 4'd0;
    localparam logic [3:0] RSN_OPEN_PULSE      = 4'd1;
    localparam logic [3:0] RSN_EARLY_NO_WIT    = 4'd2;
    localparam logic [3:0] RSN_TRAP_MIRROR     = 4'd3;
    localparam logic [3:0] RSN_KILL_SHORTCUT   = 4'd4;
    localparam logic [3:0] RSN_KILL_REPLAY     = 4'd5;
    localparam logic [3:0] RSN_KILL_LIGHTCONE  = 4'd6;
    localparam logic [3:0] RSN_KILL_GUILLOTINE = 4'd7;
    localparam logic [3:0] RSN_KILL_HOSTILE    = 4'd8;
    localparam logic [3:0] RSN_KILL_LATCHED    = 4'd9;

    // Utgangs-tilstandsmaskin for garantert dødtid (Q_high * Q_low == 0)
    localparam logic [1:0] ST_CLAMPED  = 2'b00; // Q_low=1, Q_high=0
    localparam logic [1:0] ST_DEADTIME = 2'b01; // Q_low=0, Q_high=0
    localparam logic [1:0] ST_PULSE_5V = 2'b10; // Q_low=0, Q_high=1 (1 syklus)

    logic        cmd_valid_q;
    logic        cmd_rising;
    logic        has_prev_ts_q;
    logic [31:0] last_ts_q;
    logic [1:0]  rail_state_q;
    logic [1:0]  deadtime_cnt_q;

    // Kombinatoriske feil- og statusflagg
    logic shortcut_breach;
    logic replay_breach;
    logic lightcone_breach;
    logic phys_guillotine_breach;
    logic hostile_anomaly;
    logic trap_anomaly;
    logic early_or_unwitnessed;
    logic any_kill_trigger;

    assign cmd_rising = cmd_valid_i & ~cmd_valid_q;

    always_comb begin
        // 1. Typekjede-vakt (ingen snarvei, og forhindrer 3-bit wraparound)
        shortcut_breach        = (prev_stage_i >= 3'd4) || (stage_i != (prev_stage_i + 3'd1));

        // 2. Timing-loven (anti-replay og lyskjegle uten unsigned underflow)
        replay_breach          = has_prev_ts_q && (timestamp_ns_i <= last_ts_q);
        lightcone_breach       = has_prev_ts_q && (timestamp_ns_i > last_ts_q) &&
                                 ((timestamp_ns_i - last_ts_q) > LIGHTCONE_MAX_NS);

        // 3. Fysiske skranker (Dør 24: Moment-guillotine og rykk)
        phys_guillotine_breach = (torque_abs_mnm_i > MAX_TORQUE_MNM) ||
                                 (jerk_abs_mrad_s3_i > MAX_JERK_MRAD_S3);

        // 4. Virus / anomali
        hostile_anomaly        = (anomaly_score_i >= KILL_ANOMALY_TH);
        trap_anomaly           = (anomaly_score_i > 8'd0) && !hostile_anomaly;

        // 5. Kun COMMITTED (3'd4) med >= 14 ms dvalesluse og vitne (W = 1) kan åpne 5.00 V
        early_or_unwitnessed   = (stage_i != 3'd4) ||
                                 (airlock_elapsed_ms_i < MIN_AIRLOCK_MS) ||
                                 !witness_ok_i;

        any_kill_trigger       = shortcut_breach || replay_breach || lightcone_breach ||
                                 phys_guillotine_breach || hostile_anomaly;
    end

    // Sekvensiell kontroll- og subsumpsjonslogikk
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            cmd_valid_q          <= 1'b0;
            has_prev_ts_q        <= 1'b0;
            last_ts_q            <= 32'd0;
            kill_latched_o       <= 1'b0;
            gate_decision_o      <= DEC_HOLD;
            reason_code_o        <= RSN_IDLE_HOLD;
            trap_mirror_strobe_o <= 1'b0;
            rail_state_q         <= ST_CLAMPED;
            deadtime_cnt_q       <= 2'd0;
        end else begin
            cmd_valid_q          <= cmd_valid_i;
            trap_mirror_strobe_o <= 1'b0;

            // Fysisk L01-nøkkel kan nullstille KILL-lås når kommandobussen er idle (!cmd_valid_i)
            if (l01_phys_key_i && !cmd_valid_i) begin
                kill_latched_o  <= 1'b0;
                has_prev_ts_q   <= 1'b0;
                gate_decision_o <= DEC_HOLD;
                reason_code_o   <= RSN_IDLE_HOLD;
                rail_state_q    <= ST_CLAMPED;
            end else if (cmd_rising) begin
                // Subsumpsjonslov: KILL > TRAP > HOLD > OPEN
                if (kill_latched_o) begin
                    gate_decision_o <= DEC_KILL;
                    reason_code_o   <= RSN_KILL_LATCHED;
                    rail_state_q    <= ST_CLAMPED;
                end else if (any_kill_trigger) begin
                    kill_latched_o  <= 1'b1;
                    gate_decision_o <= DEC_KILL;
                    rail_state_q    <= ST_CLAMPED;
                    if (shortcut_breach)             reason_code_o <= RSN_KILL_SHORTCUT;
                    else if (replay_breach)          reason_code_o <= RSN_KILL_REPLAY;
                    else if (lightcone_breach)       reason_code_o <= RSN_KILL_LIGHTCONE;
                    else if (phys_guillotine_breach) reason_code_o <= RSN_KILL_GUILLOTINE;
                    else                             reason_code_o <= RSN_KILL_HOSTILE;
                end else if (trap_anomaly) begin
                    gate_decision_o      <= DEC_TRAP;
                    reason_code_o        <= RSN_TRAP_MIRROR;
                    trap_mirror_strobe_o <= 1'b1;
                    last_ts_q            <= timestamp_ns_i;
                    has_prev_ts_q        <= 1'b1;
                    rail_state_q         <= ST_CLAMPED;
                end else if (early_or_unwitnessed) begin
                    gate_decision_o <= DEC_HOLD;
                    reason_code_o   <= RSN_EARLY_NO_WIT;
                    last_ts_q       <= timestamp_ns_i;
                    has_prev_ts_q   <= 1'b1;
                    rail_state_q    <= ST_CLAMPED;
                end else begin
                    // Godkjent -> start dødtid før 5.00 V engangspuls
                    gate_decision_o <= DEC_OPEN;
                    reason_code_o   <= RSN_OPEN_PULSE;
                    last_ts_q       <= timestamp_ns_i;
                    has_prev_ts_q   <= 1'b1;
                    rail_state_q    <= ST_DEADTIME;
                    deadtime_cnt_q  <= (DEADTIME_CYCLES > 2'd0) ? (DEADTIME_CYCLES - 2'd1) : 2'd0;
                end
            end else begin
                // Fremdrift i dødtids- og engangspulsmaskin
                case (rail_state_q)
                    ST_DEADTIME: begin
                        if (kill_latched_o) begin
                            rail_state_q <= ST_CLAMPED;
                        end else if (deadtime_cnt_q == 2'd0) begin
                            rail_state_q <= ST_PULSE_5V;
                        end else begin
                            deadtime_cnt_q <= deadtime_cnt_q - 2'd1;
                        end
                    end
                    ST_PULSE_5V: begin
                        // Kun én klokkesyklus med 5.00 V DC, deretter tilbake til sikker jord
                        rail_state_q <= ST_CLAMPED;
                    end
                    default: begin
                        rail_state_q <= ST_CLAMPED;
                    end
                endcase
            end
        end
    end

    // Garantert gjensidig utelukkelse: rail_5v_en_o & crowbar_gnd_o == 1'b0 alltid
    always_comb begin
        rail_5v_en_o  = (rail_state_q == ST_PULSE_5V) && !kill_latched_o;
        crowbar_gnd_o = (rail_state_q == ST_CLAMPED)  || kill_latched_o;
    end

endmodule

`default_nettype wire
