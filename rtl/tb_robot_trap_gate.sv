// ============================================================================
// TESTBENCH : tb_robot_trap_gate
// STANDARD  : SystemVerilog IEEE 1800-2012 (iverilog -g2012 -Wall)
// TARGET    : robot_trap_gate.sv (KILL > TRAP > HOLD > OPEN + 10 ns Deadtime)
// ============================================================================

module tb_robot_trap_gate;
    timeunit 1ns;
    timeprecision 1ps;

    reg        clk = 1'b0;
    reg        rst_n = 1'b1;
    reg        l01_phys_key_i = 1'b0;

    reg        cmd_valid_i = 1'b0;
    reg [2:0]  stage_i = 3'd0;
    reg [2:0]  prev_stage_i = 3'd0;
    reg [31:0] timestamp_ns_i = 32'd0;
    reg [31:0] torque_abs_mnm_i = 32'd0;
    reg [31:0] jerk_abs_mrad_s3_i = 32'd0;
    reg [7:0]  anomaly_score_i = 8'd0;
    reg        witness_ok_i = 1'b0;
    reg [15:0] airlock_elapsed_ms_i = 16'd0;

    wire [1:0] gate_decision_o;
    wire       rail_5v_en_o;
    wire       crowbar_gnd_o;
    wire       trap_mirror_strobe_o;
    wire       kill_latched_o;
    wire [3:0] reason_code_o;

    localparam [1:0] DEC_HOLD = 2'b00;
    localparam [1:0] DEC_OPEN = 2'b01;
    localparam [1:0] DEC_TRAP = 2'b10;
    localparam [1:0] DEC_KILL = 2'b11;

    always #2.5 clk = ~clk; // 200 MHz (5.0 ns)

    robot_trap_gate dut (
        .clk                  (clk),
        .rst_n                (rst_n),
        .l01_phys_key_i       (l01_phys_key_i),
        .cmd_valid_i          (cmd_valid_i),
        .stage_i              (stage_i),
        .prev_stage_i         (prev_stage_i),
        .timestamp_ns_i       (timestamp_ns_i),
        .torque_abs_mnm_i     (torque_abs_mnm_i),
        .jerk_abs_mrad_s3_i   (jerk_abs_mrad_s3_i),
        .anomaly_score_i      (anomaly_score_i),
        .witness_ok_i         (witness_ok_i),
        .airlock_elapsed_ms_i (airlock_elapsed_ms_i),
        .gate_decision_o      (gate_decision_o),
        .rail_5v_en_o         (rail_5v_en_o),
        .crowbar_gnd_o        (crowbar_gnd_o),
        .trap_mirror_strobe_o (trap_mirror_strobe_o),
        .kill_latched_o       (kill_latched_o),
        .reason_code_o        (reason_code_o)
    );

    integer pass_cnt = 0;
    integer fail_cnt = 0;
    integer shoot_through_err = 0;

    always @(posedge clk) begin
        if (rail_5v_en_o === 1'b1 && crowbar_gnd_o === 1'b1) begin
            $display("FAIL | SHOOT_THROUGH | rail_5v_en_o & crowbar_gnd_o both HIGH!");
            shoot_through_err = shoot_through_err + 1;
        end
    end

    task automatic do_reset;
        begin
            cmd_valid_i = 1'b0;
            l01_phys_key_i = 1'b0;
            rst_n = 1'b1; #1;
            rst_n = 1'b0;
            repeat (2) @(posedge clk);
            rst_n = 1'b1;
            @(posedge clk); #1;
        end
    endtask

    task automatic send_cmd(
        input [2:0]  st,
        input [2:0]  prev_st,
        input [31:0] ts,
        input [31:0] trq,
        input [31:0] jrk,
        input [7:0]  anom,
        input        wit,
        input [15:0] air
    );
        begin
            stage_i              = st;
            prev_stage_i         = prev_st;
            timestamp_ns_i       = ts;
            torque_abs_mnm_i     = trq;
            jerk_abs_mrad_s3_i   = jrk;
            anomaly_score_i      = anom;
            witness_ok_i         = wit;
            airlock_elapsed_ms_i = air;
            cmd_valid_i          = 1'b1;
            @(posedge clk); #1;
            cmd_valid_i          = 1'b0;
        end
    endtask

    task automatic expect_eq(input [255:0] name, input cond);
        begin
            if (cond) begin
                $display("PASS | %0s | dec=%b 5v=%b gnd=%b trap=%b kill=%b rsn=%0d",
                         name, gate_decision_o, rail_5v_en_o, crowbar_gnd_o,
                         trap_mirror_strobe_o, kill_latched_o, reason_code_o);
                pass_cnt = pass_cnt + 1;
            end else begin
                $display("FAIL | %0s | dec=%b 5v=%b gnd=%b trap=%b kill=%b rsn=%0d",
                         name, gate_decision_o, rail_5v_en_o, crowbar_gnd_o,
                         trap_mirror_strobe_o, kill_latched_o, reason_code_o);
                fail_cnt = fail_cnt + 1;
            end
        end
    endtask

    initial begin
        do_reset();

        // T0: Reset HOLD, clamped to GND
        expect_eq("T0_RESET_HOLD_CLAMPED", gate_decision_o == DEC_HOLD && rail_5v_en_o == 1'b0 && crowbar_gnd_o == 1'b1);

        // T1: Valid COMMITTED -> 2 cycles deadtime (Q_h=0, Q_l=0), then 1-cycle 5V pulse, then back to GND
        send_cmd(3'd4, 3'd3, 32'd1000, 32'd40_000, 32'd10_000, 8'd0, 1'b1, 16'd15);
        expect_eq("T1A_DEADTIME_CYCLE1", gate_decision_o == DEC_OPEN && rail_5v_en_o == 1'b0 && crowbar_gnd_o == 1'b0);
        @(posedge clk); #1;
        expect_eq("T1B_DEADTIME_CYCLE2", rail_5v_en_o == 1'b0 && crowbar_gnd_o == 1'b0);
        @(posedge clk); #1;
        expect_eq("T1C_SINGLE_5V_PULSE", rail_5v_en_o == 1'b1 && crowbar_gnd_o == 1'b0);
        @(posedge clk); #1;
        expect_eq("T1D_RETURN_TO_CLAMP", rail_5v_en_o == 1'b0 && crowbar_gnd_o == 1'b1);

        // T2: Intermediate stage RAW -> ESTIMATE -> HOLD (never energizes)
        send_cmd(3'd1, 3'd0, 32'd1050, 32'd10_000, 32'd1_000, 8'd0, 1'b1, 16'd20);
        expect_eq("T2_INTERMEDIATE_HOLD", gate_decision_o == DEC_HOLD && rail_5v_en_o == 1'b0 && reason_code_o == 4'd2);

        // One idle cycle so cmd_valid_q clears before next rising edge
        @(posedge clk); #1;

        // T3: Suspicious anomaly (42) -> TRAP + mirror strobe
        send_cmd(3'd4, 3'd3, 32'd1100, 32'd40_000, 32'd10_000, 8'd42, 1'b1, 16'd15);
        expect_eq("T3_TRAP_MIRROR", gate_decision_o == DEC_TRAP && trap_mirror_strobe_o == 1'b1 && rail_5v_en_o == 1'b0);

        @(posedge clk); #1;

        // T4: Shortcut RAW -> COMMITTED -> sticky KILL
        send_cmd(3'd4, 3'd0, 32'd1150, 32'd40_000, 32'd10_000, 8'd0, 1'b1, 16'd15);
        expect_eq("T4_SHORTCUT_KILL", gate_decision_o == DEC_KILL && kill_latched_o == 1'b1 && reason_code_o == 4'd4);

        // T5: L01 physical key reset while bus is idle (stage=0, prev=0) releases sticky KILL to HOLD
        stage_i = 3'd0; prev_stage_i = 3'd0;
        l01_phys_key_i = 1'b1;
        @(posedge clk); #1;
        l01_phys_key_i = 1'b0;
        expect_eq("T5_L01_IDLE_KEY_RESET", gate_decision_o == DEC_HOLD && kill_latched_o == 1'b0 && crowbar_gnd_o == 1'b1);

        // T6: Replay attack (dt == 0) -> KILL
        send_cmd(3'd4, 3'd3, 32'd2000, 32'd10_000, 32'd1_000, 8'd0, 1'b1, 16'd15);
        repeat (3) @(posedge clk); #1;
        send_cmd(3'd4, 3'd3, 32'd2000, 32'd10_000, 32'd1_000, 8'd0, 1'b1, 16'd15);
        expect_eq("T6_REPLAY_KILL", gate_decision_o == DEC_KILL && kill_latched_o == 1'b1 && reason_code_o == 4'd5);

        expect_eq("T7_ZERO_SHOOT_THROUGH", shoot_through_err == 0);

        $display("SUMMARY | robot_trap_gate | PASS=%0d FAIL=%0d", pass_cnt, fail_cnt);
        if (fail_cnt != 0) $fatal(1, "tb_robot_trap_gate FAILED");
        $finish;
    end
endmodule
