# ============================================================================
# OmegaGate-QNX Makefile
# Targets:
#   make test                   -> Host C11 zero-float verification (gcc -Werror)
#   make demo                   -> Host C11 planner demo
#   make rtl                    -> SystemVerilog RTL cross-verification (iverilog + yosys)
#   make verify                 -> Full C11 + RTL verification gate
#   make qnx ARCH=x86_64        -> Cross-compile 3 QNX 8.0 binaries via qcc (QEMU)
#   make qnx ARCH=aarch64le     -> Cross-compile for Raspberry Pi 4 / QNX 8.0 aarch64
# ============================================================================

CC       ?= gcc
CFLAGS   := -std=c11 -O2 -Wall -Wextra -Werror -Iinclude
ARCH     ?= x86_64
QCC      ?= qcc
QCCFLAGS := -Vgcc_nto$(ARCH) -std=gnu11 -O2 -Wall -Wextra -Werror -Iinclude

CORE_SRCS := src/sha256_zero_dep.c src/omega_gate_core.c
BUILD_DIR := build

.PHONY: all verify test demo rtl qnx clean

all: verify

verify: test demo rtl

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

test: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_omega_gate $(CORE_SRCS) tests/test_omega_gate.c
	./$(BUILD_DIR)/test_omega_gate

demo: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/omega_gate_resmgr $(CORE_SRCS) src/omega_gate_resmgr.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/d0_planner $(CORE_SRCS) src/d0_planner.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/trap_mirror_daemon src/trap_mirror_daemon.c
	./$(BUILD_DIR)/omega_gate_resmgr
	./$(BUILD_DIR)/d0_planner

rtl: $(BUILD_DIR)
	iverilog -g2012 -Wall -o $(BUILD_DIR)/tb_robot_trap_gate.vvp rtl/robot_trap_gate.sv rtl/tb_robot_trap_gate.sv
	vvp $(BUILD_DIR)/tb_robot_trap_gate.vvp
	sed -E '/^[[:space:]]*(timeunit|timeprecision)[[:space:]]/d' rtl/robot_trap_gate.sv > $(BUILD_DIR)/robot_trap_gate_yosys.sv
	yosys -q -p "read_verilog -sv $(BUILD_DIR)/robot_trap_gate_yosys.sv; hierarchy -check -top robot_trap_gate; proc; opt; check -assert; stat -top robot_trap_gate"
	@echo "[PASS] RTL cross-verification (iverilog -g2012 -Wall + yosys check -assert) CLEAN"

qnx:
	@mkdir -p $(BUILD_DIR)/qnx_$(ARCH)
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/omega_gate_resmgr $(CORE_SRCS) src/omega_gate_resmgr.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/d0_planner $(CORE_SRCS) src/d0_planner.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/trap_mirror_daemon src/trap_mirror_daemon.c
	@echo "[OK] Built QNX 8.0 ($(ARCH)) binaries in $(BUILD_DIR)/qnx_$(ARCH)/"

clean:
	@rm -rf $(BUILD_DIR)
