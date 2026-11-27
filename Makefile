# ============================================================================
# OmegaGate-QNX Makefile
# Targets:
#   make test                   -> Host C11 zero-float verification (gcc -Werror)
#   make demo                   -> Host C11 planner demo
#   make rtl                    -> SystemVerilog RTL cross-verification (iverilog + yosys)
#   make verify                 -> Full C11 + RTL verification gate
#   make qnx ARCH=x86_64        -> Cross-compile 15 QNX 8.0 binaries via qcc (QEMU)
#   make qnx ARCH=aarch64le     -> Cross-compile for Raspberry Pi 4 / QNX 8.0 aarch64
# ============================================================================

CC       ?= gcc
CFLAGS   := -std=c11 -O2 -Wall -Wextra -Werror -Iinclude
ARCH     ?= x86_64
QCC      ?= qcc
QCCFLAGS := -Vgcc_nto$(ARCH) -std=gnu11 -O2 -Wall -Wextra -Werror -Iinclude

CORE_SRCS    := src/sha256_zero_dep.c src/omega_gate_core.c
SLUICE_SRCS  := src/sha256_zero_dep.c src/hashprune_sluice.c
CAP205_SRCS  := $(SLUICE_SRCS) src/omega_capsule205b.c
BUILD_DIR    := build

.PHONY: all verify test demo rtl qnx clean

all: verify

verify: test demo rtl

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

test: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_omega_gate $(CORE_SRCS) tests/test_omega_gate.c
	./$(BUILD_DIR)/test_omega_gate
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_hashprune_sluice $(SLUICE_SRCS) tests/test_hashprune_sluice.c
	./$(BUILD_DIR)/test_hashprune_sluice
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_capsule205b_bridge $(CAP205_SRCS) tests/test_capsule205b_bridge.c
	./$(BUILD_DIR)/test_capsule205b_bridge
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_d2_hardening $(SLUICE_SRCS) tests/test_d2_hardening.c
	./$(BUILD_DIR)/test_d2_hardening
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test_omg8_sluice src/sha256_zero_dep.c tests/test_omg8_sluice.c
	./$(BUILD_DIR)/test_omg8_sluice
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/d2_gate_resmgr_host $(SLUICE_SRCS) src/d2_gate_resmgr.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/omg8_gate_resmgr_host src/sha256_zero_dep.c src/omg8_gate_resmgr.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/spi_fpga_sim_resmgr_host $(SLUICE_SRCS) src/spi_fpga_sim_resmgr.c
	@python3 -B -c 'import pathlib, re; bad=("00_KANONISK_KJERNE","03_ENGINES","04_REALITY_FORGE","05_PATENTS","07_BOKHYLLA","CARBON/","Gemini-Core","/home/sololyset"); fp_re=re.compile(r"(^|[^A-Za-z0-9_])(float|double|float32|float64)([^A-Za-z0-9_]|$$)"); files=[p for p in sorted(pathlib.Path(".").rglob("*")) if p.is_file() and ".git" not in p.parts and "build" not in p.parts and p.name!="Makefile" and p.name!="check_dco_and_zero_float.sh"]; leaks=[(str(p),t) for p in files for t in bad if t in p.read_text(encoding="utf-8", errors="ignore")]; assert not leaks, f"0_LEAKS violation: {leaks}"; omg8=[pathlib.Path(x) for x in ("include/omega_omg8_sluice.h","src/omg8_gate_resmgr.c","tests/test_omg8_sluice.c")]; fp=[(str(p),m.group(0)) for p in omg8 for m in fp_re.finditer(p.read_text(encoding="utf-8"))]; assert not fp, f"0_FLOAT violation: {fp}"; print(f"[HYGIENE_OPEN] 0 LEAKS across {len(files)} files & 0 FP tokens in OMG8 sources.")'

demo: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/omega_gate_resmgr $(CORE_SRCS) src/omega_gate_resmgr.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/d0_planner $(CORE_SRCS) src/d0_planner.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/trap_mirror_daemon src/trap_mirror_daemon.c
	./$(BUILD_DIR)/omega_gate_resmgr
	./$(BUILD_DIR)/d0_planner

rtl: $(BUILD_DIR)
	iverilog -g2012 -Wall -o $(BUILD_DIR)/tb_robot_trap_gate.vvp rtl/robot_trap_gate.sv rtl/tb_robot_trap_gate.sv
	vvp -N $(BUILD_DIR)/tb_robot_trap_gate.vvp
	sed -E '/^[[:space:]]*(timeunit|timeprecision)[[:space:]]/d' rtl/robot_trap_gate.sv > $(BUILD_DIR)/robot_trap_gate_yosys.sv
	yosys -q -p "read_verilog -sv $(BUILD_DIR)/robot_trap_gate_yosys.sv; hierarchy -check -top robot_trap_gate; proc; opt; check -assert; stat -top robot_trap_gate"
	@echo "[PASS] RTL cross-verification (iverilog -g2012 -Wall + yosys check -assert) CLEAN"

qnx:
	@mkdir -p $(BUILD_DIR)/qnx_$(ARCH)
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/omega_gate_resmgr $(CORE_SRCS) src/omega_gate_resmgr.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/d0_planner $(CORE_SRCS) src/d0_planner.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/trap_mirror_daemon src/trap_mirror_daemon.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/test_hashprune_sluice $(SLUICE_SRCS) tests/test_hashprune_sluice.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/test_capsule205b_bridge $(CAP205_SRCS) tests/test_capsule205b_bridge.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/test_d2_hardening $(SLUICE_SRCS) tests/test_d2_hardening.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/test_omg8_sluice src/sha256_zero_dep.c tests/test_omg8_sluice.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/spi_fpga_sim_resmgr $(SLUICE_SRCS) src/spi_fpga_sim_resmgr.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/d2_gate_resmgr $(SLUICE_SRCS) src/d2_gate_resmgr.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/omg8_gate_resmgr src/sha256_zero_dep.c src/omg8_gate_resmgr.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/d1_guestroom_resmgr $(SLUICE_SRCS) src/d1_guestroom_resmgr.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/d0_trap_resmgr $(CAP205_SRCS) src/d0_trap_resmgr.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/ser2_capsule_bridge $(CAP205_SRCS) src/ser2_capsule_bridge.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/cascade_mirror_daemon $(SLUICE_SRCS) src/cascade_mirror_daemon.c
	$(QCC) $(QCCFLAGS) -o $(BUILD_DIR)/qnx_$(ARCH)/cascade_driver $(SLUICE_SRCS) src/cascade_driver.c
	@echo "[OK] Built QNX 8.0 ($(ARCH)) binaries in $(BUILD_DIR)/qnx_$(ARCH)/"

clean:
	@rm -rf $(BUILD_DIR)
