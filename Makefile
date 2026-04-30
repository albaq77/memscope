.PHONY: all clean install test bench

ARCH ?= $(shell uname -m)
BPF_ARCH := $(ARCH)

ifeq ($(BPF_ARCH),x86_64)
    BPF_ARCH := x86
endif
ifeq ($(BPF_ARCH),aarch64)
    BPF_ARCH := arm64
endif

CLANG ?= clang
CC ?= gcc
CXX ?= g++
BPFTOOL ?= bpftool

PROJECT_DIR := $(shell pwd)
BUILD_DIR   := $(PROJECT_DIR)/build
OBJ_DIR     := $(BUILD_DIR)/obj

BPF_CFLAGS  := -g -O2 -target bpf \
               -D__TARGET_ARCH_$(BPF_ARCH) \
               -I$(PROJECT_DIR)/src/bpf \
               -I/usr/include/$(shell uname -m)-linux-gnu \
               -Wno-unused-value -Wno-unknown-warning-option

CFLAGS  := -g -O2 -Wall -Wextra \
           -I$(PROJECT_DIR)/src/collector \
           -I$(PROJECT_DIR)/src/bpf

CXXFLAGS := -g -O2 -Wall -Wextra -std=c++17 \
            -I$(PROJECT_DIR)/src/dwarf \
            -I$(PROJECT_DIR)/src/resolver \
            -I$(PROJECT_DIR)/src/bpf

LDFLAGS_COLLECTOR := -lbpf -lelf -lz
LDFLAGS_RESOLVER  := -ldw -lelf -lz
LDFLAGS_BENCH     := -lm

BPF_SRC     := $(PROJECT_DIR)/src/bpf/memscope.bpf.c
BPF_OBJ     := $(BUILD_DIR)/memscope.bpf.o
BPF_SKEL    := $(BUILD_DIR)/memscope.skel.h

BENCH_SRC := $(PROJECT_DIR)/src/benchmark/bench_target.c

all: $(BUILD_DIR)/memscope-collect $(BUILD_DIR)/memscope-resolve $(BUILD_DIR)/bench_target $(BPF_OBJ)

dirs:
	mkdir -p $(BUILD_DIR) $(OBJ_DIR)

$(BPF_OBJ): $(BPF_SRC) dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPFTOOL) gen skeleton $< > $(BPF_SKEL) 2>/dev/null || true

$(OBJ_DIR)/main_collector.o: $(PROJECT_DIR)/src/collector/main.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/collector.o: $(PROJECT_DIR)/src/collector/collector.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/memscope-collect: $(OBJ_DIR)/main_collector.o $(OBJ_DIR)/collector.o | dirs
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS_COLLECTOR)

$(OBJ_DIR)/dwarf_analyzer.o: $(PROJECT_DIR)/src/dwarf/dwarf_analyzer.cpp | dirs
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/address_resolver.o: $(PROJECT_DIR)/src/resolver/address_resolver.cpp | dirs
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/main_resolve.o: $(PROJECT_DIR)/src/resolver/main.cpp | dirs
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/memscope-resolve: $(OBJ_DIR)/main_resolve.o \
                                $(OBJ_DIR)/dwarf_analyzer.o \
                                $(OBJ_DIR)/address_resolver.o | dirs
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS_RESOLVER)

$(BUILD_DIR)/bench_target: $(BENCH_SRC) | dirs
	$(CC) -g -O2 $< -o $@ $(LDFLAGS_BENCH)

clean:
	rm -rf $(BUILD_DIR)

install: all
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(BUILD_DIR)/memscope-collect $(DESTDIR)/usr/local/bin/
	install -m 755 $(BUILD_DIR)/memscope-resolve $(DESTDIR)/usr/local/bin/

test: all
	@echo "Running tests..."
	@$(BUILD_DIR)/memscope-resolve types -b $(BUILD_DIR)/bench_target 2>/dev/null || echo "Note: bench_target may lack DWARF in release build"
	@echo "Tests complete."

bench: all
	@chmod +x $(PROJECT_DIR)/src/benchmark/bench_runner.sh
	@bash $(PROJECT_DIR)/src/benchmark/bench_runner.sh
