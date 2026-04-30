#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
BPF_OBJ="$BUILD_DIR/src/bpf/memscope.bpf.o"
BENCH_TARGET="$BUILD_DIR/src/benchmark/bench_target"
RESOLVE="$BUILD_DIR/src/resolver/memscope-resolve"
COLLECT="$BUILD_DIR/src/collector/memscope-collect"
RESULTS_DIR="$PROJECT_DIR/results"

mkdir -p "$RESULTS_DIR"

BOLD='\033[1m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
RESET='\033[0m'

step() { echo -e "\n${BOLD}${CYAN}=== $1 ===${RESET}\n"; }
ok()   { echo -e "${GREEN}$1${RESET}"; }
warn() { echo -e "${YELLOW}$1${RESET}"; }

step "Step 1: Build with CMake"
if [ ! -f "$COLLECT" ]; then
    mkdir -p "$BUILD_DIR"
    cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug
    cmake --build "$BUILD_DIR" -j"$(nproc)"
fi

step "Step 2: View struct types in bench_target"
$RESOLVE types -b "$BENCH_TARGET" 2>/dev/null || warn "DWARF parse failed"

step "Step 3: View struct layouts"
$RESOLVE layout -b "$BENCH_TARGET" -t Point 2>/dev/null || true
$RESOLVE layout -b "$BENCH_TARGET" -t Node 2>/dev/null || true
$RESOLVE layout -b "$BENCH_TARGET" -t Buffer 2>/dev/null || true
$RESOLVE layout -b "$BENCH_TARGET" -t Packet 2>/dev/null || true

step "Step 4: Run eBPF collector to capture allocations"
warn "Requires root for eBPF..."
sudo $COLLECT -p 0 -b "$BENCH_TARGET" -B "$BPF_OBJ" -d 60 -o "$RESULTS_DIR/demo_allocs.csv" &
COLLECT_PID=$!
sleep 2

$BENCH_TARGET 1
BENCH_PID=$!
echo "Benchmark PID: $BENCH_PID"

wait $BENCH_PID 2>/dev/null || true
echo "Benchmark done."

sleep 1
sudo kill $COLLECT_PID 2>/dev/null || true
wait $COLLECT_PID 2>/dev/null || true
echo "Collector finished."

step "Step 5: View captured allocations"
if [ -f "$RESULTS_DIR/demo_allocs.csv" ]; then
    echo "CSV (first 10 lines):"
    head -11 "$RESULTS_DIR/demo_allocs.csv"
    echo ""

    TOTAL=$(tail -n +2 "$RESULTS_DIR/demo_allocs.csv" | wc -l)
    LIVE=$(tail -n +2 "$RESULTS_DIR/demo_allocs.csv" | awk -F, '$5=="1"' | wc -l)
    ok "Total $TOTAL allocation records, $LIVE still live"
else
    echo -e "${RED}No CSV file generated${RESET}"
    exit 1
fi

step "Step 6: Batch resolve all addresses to struct fields"
$RESOLVE batch -b "$BENCH_TARGET" -f "$RESULTS_DIR/demo_allocs.csv" -o "$RESULTS_DIR/demo_resolved.csv"
echo ""

step "Step 7: View resolved results"
if [ -f "$RESULTS_DIR/demo_resolved.csv" ]; then
    echo "Resolved (first 20 lines):"
    head -21 "$RESULTS_DIR/demo_resolved.csv"
    echo ""

    WITH_FIELD=$(tail -n +2 "$RESULTS_DIR/demo_resolved.csv" | awk -F, '$5!=""' | wc -l)
    ok "$WITH_FIELD records matched to specific fields"
fi

step "Done!"
