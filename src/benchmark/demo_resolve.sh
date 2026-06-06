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
mkdir -p "$BUILD_DIR"
cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug
cmake --build "$BUILD_DIR" -j"$(nproc)"

if [ ! -f "$BENCH_TARGET" ]; then
    echo -e "${RED}Error: bench_target not found at $BENCH_TARGET${RESET}"
    echo "Looking for bench_target in build directory..."
    FOUND=$(find "$BUILD_DIR" -name "bench_target" -type f 2>/dev/null | head -1)
    if [ -n "$FOUND" ]; then
        BENCH_TARGET="$FOUND"
        ok "Found bench_target at: $BENCH_TARGET"
    else
        echo -e "${RED}bench_target not found anywhere in build directory!${RESET}"
        exit 1
    fi
fi

if [ ! -f "$RESOLVE" ]; then
    echo -e "${RED}Error: memscope-resolve not found at $RESOLVE${RESET}"
    exit 1
fi

step "Step 2: View struct types in bench_target"
$RESOLVE types -b "$BENCH_TARGET" 2>/dev/null || warn "DWARF parse failed"

step "Step 3: View struct layouts"
$RESOLVE layout -b "$BENCH_TARGET" -t Point 2>/dev/null || true
$RESOLVE layout -b "$BENCH_TARGET" -t Node 2>/dev/null || true
$RESOLVE layout -b "$BENCH_TARGET" -t Buffer 2>/dev/null || true
$RESOLVE layout -b "$BENCH_TARGET" -t Packet 2>/dev/null || true
$RESOLVE layout -b "$BENCH_TARGET" -t Vec3 2>/dev/null || true
$RESOLVE layout -b "$BENCH_TARGET" -t Color 2>/dev/null || true

step "Step 4: Run eBPF collector to capture allocations (5 seconds)"
warn "Requires root for eBPF..."

sudo $COLLECT -p 0 -b "$BENCH_TARGET" -B "$BPF_OBJ" -d 5 -o "$RESULTS_DIR/demo_allocs.csv" &
COLLECT_PID=$!
echo "Collector PID: $COLLECT_PID"

sleep 2

$BENCH_TARGET 1 10000 &
BENCH_PID=$!
echo "Benchmark PID: $BENCH_PID (running test 1: basic allocations, 10000 iterations)"

wait $BENCH_PID 2>/dev/null || true
echo "Benchmark done."

sleep 1
sudo kill $COLLECT_PID 2>/dev/null || true
wait $COLLECT_PID 2>/dev/null || true
echo "Collector finished."

step "Step 5: View captured allocations"
if [ -f "$RESULTS_DIR/demo_allocs.csv" ]; then
    TOTAL=$(tail -n +2 "$RESULTS_DIR/demo_allocs.csv" | wc -l)
    ok "Total $TOTAL allocation records (all processes)"
    
    if [ -n "$BENCH_PID" ]; then
        head -1 "$RESULTS_DIR/demo_allocs.csv" > "$RESULTS_DIR/demo_filtered.csv"
        awk -F, -v pid="$BENCH_PID" 'NR>1 && $3==pid' "$RESULTS_DIR/demo_allocs.csv" >> "$RESULTS_DIR/demo_filtered.csv"
        FILTERED=$(tail -n +2 "$RESULTS_DIR/demo_filtered.csv" | wc -l)
        ok "Filtered to $FILTERED records for PID $BENCH_PID"
        echo ""
        
        echo "CSV (first 10 lines):"
        head -11 "$RESULTS_DIR/demo_filtered.csv"
        echo ""
    else
        echo "CSV (first 10 lines):"
        head -11 "$RESULTS_DIR/demo_allocs.csv"
        echo ""
        cp "$RESULTS_DIR/demo_allocs.csv" "$RESULTS_DIR/demo_filtered.csv"
    fi
else
    echo -e "${RED}No CSV file generated${RESET}"
    exit 1
fi

step "Step 6: Batch resolve all addresses to struct fields"
$RESOLVE batch -b "$BENCH_TARGET" -f "$RESULTS_DIR/demo_filtered.csv" -o "$RESULTS_DIR/demo_resolved.csv"
echo ""

step "Step 7: View resolved results"
if [ -f "$RESULTS_DIR/demo_resolved.csv" ]; then
    echo "Resolved (first 20 lines):"
    head -21 "$RESULTS_DIR/demo_resolved.csv"
    echo ""

    WITH_FIELD=$(tail -n +2 "$RESULTS_DIR/demo_resolved.csv" | awk -F, '$5!=""' | wc -l)
    ok "$WITH_FIELD records matched to specific fields"
    echo ""
    
    echo "Inference methods:"
    awk -F, 'NR>1 {print $9}' "$RESULTS_DIR/demo_resolved.csv" | sort | uniq -c | sort -rn | head -10
    echo ""
    
    SOURCE_TEXT=$(grep -c "source_text" "$RESULTS_DIR/demo_resolved.csv" 2>/dev/null || echo "0")
    SIZE_MATCH=$(grep -c "size_match" "$RESULTS_DIR/demo_resolved.csv" 2>/dev/null || echo "0")
    AMBIGUOUS=$(grep -c "(ambiguous)" "$RESULTS_DIR/demo_resolved.csv" 2>/dev/null || echo "0")
    
    echo "Summary:"
    echo "  source_text: $SOURCE_TEXT"
    echo "  size_match:  $SIZE_MATCH"
    echo "  ambiguous:   $AMBIGUOUS"
    echo ""
    
    if [ "$SOURCE_TEXT" -gt 0 ]; then
        ok "addr2line type inference is working!"
        echo ""
        echo "Examples:"
        grep "source_text" "$RESULTS_DIR/demo_resolved.csv" | head -5 | cut -d',' -f1-9
    else
        warn "No source_text method detected"
    fi
fi

step "Done!"
