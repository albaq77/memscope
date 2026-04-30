#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
BENCH_TARGET="$BUILD_DIR/bench_target"
MEMSCOPE="$BUILD_DIR/memscope-collect"
BPF_OBJ="$BUILD_DIR/memscope.bpf.o"
RESULTS_DIR="$PROJECT_DIR/results"
DURATION=10

mkdir -p "$RESULTS_DIR"

info() { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
err()  { echo -e "\033[1;31m[-]\033[0m $*"; }

check_prereqs() {
    local missing=0
    for cmd in cmake clang; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Missing: $cmd"
            missing=1
        fi
    done
    if [ "$missing" -eq 1 ]; then
        err "Install missing dependencies and try again"
        exit 1
    fi
}

build_project() {
    info "Building MemScope project with CMake..."
    cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug
    cmake --build "$BUILD_DIR" -j"$(nproc)"
    ok "Build complete"
}

run_benchmark() {
    local bench_name="$1"
    local bench_id="$2"
    local output_file="$RESULTS_DIR/${bench_name}.csv"

    info "Running benchmark: $bench_name"

    $MEMSCOPE -p 0 -b "$BENCH_TARGET" -B "$BPF_OBJ" -d 30 -o "$output_file" &
    local memscope_pid=$!
    sleep 2

    $BENCH_TARGET "$bench_id" &
    local bench_pid=$!

    wait "$bench_pid" 2>/dev/null || true
    sleep 1

    kill "$memscope_pid" 2>/dev/null || true
    wait "$memscope_pid" 2>/dev/null || true

    if [ -f "$output_file" ]; then
        local alloc_count
        alloc_count=$(wc -l < "$output_file")
        ok "Captured $((alloc_count - 1)) allocation records -> $output_file"
    else
        err "No output file generated"
    fi
}

run_all_benchmarks() {
    info "Running all benchmarks..."

    local benches=(
        "point_alloc:1"
        "tree_alloc:2"
        "buffer_alloc:3"
        "packet_alloc:4"
        "mixed_alloc:5"
        "sequential_access:6"
        "random_access:7"
    )

    for bench in "${benches[@]}"; do
        local name="${bench%%:*}"
        local id="${bench##*:}"
        run_benchmark "$name" "$id"
        echo ""
    done
}

generate_report() {
    local report_file="$RESULTS_DIR/report.txt"

    info "Generating report..."

    {
        echo "========================================="
        echo "  MemScope Benchmark Report"
        echo "  Date: $(date)"
        echo "========================================="
        echo ""

        for csv in "$RESULTS_DIR"/*.csv; do
            [ -f "$csv" ] || continue
            local bench_name
            bench_name=$(basename "$csv" .csv)
            local total_lines
            total_lines=$(wc -l < "$csv")
            local live_count
            live_count=$(awk -F, 'NR>1 && $5=="1" {count++} END {print count+0}' "$csv")
            local total_size
            total_size=$(awk -F, 'NR>1 && $5=="1" {sum+=$2} END {print sum+0}' "$csv")

            echo "Benchmark: $bench_name"
            echo "  Total allocations: $((total_lines - 1))"
            echo "  Live at end:       $live_count"
            echo "  Total live bytes:  $total_size"
            echo ""
        done

        echo "========================================="
        echo "  End of Report"
        echo "========================================="
    } > "$report_file"

    ok "Report saved to $report_file"
    cat "$report_file"
}

main() {
    info "MemScope Benchmark Runner (CMake)"
    info "=================================="

    check_prereqs

    if [ "${1:-}" = "build" ]; then
        build_project
        exit 0
    fi

    build_project
    run_all_benchmarks
    generate_report

    ok "All benchmarks complete!"
}

main "$@"
