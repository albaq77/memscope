#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
BPF_OBJ="$BUILD_DIR/memscope.bpf.o"
BENCH_TARGET="$BUILD_DIR/bench_target"
RESOLVE="$BUILD_DIR/memscope-resolve"
COLLECT="$BUILD_DIR/memscope-collect"
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

step "Step 1: 查看 bench_target 中的 struct 类型"
$RESOLVE types -b "$BENCH_TARGET" 2>/dev/null || warn "DWARF 解析失败，请确认 -g 编译"

step "Step 2: 查看 struct Point 的字段布局"
$RESOLVE layout -b "$BENCH_TARGET" -t Point 2>/dev/null || true

step "Step 3: 查看 struct Node 的字段布局"
$RESOLVE layout -b "$BENCH_TARGET" -t Node 2>/dev/null || true

step "Step 4: 查看 struct Buffer 的字段布局"
$RESOLVE layout -b "$BENCH_TARGET" -t Buffer 2>/dev/null || true

step "Step 5: 查看 struct Packet 的字段布局"
$RESOLVE layout -b "$BENCH_TARGET" -t Packet 2>/dev/null || true

step "Step 6: 运行 eBPF collector 捕获内存分配"
warn "需要 root 权限运行 eBPF..."
echo "先启动 collector (全局 uprobe), 再启动 benchmark..."

sudo $COLLECT -p 0 -b "$BENCH_TARGET" -B "$BPF_OBJ" -d 60 -o "$RESULTS_DIR/demo_allocs.csv" &
COLLECT_PID=$!
sleep 3

$BENCH_TARGET 1
BENCH_PID=$!
echo "Benchmark PID: $BENCH_PID"

wait $BENCH_PID 2>/dev/null || true
echo "Benchmark done."

sudo kill $COLLECT_PID 2>/dev/null || true
wait $COLLECT_PID 2>/dev/null || true
echo "Collector finished."

step "Step 7: 查看捕获的分配记录"
if [ -f "$RESULTS_DIR/demo_allocs.csv" ]; then
    echo "CSV 内容 (前 10 行):"
    head -11 "$RESULTS_DIR/demo_allocs.csv"
    echo ""

    TOTAL=$(tail -n +2 "$RESULTS_DIR/demo_allocs.csv" | wc -l)
    LIVE=$(tail -n +2 "$RESULTS_DIR/demo_allocs.csv" | awk -F, '$5=="1"' | wc -l)
    ok "共 $TOTAL 条分配记录, 其中 $LIVE 条仍活跃"
else
    echo -e "${RED}未生成 CSV 文件${RESET}"
    exit 1
fi

step "Step 8: 批量解析所有地址到 struct 字段"
warn "使用 batch 命令一次加载 DWARF，批量解析所有地址..."
$RESOLVE batch -b "$BENCH_TARGET" -f "$RESULTS_DIR/demo_allocs.csv" -o "$RESULTS_DIR/demo_resolved.csv"
echo ""

step "Step 9: 查看解析结果"
if [ -f "$RESULTS_DIR/demo_resolved.csv" ]; then
    echo "解析结果 (前 15 行):"
    head -16 "$RESULTS_DIR/demo_resolved.csv"
    echo ""

    WITH_FIELD=$(tail -n +2 "$RESULTS_DIR/demo_resolved.csv" | awk -F, '$5!=""' | wc -l)
    ok "共 $WITH_FIELD 条记录匹配到了具体字段"
fi

step "完成!"
echo "总结:"
echo "  1. eBPF 捕获 malloc 返回的地址和 size"
echo "  2. DWARF 解析 struct 的字段名和偏移量"
echo "  3. 地址解析器: addr - base_addr = offset → 查找 struct 中该 offset 的字段"
echo ""
echo "示例映射关系 (struct Point, size=40):"
echo "  malloc(40) 返回 base_addr, 那么:"
echo "    base_addr + 0  = Point.x      (double)"
echo "    base_addr + 8  = Point.y      (double)"
echo "    base_addr + 16 = Point.z      (double)"
echo "    base_addr + 24 = Point.label  (int)"
echo "    base_addr + 32 = Point.weight (double)"
