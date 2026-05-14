#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
BPF_OBJ="$BUILD_DIR/src/bpf/memscope.bpf.o"
BENCH_V2="$BUILD_DIR/src/benchmark/bench_target_v2"
RESOLVE="$BUILD_DIR/src/resolver/memscope-resolve"
COLLECT="$BUILD_DIR/src/collector/memscope-collect"
RESULTS_DIR="$PROJECT_DIR/results_v2"

mkdir -p "$RESULTS_DIR"

BOLD='\033[1m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
DIM='\033[2m'
RESET='\033[0m'

PASS=0
FAIL=0
SKIP=0
WARN=0

step() { echo -e "\n${BOLD}${CYAN}=== $1 ===${RESET}\n"; }
ok()   { echo -e "  ${GREEN}PASS${RESET} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${RESET} $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}WARN${RESET} $1"; WARN=$((WARN + 1)); }
skip() { echo -e "  ${DIM}SKIP${RESET} $1"; SKIP=$((SKIP + 1)); }
info() { echo -e "  ${CYAN}INFO${RESET} $1"; }

check_count() {
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" -eq "$expected" ]; then
        ok "$label: expected=$expected, got=$actual"
    else
        fail "$label: expected=$expected, got=$actual"
    fi
}

check_at_least() {
    local label="$1" actual="$2" minimum="$3"
    if [ "$actual" -ge "$minimum" ]; then
        ok "$label: >=$minimum, got=$actual"
    else
        fail "$label: >=$minimum, got=$actual"
    fi
}

check_type_inference() {
    local alloc_addr="$1" expected_type="$2" csv="$3"
    local actual_type
    actual_type=$(awk -F, -v addr="$alloc_addr" '$1==addr {print $4}' "$csv" | head -1)
    if [ "$actual_type" = "$expected_type" ]; then
        ok "addr=$alloc_addr type=$expected_type"
    else
        fail "addr=$alloc_addr expected=$expected_type got=$actual_type"
    fi
}

check_infer_method() {
    local alloc_addr="$1" expected_method_prefix="$2" csv="$3"
    local actual_method
    actual_method=$(awk -F, -v addr="$alloc_addr" '$1==addr {print $9}' "$csv" | head -1)
    if echo "$actual_method" | grep -q "^${expected_method_prefix}"; then
        ok "addr=$alloc_addr method=$actual_method"
    else
        fail "addr=$alloc_addr expected_method~${expected_method_prefix} got=$actual_method"
    fi
}

check_region() {
    local alloc_addr="$1" expected_region="$2" csv="$3"
    local actual_region
    actual_region=$(awk -F, -v addr="$alloc_addr" '$1==addr {print $3}' "$csv" | head -1)
    if [ "$actual_region" = "$expected_region" ]; then
        ok "addr=$alloc_addr region=$expected_region"
    else
        fail "addr=$alloc_addr expected_region=$expected_region got=$actual_region"
    fi
}

step "Step 1: Build project"
mkdir -p "$BUILD_DIR"
cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug 2>&1 | tail -3
cmake --build "$BUILD_DIR" -j"$(nproc)" 2>&1 | tail -5

if [ ! -f "$BENCH_V2" ]; then
    echo -e "${RED}Error: bench_target_v2 not found at $BENCH_V2${RESET}"
    exit 1
fi

if [ ! -f "$RESOLVE" ]; then
    echo -e "${RED}Error: memscope-resolve not found at $RESOLVE${RESET}"
    exit 1
fi

step "Step 2: Verify DWARF type information"
TYPE_OUTPUT=$($RESOLVE types -b "$BENCH_V2" 2>/dev/null)

EXPECTED_TYPES="Point Node Buffer Vec3 Color Counter Pair Matrix4x4 Student LinkedList HashMapEntry SensorReading PacketHeader Task Config Vertex Edge Token Rectangle Circle Triangle GlobalState"
for t in $EXPECTED_TYPES; do
    if echo "$TYPE_OUTPUT" | grep -q "$t"; then
        ok "DWARF type found: $t"
    else
        fail "DWARF type missing: $t"
    fi
done

step "Step 3: Verify struct layouts"
LAYOUT_POINT=$($RESOLVE layout -b "$BENCH_V2" -t Point 2>/dev/null)
if echo "$LAYOUT_POINT" | grep -q "x" && echo "$LAYOUT_POINT" | grep -q "y" && echo "$LAYOUT_POINT" | grep -q "label"; then
    ok "Point layout: x, y, label fields present"
else
    fail "Point layout: missing expected fields"
    echo "$LAYOUT_POINT"
fi

LAYOUT_NODE=$($RESOLVE layout -b "$BENCH_V2" -t Node 2>/dev/null)
if echo "$LAYOUT_NODE" | grep -q "left" && echo "$LAYOUT_NODE" | grep -q "value" && echo "$LAYOUT_NODE" | grep -q "name"; then
    ok "Node layout: left, value, name fields present"
else
    fail "Node layout: missing expected fields"
fi

LAYOUT_GSTATE=$($RESOLVE layout -b "$BENCH_V2" -t GlobalState 2>/dev/null)
if echo "$LAYOUT_GSTATE" | grep -q "origin" && echo "$LAYOUT_GSTATE" | grep -q "counter"; then
    ok "GlobalState layout: origin, counter nested fields present"
else
    fail "GlobalState layout: missing nested fields"
fi

LAYOUT_PACKET=$($RESOLVE layout -b "$BENCH_V2" -t PacketHeader 2>/dev/null)
if echo "$LAYOUT_PACKET" | grep -q "src_addr" && echo "$LAYOUT_PACKET" | grep -q "dst_port"; then
    ok "PacketHeader layout: src_addr, dst_port present"
else
    fail "PacketHeader layout: missing fields"
fi

step "Step 4: Verify global symbols"
SYMBOL_OUTPUT=$($RESOLVE symbols -b "$BENCH_V2" -n g_ 2>/dev/null)

EXPECTED_GLOBALS="g_state g_identity g_default_packet g_last_reading g_app_config g_global_int g_global_double g_global_str"
for sym in $EXPECTED_GLOBALS; do
    if echo "$SYMBOL_OUTPUT" | grep -q "$sym"; then
        ok "Global symbol found: $sym"
    else
        fail "Global symbol missing: $sym"
    fi
done

step "Step 5: Collect allocations with eBPF (8 seconds)"
warn "Requires root for eBPF..."

sudo $COLLECT -p 0 -b "$BENCH_V2" -B "$BPF_OBJ" -d 8 -o "$RESULTS_DIR/v2_allocs.csv" &
COLLECT_PID=$!
info "Collector PID: $COLLECT_PID"

sleep 2

$BENCH_V2 &
BENCH_PID=$!
info "Benchmark PID: $BENCH_PID"

wait $BENCH_PID 2>/dev/null || true
info "Benchmark done."

sleep 1
sudo kill $COLLECT_PID 2>/dev/null || true
wait $COLLECT_PID 2>/dev/null || true
info "Collector finished."

if [ ! -f "$RESULTS_DIR/v2_allocs.csv" ]; then
    echo -e "${RED}No CSV file generated!${RESET}"
    exit 1
fi

TOTAL_ALLOCS=$(tail -n +2 "$RESULTS_DIR/v2_allocs.csv" | wc -l)
info "Total allocation records: $TOTAL_ALLOCS"

head -1 "$RESULTS_DIR/v2_allocs.csv" > "$RESULTS_DIR/v2_filtered.csv"
awk -F, -v pid="$BENCH_PID" 'NR>1 && $3==pid' "$RESULTS_DIR/v2_allocs.csv" >> "$RESULTS_DIR/v2_filtered.csv"
FILTERED_ALLOCS=$(tail -n +2 "$RESULTS_DIR/v2_filtered.csv" | wc -l)
info "Filtered to $FILTERED_ALLOCS records for PID $BENCH_PID"

if [ "$FILTERED_ALLOCS" -eq 0 ]; then
    warn "No allocations captured for bench PID, using all records"
    cp "$RESULTS_DIR/v2_allocs.csv" "$RESULTS_DIR/v2_filtered.csv"
    FILTERED_ALLOCS=$TOTAL_ALLOCS
fi

step "Step 6: Batch resolve all addresses"
$RESOLVE batch -b "$BENCH_V2" -f "$RESULTS_DIR/v2_filtered.csv" -o "$RESULTS_DIR/v2_resolved.csv" 2>&1 | tail -3

if [ ! -f "$RESULTS_DIR/v2_resolved.csv" ]; then
    echo -e "${RED}No resolved CSV generated!${RESET}"
    exit 1
fi

TOTAL_RESOLVED=$(tail -n +2 "$RESULTS_DIR/v2_resolved.csv" | wc -l)
info "Total resolved records: $TOTAL_RESOLVED"

step "Step 7: Verify HEAP type inference rates"

HEAP_COUNT=$(awk -F, 'NR>1 && $3=="HEAP" {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
HEAP_TYPED=$(awk -F, 'NR>1 && $3=="HEAP" && $4!="" {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
HEAP_SOURCE_TEXT=$(awk -F, 'NR>1 && $3=="HEAP" && $9~/source_text/ {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
HEAP_CALLSITE_PC=$(awk -F, 'NR>1 && $3=="HEAP" && $9~/callsite_pc/ {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
HEAP_CALLSITE_FUNC=$(awk -F, 'NR>1 && $3=="HEAP" && $9~/callsite_func/ {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
HEAP_SIZE_MATCH=$(awk -F, 'NR>1 && $3=="HEAP" && $9~/size_match/ {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
HEAP_AMBIGUOUS=$(awk -F, 'NR>1 && $3=="HEAP" && ($9~/ambiguous/ || $10~/ambiguous/) {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
HEAP_UNKNOWN=$(awk -F, 'NR>1 && $3=="HEAP" && $4=="" {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")

echo ""
echo "  HEAP Inference Breakdown:"
echo "  ┌──────────────────────────────────────────┐"
echo "  │ Total HEAP allocations:    $HEAP_COUNT"
echo "  │ Typed (any method):        $HEAP_TYPED"
echo "  │   source_text:             $HEAP_SOURCE_TEXT"
echo "  │   callsite_pc:             $HEAP_CALLSITE_PC"
echo "  │   callsite_func:           $HEAP_CALLSITE_FUNC"
echo "  │   size_match:              $HEAP_SIZE_MATCH"
echo "  │ Ambiguous:                 $HEAP_AMBIGUOUS"
echo "  │ Unknown (no type):         $HEAP_UNKNOWN"
echo "  └──────────────────────────────────────────┘"
echo ""

TYPED_RATE=0
if [ "$HEAP_COUNT" -gt 0 ]; then
    TYPED_RATE=$(awk "BEGIN {printf \"%.1f\", $HEAP_TYPED * 100.0 / $HEAP_COUNT}")
fi
info "Type inference rate: ${TYPED_RATE}%"

TYPENAME_RATE=0
if [ "$HEAP_COUNT" -gt 0 ]; then
    TYPENAME_TOTAL=$((HEAP_SOURCE_TEXT + HEAP_CALLSITE_PC + HEAP_CALLSITE_FUNC))
    TYPENAME_RATE=$(awk "BEGIN {printf \"%.1f\", $TYPENAME_TOTAL * 100.0 / $HEAP_COUNT}")
fi
info "Typename-based inference rate: ${TYPENAME_RATE}% (source_text + callsite_pc + callsite_func)"

if [ "$HEAP_COUNT" -gt 0 ]; then
    check_at_least "HEAP typed allocations" "$HEAP_TYPED" 1

    if [ "$HEAP_SOURCE_TEXT" -gt 0 ]; then
        ok "source_text method is working ($HEAP_SOURCE_TEXT allocations)"
    else
        warn "No source_text method detected — addr2line may not be working"
    fi

    if [ "$HEAP_CALLSITE_PC" -gt 0 ]; then
        ok "callsite_pc method is working ($HEAP_CALLSITE_PC allocations)"
    else
        warn "No callsite_pc method detected — DWARF pointer analysis may not be working"
    fi
else
    skip "No HEAP allocations captured"
fi

step "Step 8: Verify specific type inferences"

TYPED_ROWS=$(awk -F, 'NR>1 && $3=="HEAP" && $4!=""' "$RESULTS_DIR/v2_resolved.csv")

VERIFY_TYPES="Point Node Buffer Student Task SensorReading Edge Token Vertex LinkedList HashMapEntry Matrix4x4 PacketHeader Config Vec3 Color Counter Pair Rectangle Circle Triangle"
for t in $VERIFY_TYPES; do
    COUNT=$(echo "$TYPED_ROWS" | awk -F, -v t="$t" '$4==t {count++} END {print count+0}')
    if [ "$COUNT" -gt 0 ]; then
        ok "Type '$t' correctly inferred ($COUNT allocations)"
    else
        COUNT_FUZZY=$(echo "$TYPED_ROWS" | awk -F, -v t="$t" '$4~t {count++} END {print count+0}')
        if [ "$COUNT_FUZZY" -gt 0 ]; then
            warn "Type '$t' partially matched ($COUNT_FUZZY allocations, may have suffix)"
        else
            fail "Type '$t' not inferred at all"
        fi
    fi
done

step "Step 9: Verify same-size type disambiguation"

SAME_SIZE_PAIRS="Vec3:Color Counter:Pair Rectangle:Circle"
for pair in $SAME_SIZE_PAIRS; do
    T1="${pair%%:*}"
    T2="${pair##*:}"

    C1=$(echo "$TYPED_ROWS" | awk -F, -v t="$T1" '$4==t {count++} END {print count+0}')
    C2=$(echo "$TYPED_ROWS" | awk -F, -v t="$T2" '$4==t {count++} END {print count+0}')

    if [ "$C1" -gt 0 ] && [ "$C2" -gt 0 ]; then
        ok "Same-size pair ($T1/$T2) both correctly distinguished (C1=$C1, C2=$C2)"
    elif [ "$C1" -gt 0 ] || [ "$C2" -gt 0 ]; then
        warn "Same-size pair ($T1/$T2) partially distinguished (C1=$C1, C2=$C2)"
    else
        fail "Same-size pair ($T1/$T2) neither type inferred"
    fi
done

step "Step 10: Verify array allocation detection"

ARRAY_TYPES="Point Node SensorReading Edge Token Matrix4x4 PacketHeader Vertex Vec3 Color"
for t in $ARRAY_TYPES; do
    ARRAY_COUNT=$(echo "$TYPED_ROWS" | awk -F, -v t="$t" '$4==t && $6~/array/ {count++} END {print count+0}')
    TOTAL_COUNT=$(echo "$TYPED_ROWS" | awk -F, -v t="$t" '$4==t {count++} END {print count+0}')
    if [ "$ARRAY_COUNT" -gt 0 ]; then
        ok "Type '$t' has array allocations detected ($ARRAY_COUNT/$TOTAL_COUNT)"
    elif [ "$TOTAL_COUNT" -gt 0 ]; then
        warn "Type '$t' has allocations but no array detection ($TOTAL_COUNT total)"
    fi
done

step "Step 11: Verify field resolution"

FIELDS_RESOLVED=$(awk -F, 'NR>1 && $3=="HEAP" && $5!="" {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
info "Total field-level resolutions: $FIELDS_RESOLVED"

if [ "$FIELDS_RESOLVED" -gt 0 ]; then
    ok "Field resolution is working ($FIELDS_RESOLVED records with field info)"

    EXPECTED_FIELDS="x y z label weight left right value score name capacity length data flags refcount id gpa age major"
    for f in $EXPECTED_FIELDS; do
        FCOUNT=$(awk -F, -v f="$f" 'NR>1 && $3=="HEAP" && $5~f {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
        if [ "$FCOUNT" -gt 0 ]; then
            ok "Field '$f' resolved ($FCOUNT times)"
        fi
    done
else
    warn "No field-level resolutions found"
fi

step "Step 12: Verify global variable resolution"

GLOBAL_COUNT=$(awk -F, 'NR>1 && $3=="GLOBAL" {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
info "GLOBAL region records: $GLOBAL_COUNT"

if [ "$GLOBAL_COUNT" -gt 0 ]; then
    ok "Global variables detected in GLOBAL region ($GLOBAL_COUNT records)"

    GLOBAL_TYPES=$(awk -F, 'NR>1 && $3=="GLOBAL" && $4!="" {print $4}' "$RESULTS_DIR/v2_resolved.csv" | sort -u)
    info "Global types found: $(echo $GLOBAL_TYPES | tr '\n' ' ')"

    for gt in GlobalState Matrix4x4 PacketHeader SensorReading Config; do
        if echo "$GLOBAL_TYPES" | grep -q "$gt"; then
            ok "Global type '$gt' resolved"
        else
            warn "Global type '$gt' not resolved (may not have been captured as allocation)"
        fi
    done
else
    warn "No GLOBAL region records — globals are accessed, not allocated via malloc"
    info "Note: Global variables appear as symbols, not in allocation CSV"
    info "Testing global resolution via lookup command..."

    GSTATE_ADDR=$($RESOLVE symbols -b "$BENCH_V2" -n g_state 2>/dev/null | awk '{print $1}' | head -1)
    if [ -n "$GSTATE_ADDR" ]; then
        info "g_state symbol address: $GSTATE_ADDR"
        GSTATE_RESULT=$($RESOLVE resolve -b "$BENCH_V2" -a "$GSTATE_ADDR" 2>/dev/null)
        if echo "$GSTATE_RESULT" | grep -qi "GlobalState\|GLOBAL"; then
            ok "g_state resolved as GlobalState via symbol lookup"
        else
            warn "g_state not resolved as GlobalState"
        fi
    else
        warn "g_state symbol not found"
    fi
fi

step "Step 13: Verify inference method distribution"

echo ""
echo "  Inference Method Distribution:"
awk -F, 'NR>1 && $3=="HEAP" && $9!="" {print $9}' "$RESULTS_DIR/v2_resolved.csv" | sort | uniq -c | sort -rn | while read count method; do
    printf "    %-30s %s\n" "$method" "$count"
done

echo ""
echo "  Confidence Distribution:"
awk -F, 'NR>1 && $3=="HEAP" && $10!="" {print $10}' "$RESULTS_DIR/v2_resolved.csv" | sort | uniq -c | sort -rn | while read count conf; do
    printf "    %-30s %s\n" "$conf" "$count"
done

step "Step 14: Verify untyped/raw allocations"

RAW_COUNT=$(awk -F, 'NR>1 && $3=="HEAP" && $4=="" {count++} END {print count+0}' "$RESULTS_DIR/v2_resolved.csv")
info "Untyped HEAP allocations: $RAW_COUNT"

if [ "$RAW_COUNT" -gt 0 ]; then
    ok "Untyped allocations exist (expected for void*/raw malloc) — $RAW_COUNT records"
    RAW_SIZES=$(awk -F, 'NR>1 && $3=="HEAP" && $4=="" {print $2}' "$RESULTS_DIR/v2_resolved.csv" | sort -n | uniq -c | sort -rn | head -5)
    info "Untyped allocation sizes:\n$RAW_SIZES"
fi

step "Step 15: Cross-check — source_text vs DWARF consistency"

if [ "$HEAP_SOURCE_TEXT" -gt 0 ] && [ "$HEAP_CALLSITE_PC" -gt 0 ]; then
    ok "Both source_text and callsite_pc methods are active — cross-validation possible"

    SOURCE_TEXT_TYPES=$(awk -F, 'NR>1 && $3=="HEAP" && $9~/source_text/ {print $4}' "$RESULTS_DIR/v2_resolved.csv" | sort -u)
    CALLSITE_PC_TYPES=$(awk -F, 'NR>1 && $3=="HEAP" && $9~/callsite_pc/ {print $4}' "$RESULTS_DIR/v2_resolved.csv" | sort -u)

    info "source_text types: $(echo $SOURCE_TEXT_TYPES | tr '\n' ' ')"
    info "callsite_pc types: $(echo $CALLSITE_PC_TYPES | tr '\n' ' ')"

    CONFLICT=0
    for t in $SOURCE_TEXT_TYPES; do
        if echo "$CALLSITE_PC_TYPES" | grep -q "$t"; then
            ok "Type '$t' confirmed by both methods"
        else
            warn "Type '$t' only from source_text, not from callsite_pc"
        fi
    done
else
    warn "Cannot cross-validate — need both source_text and callsite_pc methods active"
fi

step "Step 16: Summary report"

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║     MemScope V2 Verification Results         ║"
echo "  ╠══════════════════════════════════════════════╣"
printf "  ║  PASS: %-5d                                ║\n" "$PASS"
printf "  ║  FAIL: %-5d                                ║\n" "$FAIL"
printf "  ║  WARN: %-5d                                ║\n" "$WARN"
printf "  ║  SKIP: %-5d                                ║\n" "$SKIP"
echo "  ╠══════════════════════════════════════════════╣"
printf "  ║  HEAP type inference rate: %-6s            ║\n" "${TYPED_RATE}%"
printf "  ║  Typename-based rate:      %-6s            ║\n" "${TYPENAME_RATE}%"
printf "  ║  Total HEAP allocations:   %-6d            ║\n" "$HEAP_COUNT"
printf "  ║  Field resolutions:        %-6d            ║\n" "$FIELDS_RESOLVED"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}VERIFICATION FAILED: $FAIL checks failed${RESET}"
    exit 1
else
    echo -e "${GREEN}ALL CHECKS PASSED!${RESET}"
    exit 0
fi
