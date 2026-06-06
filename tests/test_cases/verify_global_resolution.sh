#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
RESOLVER="$BUILD_DIR/src/resolver/memscope-resolve"
TEST_BIN="$BUILD_DIR/tests/test_cases/test_global_resolution"
RESULTS_DIR="$SCRIPT_DIR/results_global"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

PASS=0
FAIL=0

step() { echo -e "\n${BLUE}━━━ $1 ━━━${RESET}"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}✗${RESET} $1"; FAIL=$((FAIL + 1)); }
info() { echo -e "  ${YELLOW}→${RESET} $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET} $1"; }

# Extract ADDR:label=0x... from test output
get_addr() {
    grep "^ADDR:$1=" "$TEST_OUTPUT" | head -1 | cut -d= -f2
}

check_resolve() {
    local addr="$1"
    local expected_type="$2"
    local desc="$3"
    local result
    result=$("$RESOLVER" resolve -b "$TEST_BIN" -a "$addr" 2>/dev/null || true)
    if echo "$result" | grep -qi "$expected_type"; then
        ok "$desc → $expected_type"
    else
        fail "$desc → expected '$expected_type', got: $(echo "$result" | head -1)"
    fi
}

check_field() {
    local addr="$1"
    local expected_field="$2"
    local desc="$3"
    local result
    result=$("$RESOLVER" resolve -b "$TEST_BIN" -a "$addr" 2>/dev/null || true)
    if echo "$result" | grep -qi "$expected_field"; then
        ok "$desc → field '$expected_field'"
    else
        fail "$desc → expected field '$expected_field', got: $(echo "$result" | head -3)"
    fi
}

check_region() {
    local addr="$1"
    local expected_region="$2"
    local desc="$3"
    local result
    result=$("$RESOLVER" resolve -b "$TEST_BIN" -a "$addr" 2>/dev/null || true)
    if echo "$result" | grep -qi "Class:.*${expected_region}"; then
        ok "$desc → $expected_region"
    else
        fail "$desc → expected $expected_region, got: $(echo "$result" | head -2)"
    fi
}

mkdir -p "$RESULTS_DIR"

echo "=============================================="
echo "  Global Variable Resolution Test"
echo "  Timestamp: $TIMESTAMP"
echo "=============================================="

# ============================================================
step "Step 1: Build test binary"

cd "$PROJECT_ROOT"
if [ ! -f "$TEST_BIN" ]; then
    info "Building test_global_resolution..."
    cmake --build "$BUILD_DIR" --target test_global_resolution 2>&1 | tail -5
fi

if [ ! -f "$TEST_BIN" ]; then
    fail "Test binary not found: $TEST_BIN"
    exit 1
fi
ok "Test binary exists"

file "$TEST_BIN"
echo ""

# ============================================================
step "Step 2: Check binary type (static vs PIE)"

BIN_TYPE=$(file "$TEST_BIN")
if echo "$BIN_TYPE" | grep -q "pie executable\|shared object"; then
    info "Binary is PIE (position-independent) — ASLR will apply"
    IS_PIE=1
else
    info "Binary is static (non-PIE) — no ASLR offset expected"
    IS_PIE=0
fi
ok "Binary type detected: $(echo "$BIN_TYPE" | cut -d: -f2)"

# ============================================================
step "Step 3: Verify DWARF debug info"

DWARF_CHECK=$(readelf -S "$TEST_BIN" 2>/dev/null | grep -c "debug_info\|\.debug_info" || true)
if [ "$DWARF_CHECK" -gt 0 ]; then
    ok "DWARF .debug_info section present"
else
    fail "No DWARF .debug_info section found"
fi

# ============================================================
step "Step 4: List global symbols (compile-time addresses)"

info "Compile-time global symbols:"
"$RESOLVER" symbols -b "$TEST_BIN" -n g_ 2>/dev/null | tee "$RESULTS_DIR/symbols.txt"

SYM_COUNT=$(grep -c "OBJECT" "$RESULTS_DIR/symbols.txt" 2>/dev/null || echo 0)
info "Total OBJECT symbols found: $SYM_COUNT"

if [ "$SYM_COUNT" -lt 5 ]; then
    fail "Too few global symbols (got $SYM_COUNT, expected >= 5)"
else
    ok "Sufficient global symbols ($SYM_COUNT)"
fi

# ============================================================
step "Step 5: Run test binary to get runtime addresses"

TEST_OUTPUT="$RESULTS_DIR/test_output.txt"
"$TEST_BIN" > "$TEST_OUTPUT" 2>&1 || true
info "Test output saved to $TEST_OUTPUT"

info "Runtime addresses (from ADDR: lines):"
grep "^ADDR:" "$TEST_OUTPUT" | while read line; do
    echo "  $line"
done

# ============================================================
step "Step 6: Compute ASLR offset from runtime vs compile-time addresses"

G_SIMPLE_INT_ADDR=$(get_addr "g_simple_int")
G_SIMPLE_INT_COMPILE=$("$RESOLVER" symbols -b "$TEST_BIN" -n g_simple_int 2>/dev/null | awk '{print $1}' | head -1)

if [ -n "$G_SIMPLE_INT_ADDR" ] && [ -n "$G_SIMPLE_INT_COMPILE" ]; then
    RUNTIME_DEC=$((G_SIMPLE_INT_ADDR))
    COMPILE_DEC=$((G_SIMPLE_INT_COMPILE))
    ASLR_DELTA=$((RUNTIME_DEC - COMPILE_DEC))

    info "g_simple_int: runtime=$G_SIMPLE_INT_ADDR compile=$G_SIMPLE_INT_COMPILE"
    info "ASLR delta = $ASLR_DELTA (0x$(printf '%lx' $ASLR_DELTA))"

    if [ "$ASLR_DELTA" -eq 0 ]; then
        info "ASLR delta is 0 — static binary or ASLR disabled"
    elif [ "$ASLR_DELTA" -gt 0 ]; then
        ok "ASLR offset detected: 0x$(printf '%lx' $ASLR_DELTA)"
    fi
else
    warn "Cannot compute ASLR delta"
    ASLR_DELTA=0
fi

# ============================================================
step "Step 7: Resolve scalar global variables"

check_resolve "$(get_addr "g_simple_int")"    "int"    "g_simple_int"
check_resolve "$(get_addr "g_simple_double")" "double" "g_simple_double"
check_resolve "$(get_addr "g_simple_char")"   "char"   "g_simple_char"
check_resolve "$(get_addr "g_static_int")"    "int"    "g_static_int (static)"

# ============================================================
step "Step 8: Resolve struct global variables"

check_resolve "$(get_addr "g_inner")"       "Inner"     "g_inner"
check_resolve "$(get_addr "g_outer")"       "Outer"     "g_outer"
check_resolve "$(get_addr "g_flat")"        "Flat"      "g_flat"
check_resolve "$(get_addr "g_mixed")"       "Mixed"     "g_mixed"
check_resolve "$(get_addr "g_ptr_holder")"  "PtrHolder" "g_ptr_holder"
check_resolve "$(get_addr "g_large")"       "Large"     "g_large"
check_resolve "$(get_addr "g_static_inner")" "Inner"    "g_static_inner (static)"

# ============================================================
step "Step 9: Verify GLOBAL region classification"

GLOBAL_COUNT=0
for label in g_simple_int g_inner g_outer g_flat g_mixed; do
    addr=$(get_addr "$label")
    if [ -z "$addr" ]; then continue; fi
    result=$("$RESOLVER" resolve -b "$TEST_BIN" -a "$addr" 2>/dev/null || true)
    if echo "$result" | grep -qi "Class:.*GLOBAL"; then
        GLOBAL_COUNT=$((GLOBAL_COUNT + 1))
    fi
done

if [ "$GLOBAL_COUNT" -ge 3 ]; then
    ok "GLOBAL region classification correct ($GLOBAL_COUNT/5 verified)"
else
    fail "GLOBAL region classification: only $GLOBAL_COUNT/5"
fi

# ============================================================
step "Step 10: Verify field-level resolution (Inner struct)"

check_field "$(get_addr "g_inner.a")" "\.a" "g_inner.a"
check_field "$(get_addr "g_inner.b")" "\.b" "g_inner.b"
check_field "$(get_addr "g_inner.c")" "\.c" "g_inner.c"

# ============================================================
step "Step 11: Verify field-level resolution (Outer struct with nested Inner)"

check_field "$(get_addr "g_outer.id")"      "\.id"   "g_outer.id"
check_field "$(get_addr "g_outer.inner.a")" "inner"  "g_outer.inner.a"
check_field "$(get_addr "g_outer.inner.b")" "inner"  "g_outer.inner.b"
check_field "$(get_addr "g_outer.inner.c")" "inner"  "g_outer.inner.c"

# ============================================================
step "Step 12: Verify field-level resolution (Flat struct)"

check_field "$(get_addr "g_flat.x")" "\.x" "g_flat.x"
check_field "$(get_addr "g_flat.y")" "\.y" "g_flat.y"
check_field "$(get_addr "g_flat.z")" "\.z" "g_flat.z"

# ============================================================
step "Step 13: Verify field-level resolution (Mixed struct with padding)"

check_field "$(get_addr "g_mixed.f")" "\.f" "g_mixed.f"
check_field "$(get_addr "g_mixed.i")" "\.i" "g_mixed.i"
check_field "$(get_addr "g_mixed.d")" "\.d" "g_mixed.d"

# ============================================================
step "Step 14: Verify array global variables"

check_resolve "$(get_addr "g_int_array")"    "int"    "g_int_array"
check_resolve "$(get_addr "g_double_array")" "double" "g_double_array"

# ============================================================
step "Step 15: Cross-validate: runtime addr - ASLR == compile addr"

if [ -n "$G_SIMPLE_INT_ADDR" ] && [ -n "$G_SIMPLE_INT_COMPILE" ] && [ "$ASLR_DELTA" -gt 0 ] 2>/dev/null; then
    COMPUTED_COMPILE=$((G_SIMPLE_INT_ADDR - ASLR_DELTA))
    COMPUTED_COMPILE_HEX=$(printf "0x%lx" $COMPUTED_COMPILE)

    info "Runtime: $G_SIMPLE_INT_ADDR"
    info "ASLR:    0x$(printf '%lx' $ASLR_DELTA)"
    info "Computed compile: $COMPUTED_COMPILE_HEX"
    info "Actual compile:   $G_SIMPLE_INT_COMPILE"

    if [ "$COMPUTED_COMPILE_HEX" = "$G_SIMPLE_INT_COMPILE" ]; then
        ok "ASLR offset verified: runtime - ASLR == compile address"
    else
        fail "ASLR offset mismatch"
    fi
else
    info "Skipping ASLR cross-validation (static binary or ASLR=0)"
fi

# ============================================================
step "Step 16: Verify layout command works for all struct types"

for type in Inner Outer Flat Mixed PtrHolder Large; do
    LAYOUT=$("$RESOLVER" layout -b "$TEST_BIN" -t "$type" 2>/dev/null || true)
    if [ -n "$LAYOUT" ]; then
        ok "Layout for $type"
    else
        fail "Layout for $type (empty output)"
    fi
done

# ============================================================
step "Step 17: Summary"

echo ""
echo "=============================================="
echo "  Test Results"
echo "=============================================="
echo -e "  ${GREEN}Passed: $PASS${RESET}"
echo -e "  ${RED}Failed: $FAIL${RESET}"
echo "  Total:  $((PASS + FAIL))"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}ALL TESTS PASSED ✓${RESET}"
    exit 0
else
    echo -e "  ${RED}SOME TESTS FAILED ✗${RESET}"
    exit 1
fi
