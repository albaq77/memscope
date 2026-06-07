#!/bin/bash
# 简洁的全局变量解析验证脚本
# 用法: ./quick_verify.sh [binary_path] [resolver_path]

BINARY="${1:-./build/tests/test_cases/test_global_resolution}"
RESOLVER="${2:-./build/src/resolver/memscope-resolve}"

if [ ! -f "$BINARY" ]; then echo "Binary not found: $BINARY"; exit 1; fi
if [ ! -f "$RESOLVER" ]; then echo "Resolver not found: $RESOLVER"; exit 1; fi

PASS=0; FAIL=0

# 运行测试程序，获取运行时地址
OUTPUT=$("$BINARY" 2>/dev/null)

echo "=========================================="
echo "  Global Variable Resolution Verification"
echo "=========================================="
echo ""

# 对每个 ADDR: 行，提取标签和地址，调用 resolver 验证
echo "$OUTPUT" | grep "^ADDR:" | while IFS= read -r line; do
    label=$(echo "$line" | cut -d= -f1 | sed 's/^ADDR://')
    addr=$(echo "$line" | cut -d= -f2)
    
    # 跳过字段地址（含.的），只验证变量级别
    if echo "$label" | grep -q '\.'; then
        continue
    fi

    result=$("$RESOLVER" resolve -b "$BINARY" -a "$addr" 2>/dev/null)
    
    echo "── $label @ $addr ──"
    echo "$result"
    echo ""
done

# 验证特定字段地址的精确匹配
echo "=========================================="
echo "  Field-level Verification"
echo "=========================================="
echo ""

check_field() {
    local label="$1"
    local expected="$2"
    local addr=$(echo "$OUTPUT" | grep "^ADDR:${label}=" | cut -d= -f2)
    
    if [ -z "$addr" ]; then
        echo "  ✗ $label: address not found"
        return
    fi
    
    result=$("$RESOLVER" resolve -b "$BINARY" -a "$addr" 2>/dev/null)
    if echo "$result" | grep -q "$expected"; then
        echo "  ✓ $label → $expected"
    else
        echo "  ✗ $label → expected '$expected', got:"
        echo "    $result"
    fi
}

check_field "g_inner.a"       "Inner.a"
check_field "g_inner.b"       "Inner.b"
check_field "g_inner.c"       "Inner.c"
check_field "g_outer.id"      "Outer.id"
check_field "g_outer.inner.a" "inner"
check_field "g_flat.x"        "Flat.x"
check_field "g_flat.y"        "Flat.y"
check_field "g_flat.z"        "Flat.z"
check_field "g_mixed.f"       "Mixed.f"
check_field "g_mixed.i"       "Mixed.i"
check_field "g_mixed.d"       "Mixed.d"

echo ""
echo "Done."
