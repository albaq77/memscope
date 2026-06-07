# MemScope 全局变量地址解析

## 1. 概述

MemScope 的地址解析器（Resolver）支持三种内存区域的地址解析：

| 区域 | 数据来源 | 解析方法 |
|------|---------|---------|
| **HEAP**（堆） | eBPF Collector 采集的 CSV | 调用点栈回溯 + 源码类型推断 |
| **GLOBAL**（全局/静态变量） | 二进制 DWARF/ELF 符号表 | 符号表地址匹配 + DWARF 字段解析 |
| **STACK**（栈变量） | DWARF 栈帧信息 | 栈偏移 + DWARF 局部变量信息 |

**关键区别**：Collector（eBPF）只跟踪 `malloc/calloc/realloc/free/mmap` 等动态分配函数，**不采集全局变量地址**。全局变量的地址解析完全由 Resolver 从二进制文件的调试信息中完成，不需要运行时采集。

---

## 2. Collector 不采集全局变量

### 2.1 Collector 采集范围

Collector 通过 eBPF uprobe/uretprobe 挂载到以下函数：

| 挂载函数 | 事件类型 | 记录内容 |
|---------|---------|---------|
| `malloc` | `EVENT_MALLOC_RETURN` | addr, size, stack_pcs |
| `calloc` | `EVENT_CALLOC_RETURN` | addr, size, stack_pcs |
| `realloc` | `EVENT_REALLOC_RETURN` | addr, size, old_addr, stack_pcs |
| `free` | `EVENT_FREE` | addr（标记释放） |
| `mmap` | `EVENT_MMAP` | addr, size |
| `munmap` | `EVENT_MUNMAP` | addr, size |

输出的 CSV 格式：

```
addr,size,pid,tid,live,timestamp_alloc,timestamp_free,stack_id,stack_depth,stack_pcs
0x5555555592a0,48,12345,12345,1,1000000,0,0,3,0x401156;0x4011a0;0x7f...
```

### 2.2 为什么不采集全局变量

全局变量（包括 `static` 变量）的地址在编译时就已经确定（PIE 编译时为相对偏移），不需要运行时跟踪。它们的信息完整存在于二进制文件的 DWARF 调试信息和 ELF 符号表中，Resolver 可以直接从文件中获取。

---

## 3. 全局地址解析原理

### 3.1 解析流程

```
传入运行时地址 (VA)
        │
        ▼
  resolve(addr, pid, stack_frames)
        │
        ├── 1. resolve_global(addr)           ← 优先级最高
        │       │
        │       ├── 直接匹配: find_symbol_by_addr(addr)
        │       │     → 精确匹配: symbol_addr_index_[addr]
        │       │     → 范围匹配: upper_bound + [addr, addr+size)
        │       │
        │       ├── ASLR 回退: compute_aslr_from_global_addr(addr)
        │       │     → 利用页对齐特性（低12位不变）反推 ASLR 偏移
        │       │     → compile_addr = addr - aslr_offset
        │       │     → find_symbol_by_addr(compile_addr)
        │       │
        │       └── 匹配成功后:
        │             ├─ sym.name       → "g_inner"
        │             ├─ sym.type_name  → "Inner"
        │             ├─ offset = compile_addr - sym.address
        │             └─ resolve_field_at_offset("Inner", offset)
        │                   → FieldInfo { name="b", byte_offset=8, type_name="double" }
        │                   → 结果: "Inner.b"
        │
        ├── 2. resolve_heap(addr, pid)        ← 堆分配匹配
        │
        └── 3. resolve_stack(addr, frames)    ← 栈变量匹配
```

### 3.2 静态编译 vs PIE 动态编译

#### 静态编译（非 PIE）

编译时地址 == 运行时地址，直接匹配即可：

```
编译时: g_inner @ 0x604040
运行时: g_inner @ 0x604040     ← 地址相同

find_symbol_by_addr(0x604040) → 精确匹配 ✅
```

#### PIE 动态编译（ASLR 生效）

运行时地址 = 编译时地址 + ASLR 偏移：

```
编译时: g_inner @ 0x4040
运行时: g_inner @ 0x555555558040 = 0x4040 + 0x555555554000(ASLR)

直接匹配: find_symbol_by_addr(0x555555558040) → ❌ 索引中是 0x4040
ASLR回退: compute_aslr_from_global_addr(0x555555558040)
          → ASLR = 0x555555554000
          → compile_addr = 0x555555558040 - 0x555555554000 = 0x4040
          → find_symbol_by_addr(0x4040) → 精确匹配 ✅
```

### 3.3 ASLR 偏移计算算法

`compute_aslr_from_global_addr()` 利用 ASLR 页对齐特性（低 12 位不变）：

```
输入: runtime_addr = 0x555555558048

1. page_offset = runtime_addr & 0xFFF = 0x048   ← 低12位不变

2. 遍历所有 SYM_OBJECT 符号:
   sym.address = 0x4040 (编译时地址)
   compile_page_base = 0x4040 & ~0xFFF = 0x4000
   candidate_compile_addr = 0x4000 | 0x048 = 0x4048

3. 验证候选地址在符号范围内:
   0x4048 >= 0x4040 && 0x4048 < 0x4040 + 24(size) ✅

4. 计算 ASLR 偏移:
   potential_aslr = 0x555555558048 - 0x4048 = 0x555555554000

5. 页对齐取整 + 投票:
   rounded_offset = (0x555555554000 / 0x1000) * 0x1000 = 0x555555554000
   offset_counts[0x555555554000]++

6. 选出最常见的偏移量作为最终 ASLR 偏移
```

### 3.4 字段偏移计算

找到符号后，计算字段偏移：

```
运行时地址: 0x555555558048
ASLR 偏移:  0x555555554000
编译时地址: 0x555555558048 - 0x555555554000 = 0x4048
符号地址:   0x4040 (g_inner)
字段偏移:   0x4048 - 0x4040 = 8

resolve_field_at_offset("Inner", 8) → Inner.b (double, offset=8)
```

---

## 4. 符号表数据来源

Resolver 从两个来源获取全局变量信息：

### 4.1 ELF 符号表（`.symtab` / `.dynsym`）

```
来源: parse_symbol_table()
内容: sym.st_value (编译时地址), sym.st_size, sym.st_name
类型: STT_OBJECT (全局变量), STT_FUNC (函数)
限制: 无类型名称（type_name 为空）
```

### 4.2 DWARF 调试信息

```
来源: process_variable_die()
内容: DW_OP_addr (编译时地址), DW_AT_type → type_name, dwarf_aggregate_size → size
类型: DW_TAG_variable
优势: 有完整的类型名称和字段信息
```

### 4.3 合并策略

同一全局变量可能同时出现在 ELF 和 DWARF 中。排序时 DWARF 符号（有 `type_name`）排在 ELF 符号（无 `type_name`）**后面**，确保 `upper_bound` 回退时优先返回 DWARF 符号：

```cpp
std::sort(symbols_.begin(), symbols_.end(),
    [](const SymbolInfo &a, const SymbolInfo &b) {
        if (a.address != b.address)
            return a.address < b.address;
        return a.type_name.empty() && !b.type_name.empty();
    });
```

---

## 5. 使用方式

### 5.1 解析单个全局地址

```bash
# 传入运行时地址，自动识别为 GLOBAL 并解析类型和字段
memscope-resolve resolve -b ./bench_target_v2 -a 0x555555558040
```

输出示例：
```
Address: 0x555555558040
Class:   GLOBAL
Symbol:  g_inner
Type:    Inner
Field:   Inner.a (offset=0, size=4, type=int)
```

### 5.2 批量解析多个地址

```bash
# lookup 命令支持多个 -a 参数
memscope-resolve lookup -b ./bench_target_v2 \
    -a 0x555555558040 \
    -a 0x555555558048 \
    -a 0x555555558060
```

输出示例：
```
ADDRESS             REGION  TYPE                 FIELD                          OFFSET
0x555555558040      GLOBAL  Inner                Inner.a                        +0 [4B int]
0x555555558048      GLOBAL  Inner                Inner.b                        +8 [8B double]
0x555555558060      GLOBAL  Outer                Outer.id                       +0 [4B int]
```

### 5.3 结合 Collector CSV 使用

```bash
# batch 命令：解析 Collector 采集的堆分配地址
# 注意：CSV 中只有堆地址，但 resolve() 会先尝试 resolve_global()
# 如果某个地址恰好落在全局变量范围内，也会被识别为 GLOBAL
memscope-resolve batch -b ./bench_target_v2 \
    -f allocs.csv \
    -o resolved.csv
```

### 5.4 查看全局符号列表

```bash
# 列出所有全局变量符号（编译时地址）
memscope-resolve symbols -b ./bench_target_v2 -n g_

# 输出示例:
# 0x4040             24  GLOBAL    OBJECT       g_inner [Inner]
# 0x4060             96  GLOBAL    OBJECT       g_outer [Outer]
# 0x40c0             24  GLOBAL    OBJECT       g_flat [Flat]
```

### 5.5 查看类型布局

```bash
# 查看结构体字段布局（用于验证偏移计算）
memscope-resolve layout -b ./bench_target_v2 -t Inner

# 输出示例:
# struct Inner (size=24, align=8)
#   Offset  Size  Type            Name
#   ------  ----  ----            ----
#       0     4  int             a
#       4     4  <padding>       <padding>
#       8     8  double          b
#      16     1  char            c
#      17     7  <padding>       <tail padding>
```

---

## 6. 完整使用流程示例

### 场景：验证 bench_target_v2 的全局变量解析

```bash
# Step 1: 编译
cd /path/to/memscope/build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# Step 2: 运行目标程序，获取全局变量运行时地址
./bench_target_v2 | grep "g_"
# 输出: g_state @ 0x555555558040
#        g_identity @ 0x5555555580a0
#        ...

# Step 3: 使用 eBPF Collector 采集堆分配（10秒）
sudo ./memscope-collect -p $(pidof bench_target_v2) \
    -b ./bench_target_v2 \
    -B ./memscope.bpf.o \
    -d 10 \
    -o allocs.csv

# Step 4: 解析堆分配地址
memscope-resolve batch -b ./bench_target_v2 \
    -f allocs.csv \
    -o heap_resolved.csv

# Step 5: 解析全局变量地址（手动传入）
memscope-resolve lookup -b ./bench_target_v2 \
    -a 0x555555558040 \
    -a 0x5555555580a0

# Step 6: 运行自动化验证脚本
cd ../tests/test_cases
./verify_global_resolution.sh
```

---

## 7. 局限性与未来改进

| 局限 | 说明 | 可能的改进 |
|------|------|-----------|
| 全局地址需手动传入 | Collector 不采集全局变量访问 | 在 Collector 启动时自动从 ELF 符号表提取全局变量地址范围 |
| 共享库全局变量 | 当前跳过 `>= 0x7f...` 的地址 | 解析 `/proc/pid/maps` 获取共享库加载基址 |
| ASLR 偏移独立计算 | 每次调用 `resolve_global()` 都可能重新计算 | 缓存首次计算的 ASLR 偏移 |
| 多线程安全 | `aslr_offset_` 使用 `const_cast` | 改为 `std::atomic` 或初始化时计算 |
