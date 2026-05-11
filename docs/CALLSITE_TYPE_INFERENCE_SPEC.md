# MemScope 增强类型推断：基于调用点的精确类型解析

**规格版本**：v1.0  
**状态**：待实现  
**目标**：通过 PC 精确的调用点分析，从 `malloc(n * sizeof(struct X))` 中直接提取类型 `X`，替代并优于纯大小匹配策略。

---

## 1. 背景与动机

### 1.1 现有方案的根本局限

当前大小匹配（Size Matching）的本质缺陷：

```
malloc(40) → size_index_[40] → [struct Point]   ✓ 唯一匹配（偶然）
malloc(16) → size_index_[16] → [A, B, C, ...]   ✗ 歧义（常见）
malloc(n * sizeof(struct Point)) → size = n*40   ✗ 完全无法匹配（数组分配）
```

数组分配是最严重的盲区：生产代码中大量存在 `malloc(count * sizeof(T))` 模式，导致 size 不等于任何单一 struct 的大小，类型推断完全失败。

### 1.2 目标方案

```
malloc(n * sizeof(struct Point)) 的调用点：
  struct Point *arr = malloc(n * sizeof(struct Point));
                                                    ↑
                           这里有 DW_TAG_pointer_type → struct Point

通过 eBPF 捕获调用栈 → 获取 caller PC → 查询 DWARF 找到这个指针变量
→ 直接得到 struct Point，与 n 无关
```

**核心优势**：
- 正确处理 `n * sizeof(struct)` 的数组分配
- 消除大小相同类型之间的歧义
- 可检测分配数量 `n = size / sizeof(struct)`

---

## 2. 技术架构总览

```
┌─────────────────────────────────────────────────────────────────┐
│                        数据流向                                   │
│                                                                   │
│  目标进程                    eBPF                   用户空间       │
│  ──────────                ──────                 ──────────     │
│  malloc(n*sizeof(T))  →  uprobe/uretprobe  →  {addr, size,      │
│                           采集 stack_id          stack_id}       │
│                                                      │           │
│                                                      ▼           │
│  DWARF 调试信息  →  DwarfAnalyzer  →  build_pc_callsite_map()   │
│                      (离线解析)      PC → [PointerVarInfo]       │
│                                                      │           │
│                                                      ▼           │
│  BPF stack map   →  StackResolver  →  stack_id → [PC]  →  type  │
│                      (在线解析)                                   │
│                                                      │           │
│                                                      ▼           │
│                      AddressResolver::infer_type_combined()      │
│                      → "struct Point (count=5)"                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.1 新增/修改模块

| 模块 | 文件 | 变更类型 |
|------|------|----------|
| BPF 栈追踪 | `src/bpf/memscope.bpf.c` | 修复 stack_id 采集 |
| DWARF PC 映射 | `src/dwarf/dwarf_analyzer.{h,cpp}` | 新增 PC callsite map |
| 栈帧解析器 | `src/resolver/stack_resolver.{h,cpp}` | 新增模块 |
| 地址解析器 | `src/resolver/address_resolver.{h,cpp}` | 重写 infer_type_combined |
| 数据结构 | `src/common/types.h` | 新增字段 |

---

## 3. 第一阶段：eBPF 层——正确采集 stack_id

### 3.1 当前问题

```c
// src/bpf/memscope.bpf.c（当前错误实现）
info.stack_id = 0;   // 硬编码 0！所有分配都映射到同一个栈
evt.stack_id  = 0;   // 硬编码 0！
```

### 3.2 修复：实现 get_stack_id()

```c
// src/bpf/memscope.bpf.c

// 声明 BPF_MAP_TYPE_STACK_TRACE map（在 map section 中定义）
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10240);          // 最多存储 10240 个不同调用栈
    __uint(key_size, sizeof(__u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

// get_stack_id() 实现
static __always_inline __s64 get_stack_id(struct pt_regs *ctx)
{
    // BPF_F_USER_STACK: 采集用户态栈（不是内核栈）
    // BPF_F_REUSE_STACKID: 相同栈复用同一个 ID，节省空间
    return bpf_get_stackid(ctx, &stack_traces,
                           BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
}

// uretprobe_malloc_return 中的修复
SEC("uretprobe/libc.so.6:malloc")
int BPF_KRETPROBE(uprobe_malloc_return, void *ret)
{
    // ...（现有代码不变）

    // ✅ 修复：在 uretprobe 中采集用户态栈
    // 注意：此时 ctx 是 uretprobe 的 pt_regs，指向 malloc 的返回点
    // stack[0] = malloc 内部某处
    // stack[1] = malloc 的调用者（我们需要的！）
    __s64 sid = get_stack_id(ctx);
    info.stack_id = (sid < 0) ? -1 : (__s32)sid;

    evt.malloc_ret.addr     = addr;
    evt.malloc_ret.size     = size_val;
    evt.malloc_ret.stack_id = info.stack_id;   // ✅ 不再是 0

    emit_event(ctx, &evt);
    return 0;
}

// uprobe_free 中同样修复（用于追踪释放时的调用点）
SEC("uprobe/libc.so.6:free")
int BPF_UPROBE(uprobe_free, void *ptr)
{
    __s64 sid = get_stack_id(ctx);
    evt.free.stack_id = (sid < 0) ? -1 : (__s32)sid;
    // ...
}
```

### 3.3 stack_id 语义说明

```
stack_id = -1    → 栈采集失败（栈溢出、权限问题等）
stack_id =  0    → 有效栈，但与另一个 stack_id=0 的栈哈希碰撞（罕见）
stack_id >  0    → 正常有效的栈 ID

BPF stack map 中存储的内容（以 stack_id 为 key）：
  value = [PC_0, PC_1, PC_2, ..., 0, 0, ...]
  PC_0 = malloc 函数内部的 PC（不需要）
  PC_1 = malloc 调用者的返回地址（关键！）
  PC_2 = 调用者的调用者（辅助确认）
  ...
```

---

## 4. 第二阶段：DWARF 层——构建 PC→指针变量映射

### 4.1 目标数据结构

```cpp
// src/dwarf/dwarf_analyzer.h

// 局部指针变量信息
struct LocalPtrVarInfo {
    std::string var_name;              // 变量名，如 "p", "arr"
    std::string target_type_name;      // 指向的类型名，如 "Point"
    uint64_t    pc_low;                // 变量作用域起始 PC（来自 DW_AT_location）
    uint64_t    pc_high;               // 变量作用域结束 PC（0 表示整个函数）
    bool        valid;                 // 解析是否成功
};

// 子程序（函数）信息
struct SubprogramInfo {
    std::string name;                  // 函数名
    uint64_t    pc_low;                // DW_AT_low_pc
    uint64_t    pc_high;               // DW_AT_high_pc
    std::vector<LocalPtrVarInfo> ptr_vars;  // 所有指针类型的局部变量
};

// DwarfAnalyzer 新增成员
class DwarfAnalyzer {
public:
    // 新增：按 PC 查找所有可能的指针目标类型
    std::vector<std::string> find_pointer_target_types_at_pc(uint64_t pc) const;

    // 新增：获取所有子程序信息
    const std::vector<SubprogramInfo>& get_subprograms() const;

private:
    // 新增：PC → SubprogramInfo 的快速查找索引
    // key = (pc_low, pc_high), value = SubprogramInfo 的索引
    std::vector<SubprogramInfo> subprograms_;

    // 新增：构建内部索引
    void build_subprogram_pc_index();
    void process_subprogram_die_enhanced(void *die_v);  // 替换原有实现
    void extract_local_ptr_vars(void *die_v, SubprogramInfo &info);
    bool resolve_pointer_target_type(void *type_die_v, std::string &out_type_name);
};
```

### 4.2 process_subprogram_die_enhanced() 实现

```cpp
// src/dwarf/dwarf_analyzer.cpp

void DwarfAnalyzer::process_subprogram_die_enhanced(void *die_v)
{
    Dwarf_Die *die = (Dwarf_Die *)die_v;

    SubprogramInfo info = {};

    // 1. 函数名
    const char *name = dwarf_diename(die);
    if (!name) return;
    info.name = name;

    // 2. PC 范围（DW_AT_low_pc / DW_AT_high_pc）
    // 注意：有些函数用 DW_AT_ranges，处理更复杂，先处理简单的连续 PC 范围
    Dwarf_Addr low_pc = 0, high_pc = 0;
    if (dwarf_lowpc(die, &low_pc) != 0) return;  // 没有 low_pc 就跳过

    Dwarf_Attribute high_attr;
    if (dwarf_attr(die, DW_AT_high_pc, &high_attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&high_attr, &val) == 0) {
            // DW_AT_high_pc 可以是绝对地址或相对偏移
            // 如果是 DW_FORM_addr，是绝对地址；
            // 如果是 DW_FORM_data*，是相对于 low_pc 的偏移
            Dwarf_Half form = dwarf_whatform(&high_attr);
            if (form == DW_FORM_addr) {
                high_pc = val;
            } else {
                high_pc = low_pc + val;  // 相对偏移
            }
        }
    }

    info.pc_low  = low_pc;
    info.pc_high = high_pc;

    // 3. 提取所有指针类型的局部变量
    extract_local_ptr_vars(die, info);

    subprograms_.push_back(std::move(info));
}

void DwarfAnalyzer::extract_local_ptr_vars(void *die_v, SubprogramInfo &info)
{
    Dwarf_Die *die = (Dwarf_Die *)die_v;
    Dwarf_Die child;

    if (dwarf_child(die, &child) != 0) return;

    do {
        int tag = dwarf_tag(&child);

        // 只处理 DW_TAG_variable（局部变量）
        // 注意：DW_TAG_formal_parameter（函数参数）也应该处理
        if (tag != DW_TAG_variable && tag != DW_TAG_formal_parameter)
            continue;

        const char *var_name = dwarf_diename(&child);
        if (!var_name) continue;

        // 获取变量的类型
        Dwarf_Attribute type_attr;
        if (!dwarf_attr(&child, DW_AT_type, &type_attr)) continue;

        Dwarf_Die type_die;
        if (dwarf_formref_die(&type_attr, &type_die) == nullptr) continue;

        // 检查是否是指针类型
        std::string target_type_name;
        if (!resolve_pointer_target_type(&type_die, target_type_name)) continue;

        // 到这里说明是 T* 类型的变量，且 T 是一个 struct

        LocalPtrVarInfo var = {};
        var.var_name         = var_name;
        var.target_type_name = target_type_name;
        var.pc_low           = info.pc_low;   // 默认：整个函数范围有效
        var.pc_high          = info.pc_high;
        var.valid            = true;

        // 可选优化：尝试解析 DW_AT_location 中的 PC 范围（位置列表）
        // 这能缩小变量的有效范围，提高精度，但复杂度较高
        // 作为 Phase 2 可选实现，当前先跳过
        // extract_location_pc_range(&child, info.pc_low, var.pc_low, var.pc_high);

        info.ptr_vars.push_back(var);

    } while (dwarf_siblingof(&child, &child) == 0);
}

bool DwarfAnalyzer::resolve_pointer_target_type(void *type_die_v, std::string &out_name)
{
    Dwarf_Die *die = (Dwarf_Die *)type_die_v;

    // 跳过 typedef 和 const 修饰符，找到底层类型
    int max_depth = 8;  // 防止无限循环（如 typedef typedef typedef ...）
    while (max_depth-- > 0) {
        int tag = dwarf_tag(die);

        // 找到指针类型
        if (tag == DW_TAG_pointer_type) {
            // 获取指针指向的类型
            Dwarf_Attribute target_attr;
            if (!dwarf_attr(die, DW_AT_type, &target_attr)) return false;

            Dwarf_Die target_die;
            if (dwarf_formref_die(&target_attr, &target_die) == nullptr) return false;

            // 继续解析目标类型（可能还有 typedef/const）
            int inner_depth = 8;
            Dwarf_Die inner_die = target_die;
            while (inner_depth-- > 0) {
                int inner_tag = dwarf_tag(&inner_die);

                if (inner_tag == DW_TAG_structure_type ||
                    inner_tag == DW_TAG_class_type) {
                    // 找到！这是 struct/class 类型
                    const char *name = dwarf_diename(&inner_die);
                    if (!name) return false;
                    out_name = name;
                    return true;
                }

                if (inner_tag == DW_TAG_typedef ||
                    inner_tag == DW_TAG_const_type ||
                    inner_tag == DW_TAG_volatile_type) {
                    // 跳过修饰符
                    Dwarf_Attribute next_attr;
                    if (!dwarf_attr(&inner_die, DW_AT_type, &next_attr)) return false;
                    if (dwarf_formref_die(&next_attr, &inner_die) == nullptr) return false;
                    continue;
                }

                return false;  // 指针指向非 struct 类型（如 int*，void*）
            }
            return false;
        }

        // 跳过 typedef 和 const 修饰符
        if (tag == DW_TAG_typedef ||
            tag == DW_TAG_const_type ||
            tag == DW_TAG_volatile_type) {
            Dwarf_Attribute next_attr;
            if (!dwarf_attr(die, DW_AT_type, &next_attr)) return false;
            if (dwarf_formref_die(&next_attr, die) == nullptr) return false;
            continue;
        }

        return false;
    }
    return false;
}
```

### 4.3 find_pointer_target_types_at_pc() 实现

```cpp
// src/dwarf/dwarf_analyzer.cpp

std::vector<std::string>
DwarfAnalyzer::find_pointer_target_types_at_pc(uint64_t pc) const
{
    std::vector<std::string> results;

    for (const auto &subprog : subprograms_) {
        // 检查 pc 是否落在这个函数的范围内
        if (pc < subprog.pc_low || pc >= subprog.pc_high)
            continue;

        // pc 落在这个函数内，收集所有指针变量的目标类型
        for (const auto &var : subprog.ptr_vars) {
            // 检查 pc 是否在变量的有效范围内（默认是整个函数）
            if (pc >= var.pc_low && pc < var.pc_high) {
                results.push_back(var.target_type_name);
            }
        }

        // 找到了包含该 pc 的函数，不需要继续搜索
        // 注意：内联函数可能导致多个函数覆盖同一个 PC，目前忽略这种情况
        break;
    }

    // 去重
    std::sort(results.begin(), results.end());
    results.erase(std::unique(results.begin(), results.end()), results.end());

    return results;
}
```

### 4.4 性能优化：PC 区间索引

顺序扫描 subprograms_ 对于大型二进制文件（几百个函数）效率较低。可以构建区间树或排序数组加速查询：

```cpp
// src/dwarf/dwarf_analyzer.cpp

void DwarfAnalyzer::build_subprogram_pc_index()
{
    // 按 pc_low 排序，用于二分查找
    std::sort(subprograms_.begin(), subprograms_.end(),
              [](const SubprogramInfo &a, const SubprogramInfo &b) {
                  return a.pc_low < b.pc_low;
              });
}

// find_pointer_target_types_at_pc 的优化版本
// 用二分查找代替顺序扫描
std::vector<std::string>
DwarfAnalyzer::find_pointer_target_types_at_pc(uint64_t pc) const
{
    // 找到第一个 pc_low > pc 的元素
    auto it = std::upper_bound(subprograms_.begin(), subprograms_.end(), pc,
                               [](uint64_t val, const SubprogramInfo &s) {
                                   return val < s.pc_low;
                               });

    // 向前检查（可能有多个函数的 pc_low <= pc）
    if (it != subprograms_.begin()) {
        --it;
        if (pc >= it->pc_low && pc < it->pc_high) {
            // 找到了
            // ...（同上）
        }
    }
    return {};
}
```

---

## 5. 第三阶段：StackResolver——BPF stack map 读取与符号解析

### 5.1 新增模块：StackResolver

```cpp
// src/resolver/stack_resolver.h

#pragma once
#include <cstdint>
#include <vector>
#include <string>

class StackResolver {
public:
    // pid：目标进程 ID（用于定位 /proc/pid/maps）
    // map_fd：BPF stack_traces map 的文件描述符
    explicit StackResolver(int pid, int stack_map_fd);

    // 根据 stack_id 获取调用栈的 PC 列表（用户态地址）
    // 返回的列表中：
    //   [0] = malloc 内部 PC（通常跳过）
    //   [1] = malloc 调用者的返回 PC（我们最感兴趣的）
    //   [2...] = 更上层的调用者
    std::vector<uint64_t> get_stack_pcs(int32_t stack_id) const;

    // 获取调用者 PC（跳过 malloc 本身）
    // 即 get_stack_pcs() 中下标 1 的那个 PC
    // 减 1 是因为 call 指令之后的 PC 需要减 1 才是调用点
    uint64_t get_caller_pc(int32_t stack_id) const;

    // 将用户态虚拟地址转换为文件中的偏移量（用于 DWARF 查询）
    // 因为 ASLR 的存在，虚拟地址 ≠ 文件偏移，需要通过 /proc/pid/maps 转换
    uint64_t va_to_file_offset(uint64_t va) const;

private:
    int pid_;
    int stack_map_fd_;

    // 从 /proc/pid/maps 解析的内存映射信息
    struct MapEntry {
        uint64_t va_start;
        uint64_t va_end;
        uint64_t file_offset;
        std::string pathname;
    };
    std::vector<MapEntry> maps_;

    void load_proc_maps();
};
```

### 5.2 StackResolver 实现关键部分

```cpp
// src/resolver/stack_resolver.cpp

std::vector<uint64_t> StackResolver::get_stack_pcs(int32_t stack_id) const
{
    if (stack_id < 0) return {};

    // PERF_MAX_STACK_DEPTH 通常是 127
    constexpr int MAX_DEPTH = 127;
    uint64_t ips[MAX_DEPTH] = {};

    // 从 BPF stack_traces map 中读取
    // key = stack_id, value = uint64_t[MAX_DEPTH]
    if (bpf_map_lookup_elem(stack_map_fd_, &stack_id, ips) < 0)
        return {};

    std::vector<uint64_t> result;
    for (int i = 0; i < MAX_DEPTH && ips[i] != 0; i++)
        result.push_back(ips[i]);

    return result;
}

uint64_t StackResolver::get_caller_pc(int32_t stack_id) const
{
    auto pcs = get_stack_pcs(stack_id);

    // pcs[0] 是 malloc 内部的 PC，pcs[1] 是调用者
    if (pcs.size() < 2) return 0;

    // 减 1：call 指令执行后，栈上保存的是下一条指令的地址
    // 我们想要的是 call 指令本身（或其前一字节）
    // 这样才能映射到 DWARF 中的正确位置
    return pcs[1] - 1;
}

uint64_t StackResolver::va_to_file_offset(uint64_t va) const
{
    for (const auto &entry : maps_) {
        if (va >= entry.va_start && va < entry.va_end) {
            // 文件偏移 = 虚拟地址 - 段起始虚拟地址 + 段在文件中的偏移
            return va - entry.va_start + entry.file_offset;
        }
    }
    return 0;  // 未找到
}

void StackResolver::load_proc_maps()
{
    // 解析 /proc/{pid}/maps
    std::string path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream f(path);
    std::string line;

    while (std::getline(f, line)) {
        // 格式：55a12300-55a12400 r-xp 00001000 08:01 12345 /path/to/binary
        MapEntry entry = {};
        char perms[8], dev[8], pathname[512] = {};
        uint64_t inode;

        int ret = sscanf(line.c_str(),
            "%lx-%lx %7s %lx %7s %lu %511s",
            &entry.va_start, &entry.va_end,
            perms, &entry.file_offset, dev, &inode, pathname);

        if (ret >= 6) {
            entry.pathname = (ret == 7) ? pathname : "";
            // 只关心可执行段（包含代码）
            if (perms[2] == 'x')
                maps_.push_back(entry);
        }
    }
}
```

---

## 6. 第四阶段：组合推断策略

### 6.1 更新 AddressResolver

```cpp
// src/resolver/address_resolver.h（新增依赖）

#include "stack_resolver.h"

class AddressResolver {
public:
    // 构造函数新增 stack_map_fd 参数
    AddressResolver(DwarfAnalyzer &analyzer,
                    int pid,
                    int stack_map_fd);

private:
    std::unique_ptr<StackResolver> stack_resolver_;

    // 新增：基于 PC 的精确推断
    std::vector<std::string> infer_types_from_caller_pc(uint64_t caller_pc) const;

    // 修改：综合所有策略
    TypeInferenceResult infer_type_combined(int32_t stack_id, uint64_t size) const;
};

// 类型推断结果（新增结构体）
struct TypeInferenceResult {
    std::string type_name;        // 推断出的类型名，如 "Point"
    uint64_t    alloc_count;      // 分配数量（n * sizeof(T) 中的 n）
    std::string method;           // 推断方法："callsite", "size", "combined", "ambiguous"
    float       confidence;       // 置信度 0.0 ~ 1.0
    std::string note;             // 附加说明
};
```

### 6.2 infer_type_combined() 核心逻辑

```cpp
// src/resolver/address_resolver.cpp

TypeInferenceResult
AddressResolver::infer_type_combined(int32_t stack_id, uint64_t size) const
{
    TypeInferenceResult result = {};
    result.alloc_count = 1;

    // ── 策略 1：调用点 PC 推断（最高优先级）──────────────────────
    if (stack_id >= 0 && stack_resolver_) {
        uint64_t caller_pc = stack_resolver_->get_caller_pc(stack_id);

        if (caller_pc != 0) {
            // 转换为文件偏移，再查询 DWARF
            uint64_t file_offset = stack_resolver_->va_to_file_offset(caller_pc);
            auto pc_types = analyzer_.find_pointer_target_types_at_pc(file_offset);

            if (pc_types.size() == 1) {
                // ✅ 唯一匹配：高置信度
                result.type_name  = pc_types[0];
                result.method     = "callsite_pc";
                result.confidence = 0.95f;

                // 计算数组分配数量
                const TypeInfo *ti = analyzer_.find_type_by_name(result.type_name);
                if (ti && ti->byte_size > 0 && size % ti->byte_size == 0) {
                    result.alloc_count = size / ti->byte_size;
                    if (result.alloc_count > 1)
                        result.note = "array allocation (" +
                                      std::to_string(result.alloc_count) + " elements)";
                }

                return result;  // 直接返回，不需要大小匹配

            } else if (pc_types.size() > 1) {
                // 多个候选，继续尝试用大小匹配缩小范围
                auto size_types = get_size_candidates(size);

                // 计算交集
                std::vector<std::string> intersection;
                for (const auto &t : pc_types) {
                    if (std::find(size_types.begin(), size_types.end(), t)
                        != size_types.end())
                        intersection.push_back(t);
                }

                if (intersection.size() == 1) {
                    // ✅ 交集唯一：中等置信度
                    result.type_name  = intersection[0];
                    result.method     = "combined";
                    result.confidence = 0.80f;
                    return result;
                }

                if (!pc_types.empty()) {
                    result.type_name  = pc_types[0] + " (ambiguous: " +
                                        std::to_string(pc_types.size()) + " candidates)";
                    result.method     = "callsite_ambiguous";
                    result.confidence = 0.4f;
                    return result;
                }
            }
        }
    }

    // ── 策略 2：大小匹配（回退策略）────────────────────────────
    auto size_types = get_size_candidates(size);

    if (size_types.size() == 1) {
        result.type_name  = size_types[0];
        result.method     = "size_match";
        result.confidence = 0.60f;
        result.alloc_count = 1;  // 大小精确匹配时，认为是单个对象
        return result;
    }

    if (size_types.size() > 1) {
        result.type_name  = size_types[0] + " (ambiguous: " +
                            std::to_string(size_types.size()) + " candidates)";
        result.method     = "size_ambiguous";
        result.confidence = 0.2f;
        return result;
    }

    // ── 策略 3：大小倍数匹配（数组检测）────────────────────────
    // 当 size 不直接匹配任何 struct 时，检查是否是 n * sizeof(T)
    auto array_result = try_array_size_match(size);
    if (!array_result.type_name.empty()) {
        return array_result;
    }

    // 无法推断
    result.method     = "unknown";
    result.confidence = 0.0f;
    return result;
}

// 新增：数组大小倍数匹配
TypeInferenceResult
AddressResolver::try_array_size_match(uint64_t size) const
{
    TypeInferenceResult result = {};
    const auto &types = analyzer_.get_all_types();

    for (const auto &type : types) {
        if (type.byte_size < 8) continue;  // 忽略太小的类型，避免误匹配
        if (size % type.byte_size != 0) continue;

        uint64_t count = size / type.byte_size;
        if (count < 2 || count > 10000) continue;  // 合理的数组范围

        // 找到一个可能的数组类型匹配
        if (result.type_name.empty()) {
            result.type_name  = type.name;
            result.alloc_count = count;
            result.method     = "array_size_match";
            result.confidence = 0.35f;
        } else {
            // 多个类型都能整除，歧义
            result.type_name  += " (ambiguous)";
            result.confidence = 0.15f;
            break;
        }
    }

    return result;
}
```

### 6.3 完整推断决策树

```
infer_type_combined(stack_id, size)
│
├─ stack_id >= 0 ?
│  │
│  └─ YES → get_caller_pc(stack_id) → file_offset
│            │
│            └─ find_pointer_target_types_at_pc(file_offset)
│               │
│               ├─ size == 1 → 返回 type, confidence=0.95, 计算 count
│               │
│               ├─ size > 1 → get_size_candidates(alloc_size)
│               │              │
│               │              └─ 计算交集
│               │                 ├─ |交集| == 1 → 返回, confidence=0.80
│               │                 └─ |交集| > 1 → 返回第一个, confidence=0.40
│               │
│               └─ size == 0 → 继续到大小匹配
│
├─ get_size_candidates(alloc_size)
│  ├─ size == 1 → 返回, confidence=0.60
│  ├─ size > 1 → 返回第一个, confidence=0.20
│  └─ size == 0 → 继续
│
└─ try_array_size_match(alloc_size)
   ├─ 找到唯一倍数 → 返回, confidence=0.35
   └─ 找不到 → 返回 unknown
```

---

## 7. 输出格式变更

### 7.1 resolve_heap() 返回值更新

```cpp
// src/common/types.h

struct ResolvedAddress {
    uint64_t    address;
    std::string segment_class;     // "HEAP"
    std::string type_name;         // "Point"
    uint64_t    alloc_size;        // malloc 的字节数
    uint64_t    alloc_count;       // 新增：分配的对象数量（1=单个，>1=数组）
    std::string field_name;        // "y"
    uint64_t    field_offset;      // 8
    uint64_t    field_size;        // 8
    std::string field_type;        // "double"
    std::string infer_method;      // 新增："callsite_pc", "size_match", ...
    float       infer_confidence;  // 新增：0.0 ~ 1.0
    std::string note;              // 新增：附加说明
};
```

### 7.2 命令行输出示例

```
# 单个对象（原有行为，无变化）
Address: 0x55a123456008
Class:   HEAP
Type:    struct Point  [callsite_pc, confidence=0.95]
Alloc:   40 bytes (1 object)
Field:   Point.y (offset=8, size=8, type=double)

# 数组分配（新增能力）
Address: 0x55a123456050
Class:   HEAP
Type:    struct Point  [callsite_pc, confidence=0.95, array: 5 elements]
Alloc:   200 bytes (5 objects, each 40 bytes)
Element: index 1 (base offset 40)
Field:   Point.z (offset=16 within element, size=8, type=double)

# 大小匹配回退
Address: 0x55a123480000
Class:   HEAP
Type:    struct Buffer  [size_match, confidence=0.60]
Alloc:   32 bytes (1 object)
Field:   Buffer.len (offset=8, size=8, type=size_t)
```

---

## 8. 数组元素字段解析

当 `alloc_count > 1` 时，地址可能指向数组中任意元素的任意字段。需要扩展 `resolve_heap()`：

```cpp
// src/resolver/address_resolver.cpp - resolve_heap() 扩展

if (type_result.alloc_count > 1) {
    // 计算元素大小
    const TypeInfo *ti = analyzer_.find_type_by_name(type_result.type_name);
    if (ti && ti->byte_size > 0) {
        uint64_t elem_size  = ti->byte_size;
        uint64_t elem_index = offset / elem_size;       // 第几个元素
        uint64_t elem_offset = offset % elem_size;      // 在元素内的偏移

        result.note = "array element [" + std::to_string(elem_index) + "]";

        // 用 elem_offset 查字段
        auto field = analyzer_.resolve_field_at_offset(type_result.type_name, elem_offset);
        // ...
    }
}
```

---

## 9. 实现顺序与里程碑

### Phase 1（基础修复，必须先做）
- [ ] 修复 `get_stack_id()`，确认 stack_id 非零
- [ ] 验证：`bpf_map_lookup_elem(stack_traces, stack_id, pcs)` 能读到正确 PC
- [ ] 验证：`pcs[1] - 1` 对应的文件偏移落在 `bench_point_alloc` 函数范围内

**验证命令**：
```bash
# 用 addr2line 验证 PC 对应的源码位置
addr2line -f -e bench_target <file_offset_hex>
# 期望输出：bench_point_alloc
#          bench_target.c:42
```

### Phase 2（DWARF 扩展）
- [ ] 实现 `process_subprogram_die_enhanced()`
- [ ] 实现 `extract_local_ptr_vars()`
- [ ] 实现 `resolve_pointer_target_type()`（处理 typedef/const 链）
- [ ] 实现 `find_pointer_target_types_at_pc()`
- [ ] 单元测试：对 `bench_target` 验证 `bench_point_alloc` 的 PC 范围和变量 `p`

### Phase 3（StackResolver）
- [ ] 实现 `load_proc_maps()`（解析 `/proc/pid/maps`）
- [ ] 实现 `va_to_file_offset()`
- [ ] 实现 `get_stack_pcs()` 和 `get_caller_pc()`
- [ ] 集成测试：打印 stack_id → caller_pc → file_offset → 函数名

### Phase 4（组合推断）
- [ ] 实现 `infer_type_combined()`
- [ ] 实现 `try_array_size_match()`
- [ ] 更新 `resolve_heap()` 处理数组元素偏移
- [ ] 端到端测试：`malloc(5 * sizeof(struct Point))` 能正确识别类型和数组长度

---

## 10. 已知边界条件与处理策略

| 情况 | 描述 | 处理方式 |
|------|------|----------|
| `void *` 指针 | `void *p = malloc(...)` 没有类型信息 | 回退到大小匹配 |
| 内联函数 | malloc 调用点被内联，PC 可能对应多个函数 | 尝试所有包含该 PC 的函数 |
| 优化编译（-O2） | 编译器可能消除局部变量，DWARF 可能不完整 | 降低置信度，回退 |
| `calloc(n, size)` | 与 malloc 不同的函数签名 | 需要单独的 uprobe，size = n * elem_size |
| C++ `new T[n]` | 最终调用 `operator new`，但包装层不同 | 需要 uprobe `_Znam` / `_Znwm` |
| ASLR | 每次运行虚拟地址不同 | 通过 `/proc/pid/maps` 转换为文件偏移 |
| PIE 可执行文件 | 可执行文件本身也有基址偏移 | 同上，maps 中 exe 本身也有条目 |

---

## 11. 依赖与编译要求

```cmake
# CMakeLists.txt 新增（如果尚未包含）

# BPF map 操作需要 libbpf
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
target_link_libraries(memscoped ${LIBBPF_LIBRARIES})

# DWARF 解析（已有）
pkg_check_modules(LIBDW REQUIRED libdw)
target_link_libraries(memscoped ${LIBDW_LIBRARIES})
```

目标二进制编译要求：
```bash
# 必须带调试信息，且需要子程序局部变量信息
gcc -g -O0 bench_target.c -o bench_target   # 推荐：O0 保留所有 DWARF 变量信息
gcc -g -O1 bench_target.c -o bench_target   # 可用：部分变量可能被优化掉
gcc -g -O2 bench_target.c -o bench_target   # 不推荐：大量变量信息丢失
```
