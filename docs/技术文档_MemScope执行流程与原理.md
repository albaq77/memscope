# MemScope — eBPF + 离线 DWARF 分析：运行时地址到结构体字段映射

## 一、概述

**MemScope** 是一个生产级别的工具链，它将 **eBPF 运行时内存追踪** 与 **离线 DWARF 调试信息分析** 相结合，实现将运行时内存地址映射到对应的结构体（struct）字段。它回答的核心问题是：**"给定一个运行时地址，它对应哪个结构体的哪个字段？"**

### 核心能力

- **eBPF 内存追踪**：通过 uprobe 钩子拦截 malloc/free/mmap，开销极低
- **DWARF 类型分析**：解析 ELF + DWARF 调试信息，获取完整的类型布局
- **地址分类**：自动将地址归类为全局（Global）、堆（Heap）或栈（Stack）
- **字段级解析**：将地址映射到具体结构体字段，包含偏移量和大小
- **类型推断**：通过调用点分析和大小匹配推断堆分配类型
- **批量解析**：一次性加载 DWARF，批量解析所有分配并展开所有字段
- **并发查找**：O(1) 哈希表用于分配查找和大小到类型的索引
- **CSV 导出**：将分配数据导出为 CSV，便于离线分析

---

## 二、整体架构

```
目标进程 → eBPF uprobes → Ring Buffer → Collector → CSV
                                                    ↓
二进制文件 (ELF+DWARF) → DWARF Analyzer → 类型数据库 → Address Resolver → struct.field
```

### 架构分层

MemScope 由四个主要组件构成，分为**运行时追踪**和**离线分析**两个阶段：

| 阶段 | 组件 | 职责 |
|------|------|------|
| **运行时** | eBPF 程序（内核侧） | 拦截内存分配/释放调用，采集事件 |
| **运行时** | Collector（用户态） | 加载 eBPF、消费 Ring Buffer、构建分配哈希表、导出 CSV |
| **离线** | DWARF Analyzer | 解析 ELF 符号表和 DWARF 调试信息，构建类型数据库 |
| **离线** | Address Resolver | 结合运行时数据与类型信息，解析地址到结构体字段 |

---

## 三、组件详解

### 3.1 eBPF 内核程序 (`src/bpf/memscope.bpf.c`)

eBPF 程序通过 **uprobe（用户态探测点）** 附加到 libc 的内存管理函数上，在内核侧拦截用户态函数的调用。

#### 挂载的探测点

| 探测程序 | 目标函数 | 捕获内容 |
|----------|----------|----------|
| `uprobe_malloc_entry` | `libc:malloc` | 入参 size（仅写入 BPF map，不发送事件） |
| `uretprobe_malloc_return` | `libc:malloc` | 返回值 addr + size |
| `uprobe_free` | `libc:free` | 入参 addr（释放的地址） |
| `uprobe_mmap_entry` | `libc:mmap` | addr, size, prot, flags |
| `uprobe_munmap_entry` | `libc:munmap` | addr, size |

#### 性能优化策略

关键的优化在于 **malloc 入口探测点不发送 Ring Buffer 事件**。`uprobe_malloc_entry` 仅将 size 写入 `pending_mallocs` BPF 哈希映射（以线程 TID 为键），而 `uretprobe_malloc_return` 在函数返回时从该映射中读出 size，将地址和大小合并为一个事件发送。这样将 Ring Buffer 的写入次数**减少了一半**。

#### BPF 内核映射（Maps）

| 映射名 | 类型 | 容量 | 用途 |
|--------|------|------|------|
| `events` | BPF_RINGBUF | 64MB | 流式传输事件到用户态 |
| `stack_traces` | BPF_MAP_TYPE_STACK_TRACE | 16K 条目 | 捕获调用栈 |
| `active_allocs` | BPF_MAP_TYPE_HASH | 16K 条目 | 追踪活跃分配（addr → alloc_info） |
| `completed_allocs` | BPF_MAP_TYPE_HASH | 16K 条目 | 记录已释放的分配（事后分析用） |
| `pending_mallocs` | BPF_MAP_TYPE_HASH | 4K 条目 | 按 TID 匹配 malloc 入口/返回 |

#### 事件类型定义

```c
enum event_type {
    EVENT_MALLOC_ENTRY  = 1,   // malloc 进入
    EVENT_MALLOC_RETURN = 2,   // malloc 返回
    EVENT_FREE          = 3,   // free 调用
    EVENT_MMAP          = 4,   // mmap 调用
    EVENT_MUNMAP        = 5,   // munmap 调用
    EVENT_STACK_SAMPLE  = 6,   // 采样栈
};
```

#### malloc 追踪的执行流程

```
1. uprobe_malloc_entry(size):
   pending_mallocs[tid] = size   ← 仅写入 map，不发事件

2. uretprobe_malloc_return(addr):
   size = pending_mallocs[tid]   ← 读出之前保存的 size
   delete pending_mallocs[tid]
   active_allocs[addr] = {size, timestamp, pid, tid}
   发送 EVENT_MALLOC_RETURN 事件到 Ring Buffer
```

### 3.2 用户态收集器 (`src/collector/`)

Collector 是运行在目标机器上的用户态守护程序，负责将 eBPF 内核事件转化为结构化的分配记录。

#### 工作流程

```
collector_init()
  ├── 分配分配哈希表 (64K 桶, Murmur3 哈希)
  ├── 打开并加载 BPF 目标文件 (.bpf.o)
  ├── 获取 BPF 映射的文件描述符
  └── 创建 Ring Buffer 消费者

collector_start()
  └── attach_uprobes()
        ├── 查找 libc 路径
        ├── 对每个探测点：objdump 获取函数偏移量
        └── bpf_program__attach_uprobe() 附加探测

主循环：
  while (running) {
    collector_poll(ctx, timeout_ms)  →  ring_buffer__poll()
    └── 回调 handle_event() 处理每种事件类型
  }

collector_stop() → 销毁 BPF 链接
collector_dump_allocs() → 导出 CSV
```

#### 分配哈希表（核心数据结构）

分配表使用 **Murmur3 最终混合哈希** 实现 O(1) 查找，取代了原始的 O(n) 线性扫描，对 10K+ 分配场景提升约 1000 倍性能。

```c
struct alloc_table {
    struct alloc_record *records;   // 连续分配记录数组
    size_t              count;      // 当前记录数
    size_t              capacity;   // 容量
    int                *hash_buckets; // 64K 桶头（索引指向 records）
    int                *hash_next;    // 链式冲突解决链接
    int                 hash_size;
};

struct alloc_record {
    uint64_t addr;            // 分配地址
    uint64_t size;            // 分配大小
    int64_t  stack_id;        // BPF 栈跟踪 ID
    uint64_t timestamp_alloc; // 分配时间戳
    uint64_t timestamp_free;  // 释放时间戳（0 表示活跃）
    uint32_t pid;
    uint32_t tid;
    int      live;            // 是否仍活跃
    // ...
};
```

哈希函数实现：

```c
static inline uint32_t alloc_hash(uint64_t addr) {
    uint64_t h = addr;
    h ^= h >> 33;  h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;  h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return (uint32_t)(h & ALLOC_HASH_MASK);  // 映射到 64K 桶
}
```

#### CSV 输出格式

```
address,size,pid,tid,live,timestamp_alloc,timestamp_free
0x55a123456000,40,1234,1234,1,1698765432109876543,0
0x55a123456020,48,1234,1235,0,1698765432109876544,1698765433109876543
```

### 3.3 DWARF 分析器 (`src/dwarf/dwarf_analyzer.cpp`)

DWARF Analyzer 是离线分析的起点，它加载目标二进制文件的 ELF 和 DWARF 调试信息，构建完整的类型和符号数据库。

#### 加载过程

```cpp
int DwarfAnalyzer::load_binary(const std::string &path)
{
    // 1. 打开 ELF 文件（使用 elfutils/libdw）
    fd = open(path, O_RDONLY);
    mmap 映射整个文件
    elf_begin() 初始化 ELF 解析器

    // 2. 初始化 DWARF 解析器
    dwarf_begin_elf() 从 ELF 中打开 DWARF 调试信息

    // 3. 解析内容
    parse_symbol_table()  ← 解析 .symtab / .dynsym
    parse_dwarf_info()    ← 解析 .debug_info 中的类型和子程序
    parse_dwarf_frames()  ← 解析 .debug_frame（CFI 栈回溯信息）

    loaded_ = true;
}
```

#### 解析的内容

| 数据来源 | 解析内容 | 用途 |
|----------|----------|------|
| `.symtab` / `.dynsym` | 符号表 | 全局变量的地址、大小、类型关联 |
| `.debug_info` | 类型定义（struct/union/enum）、子程序、变量 | 类型布局、字段偏移、调用点分析 |
| `.debug_frame` | CFI（Call Frame Information） | 栈回溯展开（当前为桩实现） |
| `.debug_line` | 行号信息 | 源码位置映射 |

#### 核心数据结构

**TypeInfo** — 类型信息：

```cpp
struct TypeInfo {
    uint64_t              die_offset;  // DWARF DIE 偏移
    std::string           name;        // 类型名称
    uint64_t              byte_size;   // 类型总大小
    uint64_t              alignment;   // 对齐要求
    Tag                   tag;         // struct/union/enum/typedef/...
    std::vector<FieldInfo> fields;     // 字段列表
    std::string           source_file;
    uint32_t              source_line;
};
```

**FieldInfo** — 字段信息：

```cpp
struct FieldInfo {
    std::string name;        // 字段名
    uint64_t    byte_offset; // 字节偏移
    uint64_t    byte_size;   // 字段大小
    bool        is_bitfield; // 是否为位域
    std::string type_name;   // 字段类型名
    bool        is_pointer;  // 是否为指针
    bool        is_array;    // 是否为数组
    // ...
};
```

**SymbolInfo** — 符号信息：

```cpp
struct SymbolInfo {
    std::string  name;           // 符号名
    uint64_t     address;        // 地址
    uint64_t     size;           // 大小
    std::string  type_name;      // 关联的类型名
    uint64_t     type_die_offset; // 类型的 DWARF DIE 偏移
    Binding      binding;        // LOCAL / GLOBAL / WEAK
    SymType      sym_type;       // FUNC / OBJECT / UNKNOWN
};
```

#### 字段偏移解析算法

给定一个类型名和字节偏移量，在类型的所有字段中二分查找包含该偏移的字段：

```cpp
std::optional<FieldInfo> DwarfAnalyzer::resolve_field_at_offset(
    uint64_t type_die_offset, uint64_t byte_offset) const
{
    // 遍历类型的所有字段
    for (const auto &field : type->fields) {
        // 精确匹配
        if (byte_offset == field.byte_offset) { ... }
        // 范围匹配：偏移落在字段范围内
        if (byte_offset >= field.byte_offset &&
            byte_offset < field.byte_offset + field.byte_size) {
            // 选择距离最近的字段
        }
    }
}
```

### 3.4 地址解析器 (`src/resolver/address_resolver.cpp`)

Resolver 是工具链的最后一环，它结合运行时收集的分配数据和编译时的 DWARF 类型信息，将地址解析为结构体字段。

#### 三地址分类解析策略

对于任意一个运行时地址，Resolver 按以下优先级进行三类分类解析：

```
resolve(address)
  ├── resolve_global(address)     → 全局变量？
  │     使用符号表二分查找包含该地址的全局符号
  │     再通过 symbol→DW_AT_type 获取类型，解析字段
  │
  ├── resolve_heap(address)       → 堆分配？
  │     在分配哈希表中 O(1) 查找包含该地址的分配记录
  │     通过大小索引或调用点推断类型，解析字段
  │
  └── resolve_stack(address)      → 栈变量？
        通过 CFI 回溯 + DW_AT_location 定位
```

##### 全局地址解析

```cpp
resolve_global(address):
  1. find_symbol_by_addr(address)
     → 符号表按地址排序，upper_bound 二分查找
     → 检查 address 是否落在符号的 [addr, addr+size) 范围内
  2. 获取符号的 DW_AT_type → 类型名
  3. offset = address - sym.address
  4. analyzer.resolve_field_at_offset(type_name, offset)
     → 从类型的字段列表中找到包含该偏移的字段
```

##### 堆地址解析

```cpp
resolve_heap(address):
  1. find_alloc(address)
     → 分配表按地址排序，upper_bound 二分查找
     → 检查 address 是否落在分配的 [addr, addr+size) 范围内
  2. 类型推断（优先级）：
     a. infer_type_from_callsite(stack_id)
        → 分析 malloc 调用点的栈回溯，从上下文推断类型（当前为桩）
     b. infer_type_from_size(alloc.size)
        → 在 size_index_ 中 O(1) 查找匹配大小的类型
  3. offset = address - alloc.addr
  4. analyzer.resolve_field_at_offset(type_name, offset)
```

##### 大小索引（Size Index）— 核心优化

Resoler 在 `load_binary()` 时构建大小索引，将类型大小映射到类型索引列表，实现 O(1) 的类型查找：

```cpp
void AddressResolver::build_size_index() {
    for (size_t i = 0; i < types.size(); i++) {
        if (types[i].byte_size > 0 && !types[i].fields.empty()) {
            size_index_[types[i].byte_size].push_back(i);
        }
    }
}

std::string AddressResolver::infer_type_from_size(uint64_t size) const {
    auto it = size_index_.find(size);
    if (it == size_index_.end()) return "";  // 无匹配

    if (it->second.size() == 1)
        return types[it->second[0]].name;     // 唯一匹配
    if (it->second.size() > 1)
        return types[it->second[0]].name + " (ambiguous)";  // 多候选
}
```

#### 批量解析（Batch Resolution）

批量解析是 Resolver 的核心工作模式之一，实现**一次加载 DWARF，批量解析所有分配**：

```
1. load_binary(path)          → 构建 TypeInfo 表和 size_index
2. set_alloc_table(allocs)    → 加载 CSV 分配数据
3. 遍历所有分配记录：
   for alloc in allocs:
     resolve(alloc.addr)
     ├── 类型推断（通过 size_index O(1) 查找）
     ├── 获取 TypeInfo
     └── 展开该类型的所有字段 → 每字段输出一行 CSV
4. 输出 resolved.csv
```

批量解析的输出格式：

```
address,size,region,type,field,offset,size_bytes,field_type
0x55a123456000,40,HEAP,Point,Point.x,0,8,double
0x55a123456000,40,HEAP,Point,Point.y,8,8,double
0x55a123456000,40,HEAP,Point,Point.z,16,8,double
0x55a123456000,40,HEAP,Point,Point.label,24,8,char*
0x55a123456000,40,HEAP,Point,Point.count,32,4,int
0x55a123456000,40,HEAP,Point,Point.flags,36,4,int
```

---

## 四、完整执行流程

### 端到端数据流

```
┌─────────────────────────────────────────────────────────────────────┐
│ 阶段一：运行时追踪（eBPF + Collector）                               │
│                                                                     │
│ 1. 目标进程调用 malloc(sizeof(struct Point))                        │
│ 2. eBPF uprobe(malloc_entry): 存储 size=40 到 pending_mallocs[tid] │
│ 3. malloc 返回 addr=0x7f8a3c001000                                 │
│ 4. eBPF uretprobe(malloc_return): 发送 {addr, size=40} 事件        │
│    → Ring Buffer                                                    │
│ 5. Collector 消费事件: hash_table.insert(addr → {size=40, pid})    │
│ 6. 输出 allocs.csv                                                 │
├─────────────────────────────────────────────────────────────────────┤
│ 阶段二：离线分析（DWARF Analyzer + Address Resolver）               │
│                                                                     │
│ 7. 用户执行: batch -b target -f allocs.csv                         │
│ 8. DWARF Analyzer.load_binary():                                    │
│    a. 解析 ELF 符号表 → 符号列表                                   │
│    b. 解析 DWARF .debug_info → 类型数据库 + 字段信息               │
│    c. 构建大小索引 size_index                                       │
│ 9. Address Resolver 加载 allocs.csv                                 │
│ 10. 对每条分配记录:                                                 │
│     a. find_alloc(addr) → {size=40}                                 │
│     b. size_index[40] → struct Point                                │
│     c. 展开 Point 所有 6 个字段                                     │
│ 11. 输出 resolved.csv                                               │
└─────────────────────────────────────────────────────────────────────┘
```

### 用户侧操作流程

```
Step 1: 启动目标进程并追踪
  $ ./bench_target &                        # 启动目标
  $ sudo memscope-collect -p $PID -d 10 -o allocs.csv
                                            # 追踪 10 秒，导出分配数据

Step 2: 检查类型信息
  $ memscope-resolve types -b target        # 列出所有类型
  $ memscope-resolve layout -t Point        # 查看 struct Point 布局

Step 3: 批量解析
  $ memscope-resolve batch -b target -f allocs.csv -o resolved.csv
                                            # 展开所有字段

Step 4: 单地址查询
  $ memscope-resolve resolve -b target -a 0x7f8a3c001048 -f allocs.csv
```

---

## 五、核心原理与技术要点

### 5.1 eBPF uprobe 原理

**uprobe（User-Level Probe）** 是 Linux 内核提供的一种动态追踪技术，允许在内核侧对用户态函数进行探测。当目标函数被调用时，内核触发 BPF 程序执行。

MemScope 利用 uprobe 的两种模式：
- **uprobe（入口探测）**：在函数入口处触发，捕获入参
- **uretprobe（返回探测）**：在函数返回时触发，捕获返回值

通过 `bpf_program__attach_uprobe()` API 附加到 libc.so.6 的指定函数偏移量。

### 5.2 BPF Ring Buffer

BPF Ring Buffer（`BPF_MAP_TYPE_RINGBUF`）是 Linux 5.8+ 引入的高效数据传递机制，相比旧的 `perf_event` 环形缓冲区具有以下优势：
- **内存效率**：共享内存，无需数据拷贝
- **乱序消费安全**：支持生产者和消费者分离
- **可变大小数据**：支持不同大小的消息

MemScope 配置 64MB 的 Ring Buffer 以减少事件丢失。

### 5.3 Murmur3 哈希表

分配表使用 Murmur3 最终混合算法作为哈希函数，将 64 位地址映射到 16 位（64K 个）桶中，通过链式哈希解决冲突。该算法具有：
- **良好的分布性**：减少哈希冲突
- **高效的计算**：仅需乘法和位运算，无需除法

### 5.4 DWARF 类型解析原理

DWARF（Debugging With Attributed Record Formats）是 ELF 二进制文件中常用的调试信息格式。MemScope 利用 DWARF 的以下特性：

- **DIE（Debugging Information Entry）**：每个类型、变量、函数都是一个 DIE
- **DW_AT_type**：类型引用，指示一个变量的类型或一个字段的类型
- **DW_AT_data_member_location**：结构体字段的字节偏移
- **DW_AT_byte_size**：类型或字段的大小
- **DW_TAG_structure_type**：结构体类型标记

解析器递归遍历 DWARF DIE 树，遇到 `DW_TAG_structure_type` 时提取所有 `DW_TAG_member` 子 DIE，构建 `TypeInfo`。

### 5.5 地址分类策略

| 地址分类 | 判定方法 | 数据结构 | 时间复杂度 |
|----------|----------|----------|------------|
| **Global** | 符号表二分查找 | 排序后的 `vector<SymbolInfo>` | O(log n) |
| **Heap** | 分配表二分查找 | 排序后的 `vector<AllocInfo>` | O(log n) |
| **Stack** | CFI 回溯 + DW_AT_location | FDE 记录（当前为桩） | 待实现 |

### 5.6 类型推断策略

| 推断策略 | 方法 | 优先级 | 状态 |
|----------|------|--------|------|
| **直接关联** | 符号的 DW_AT_type | 最高 | 已实现 |
| **调用点推断** | 分析 malloc 的调用栈上下文 | 中 | 桩实现 |
| **大小匹配** | 分配 size → size_index → 类型 | 低 | 已实现 |

---

## 六、性能特性

| 组件 | 优化手段 | 复杂度 |
|------|----------|--------|
| Collector 分配查找 | Murmur3 哈希表（64K 桶） | O(1) |
| Resolver 大小→类型映射 | 预构建 size_index 哈希映射 | O(1) |
| Resolver 分配查找 | 二分查找排序后的分配数组 | O(log n) |
| BPF 事件发送 | malloc 入口不发事件（仅 map 操作） | 约 2x 更少事件 |
| BPF Ring Buffer | 64MB 大缓冲区 | 更少丢包 |
| 批量 DWARF 加载 | 一次解析 + 构建索引 | 均摊 O(1) 每查询 |

---

## 七、构建依赖

| 依赖 | 最低版本 | 用途 |
|------|----------|------|
| Linux Kernel | ≥ 5.8 | BPF Ring Buffer 支持 |
| clang | ≥ 12 | BPF 目标编译 |
| libbpf | ≥ 0.5 | BPF 用户态库 |
| elfutils (libdw, libelf) | — | ELF/DWARF 解析 |
| cmake | ≥ 3.16 | 构建系统 |
| gcc/g++ | C11 / C++17 | 用户态代码编译 |

---

## 八、项目结构

```
memscope/
├── CMakeLists.txt              # 顶层 CMake 配置
├── src/
│   ├── bpf/
│   │   ├── memscope.bpf.c      # eBPF 内核侧程序（uprobe 探针）
│   │   ├── memscope_common.h   # 内核/用户态共享数据结构
│   │   └── vmlinux.h           # 内核类型定义
│   ├── collector/
│   │   ├── main.c              # Collector 主程序（CLI 入口）
│   │   ├── collector.c         # eBPF 加载、事件消费、哈希表构建
│   │   └── collector.h         # Collector API 定义
│   ├── dwarf/
│   │   ├── dwarf_analyzer.cpp  # DWARF 分析引擎
│   │   └── dwarf_analyzer.h    # 分析器接口及数据结构
│   ├── resolver/
│   │   ├── main.cpp            # Resolver CLI（types/layout/resolve/batch/lookup）
│   │   ├── address_resolver.cpp # 地址→字段映射核心逻辑
│   │   └── address_resolver.h  # Resolver API
│   └── benchmark/
│       ├── bench_target.c      # 基准测试目标程序
│       ├── bench_runner.sh     # 基准测试运行脚本
│       └── demo_resolve.sh     # 端到端演示脚本
└── docs/
    ├── architecture.md         # 架构文档
    └── usage.md                # 使用指南
```

---

## 九、总结

MemScope 通过精巧的两阶段设计解决了运行时内存地址到源代码结构体字段的映射问题：

1. **运行时阶段**利用 eBPF 的低开销特性，通过 uprobe 拦截内存分配/释放调用，以极小的性能损耗采集运行时内存行为数据。

2. **离线阶段**利用 DWARF 调试信息的丰富语义，通过类型解析、符号分析、大小索引等技术，将原始的内存地址精确映射到结构体字段级别。

这种 **eBPF + 离线 DWARF 分析** 的组合方案兼具运行时低开销和离线分析深度两大优势，适用于内存泄漏定位、访问模式分析、性能优化等场景。
