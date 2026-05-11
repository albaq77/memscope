# eBPF 底层原理深度剖析——从 MemScope 项目理解内核级动态追踪

> 本文基于 MemScope 项目的实际代码，深入剖析 eBPF 从用户态到内核态的完整工作链路。
> 面向 eBPF 初学者，力求将底层机制讲得足够明白。

---

## 第一章：eBPF 是什么——从"为什么能做到无损"说起

### 1.1 传统监控方式的痛点

在 eBPF 出现之前，如果你想要监控一个正在运行的程序的内存分配行为，你大概有这几种选择：

| 方式 | 原理 | 缺点 |
|------|------|------|
| **修改源码** | 在 malloc/free 调用处插入日志代码 | 需要重新编译、重新部署，侵入性极强 |
| **LD_PRELOAD** | 替换 libc 的 malloc/free 为自己的实现 | 只能拦截动态链接的调用，容易被绕过，且可能引入 bug |
| **ptrace** | 通过内核调试接口单步跟踪目标进程 | 性能极差，可能慢 100 倍以上，不适合生产环境 |
| **内核模块** | 编写 .ko 内核模块直接 hook 系统调用 | 一旦出错直接内核崩溃，风险极高 |

这些方式要么侵入性太强（改源码），要么性能太差（ptrace），要么太危险（内核模块）。

**eBPF 的出现彻底改变了这个局面。**

### 1.2 eBPF 的核心思想：在内核中安全地运行沙箱程序

eBPF（extended Berkeley Packet Filter）的核心思想可以用一句话概括：

> **让你在不修改内核源码、不编写内核模块的前提下，安全地在内核中运行自定义程序。**

打个比方：如果内核是一个正在运行的银行，传统方式要么是"闯进去改规则"（内核模块），要么是"在门口排队问"（ptrace）。而 eBPF 相当于银行给你安排了一个"安全观察室"——你可以看到里面发生的事情，但你不能随意触碰任何东西，你的行为被严格限制。

在 MemScope 项目中，这个"安全观察室"就是 eBPF 程序。它被附加到 `malloc`、`free`、`mmap` 等函数上，当这些函数被调用时，eBPF 程序自动执行，记录下分配的地址、大小、时间戳等信息，然后通过 Ring Buffer 传递给用户态的 Collector。

### 1.3 为什么能做到"无损"——三个关键设计

"无损"并不是说零开销，而是说**开销极小，对被监控程序的行为和数据几乎不产生影响**。这得益于 eBPF 的三个关键设计：

#### 设计一：沙箱隔离——eBPF 程序不能随意访问内存

eBPF 程序运行在一个严格的沙箱中：

- **不能随意读写内核内存**：所有内存访问必须通过 BPF helper 函数，且必须经过验证器检查
- **不能调用任意内核函数**：只能调用内核白名单中的 BPF helper 函数
- **不能修改被监控进程的内存**：eBPF 程序对目标进程的内存是"只读"的

这意味着 eBPF 程序**绝对不会修改你的原始数据**。它只是"看"了一眼，记录下来，然后离开。

#### 设计二：验证器保证——确保程序不会崩溃或死循环

在 eBPF 程序被加载到内核之前，内核的验证器（Verifier）会对程序进行严格的静态检查：

- 检查程序是否有无限循环 → 保证程序一定会终止
- 检查内存访问是否越界 → 保证不会访问非法内存
- 检查指令数量是否超限 → 保证执行时间可控
- 检查栈使用是否超限（512字节）→ 保证不会栈溢出

如果验证不通过，程序根本不会被加载。这就从根源上保证了 eBPF 程序不会导致内核崩溃。

#### 设计三：JIT 编译——将 BPF 字节码翻译为原生机器码

eBPF 程序不是解释执行的，而是通过 JIT（Just-In-Time）编译器翻译为原生机器码后执行的。这意味着：

- 执行速度接近原生 C 代码
- 不需要逐条解释执行，没有解释器的额外开销
- JIT 编译后的代码直接在 CPU 上运行，和普通函数调用一样快

### 1.4 对原始程序和数据的影响分析

#### 对原始程序的影响

eBPF 对原始程序的影响主要来自 **uprobe 插桩**的开销。当你在 `malloc` 函数上附加 uprobe 时，内核会在 `malloc` 的入口处插入一个断点指令（x86_64 上是 `int3`）。每次 `malloc` 被调用时：

1. CPU 执行到 `int3`，触发异常
2. 内核异常处理器接管，保存当前上下文
3. 执行 eBPF 程序（记录 size 等信息）
4. 恢复原始指令，继续执行 `malloc`

这个过程的开销大约是 **1-3 微秒（μs）** 每次。对于一个 `malloc` 本身可能只需要 100 纳秒的操作来说，这确实是一个不可忽视的开销。但请注意：

- 这个开销是**可预测的、恒定的**，不会随着运行时间增长
- 如果你只追踪特定 PID（MemScope 支持 `-p` 参数），其他进程完全不受影响
- 对于大多数生产环境来说，1-3μs 的开销是可以接受的

#### 对原始数据的影响

**eBPF 对原始数据的影响为零。** 原因如下：

1. eBPF 程序运行在内核的沙箱中，**无法修改用户态进程的内存**
2. uprobe 只是在函数入口/出口处"拦截"调用，**不会改变函数的输入参数或返回值**
3. MemScope 的 eBPF 程序只做"读取"操作：读取 `size` 参数、读取返回的 `addr`、读取 `free` 的参数——**从未写入任何用户态数据**

用 MemScope 的代码来验证这一点：

```c
// memscope.bpf.c - uprobe_malloc_entry
SEC("uprobe/libc.so.6:malloc")
int BPF_KPROBE(uprobe_malloc_entry, __u64 size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    bpf_map_update_elem(&pending_mallocs, &tid, &size, BPF_ANY);
    return 0;
}
```

这段代码做的事情是：读取 `size` 参数，写入 BPF Map。它**完全没有触碰**目标进程的任何内存。

---

## 第二章：eBPF 从用户态到内核态的完整工作链路

这一章是全文的核心。我们将跟踪一个 eBPF 程序从"一行 C 代码"到"在内核中运行"的完整旅程，每一步都结合 MemScope 的实际代码来说明。

### 完整链路总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        eBPF 完整工作链路                                      │
│                                                                             │
│  ① 编写    ② 编译         ③ 加载           ④ 验证        ⑤ JIT 编译        │
│  BPF C  ──────→ BPF   ──────→ bpf()   ──────→ Verifier ──────→ 原生      │
│  源码     clang    字节码    系统调用    检查      通过      机器码          │
│                                                                             │
│  ⑥ 附加                  ⑦ 执行                    ⑧ 数据传输              │
│  attach 到 ──────→ 目标函数被调用时 ──────→ Ring Buffer ──────→ 用户态    │
│  内核钩子     自动触发 BPF 程序         传递事件数据        Collector      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 编写阶段：BPF C 源码

eBPF 程序用 C 语言编写，但有一些特殊约束：

- 必须使用 `SEC()` 宏声明程序类型和挂载点
- 不能有无限循环
- 不能调用任意内核函数，只能用 BPF helper
- 栈大小限制为 512 字节

MemScope 的 eBPF 程序定义了 5 个探测函数，我们以 `uprobe_malloc_entry` 为例：

```c
// src/bpf/memscope.bpf.c
SEC("uprobe/libc.so.6:malloc")
int BPF_KPROBE(uprobe_malloc_entry, __u64 size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    bpf_map_update_elem(&pending_mallocs, &tid, &size, BPF_ANY);
    return 0;
}
```

**逐行解读：**

| 代码 | 含义 |
|------|------|
| `SEC("uprobe/libc.so.6:malloc")` | 声明这是一个 uprobe 类型的 BPF 程序，挂载到 libc.so.6 的 malloc 函数 |
| `BPF_KPROBE(uprobe_malloc_entry, __u64 size)` | 函数名和参数，`size` 是 malloc 的第一个参数 |
| `bpf_get_current_pid_tgid()` | BPF helper 函数，获取当前进程的 PID 和 TID |
| `bpf_map_update_elem(&pending_mallocs, ...)` | 将 size 写入 BPF Map，以 TID 为键 |

同时，eBPF 程序还需要声明使用的 BPF Maps：

```c
// src/bpf/memscope.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 26);  // 64MB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENTS);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct alloc_info));
} active_allocs SEC(".maps");
```

这些 Map 定义会被编译到 BPF 对象文件的 `.maps` section 中，加载时由内核自动创建。

### 2.2 编译阶段：BPF C → BPF 字节码

BPF C 源码需要通过 clang 编译器编译为 BPF 字节码。MemScope 的 CMake 配置如下：

```cmake
# src/bpf/CMakeLists.txt
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/memscope.bpf.o
    COMMAND ${CLANG_BIN}
        -g -O2 -target bpf
        -D__TARGET_ARCH_${MEMSCOPE_BPF_ARCH}
        -I${CMAKE_CURRENT_SOURCE_DIR}
        -I/usr/include/${MEMSCOPE_ARCH_NAME}-linux-gnu
        -c ${CMAKE_CURRENT_SOURCE_DIR}/memscope.bpf.c
        -o ${CMAKE_CURRENT_BINARY_DIR}/memscope.bpf.o
    ...
)
```

**关键编译参数解读：**

| 参数 | 含义 |
|------|------|
| `-target bpf` | 编译目标为 BPF 字节码（而非 x86_64 或 ARM64） |
| `-O2` | 优化级别，BPF 程序必须开启优化以通过验证器 |
| `-g` | 生成调试信息，用于后续的符号解析 |
| `-D__TARGET_ARCH_x86` | 定义目标架构，BPF helper 需要知道底层架构 |

编译后的 `memscope.bpf.o` 是一个 ELF 格式的目标文件，其中包含：

- `.text` section：BPF 字节码指令
- `.maps` section：BPF Map 定义
- `uprobe/libc.so.6:malloc` section：uprobe 程序
- `license` section：许可证信息

你可以用 `llvm-objdump -S memscope.bpf.o` 查看编译后的 BPF 字节码。

### 2.3 加载阶段：用户态通过 libbpf 加载 BPF 对象

编译好的 BPF 对象文件需要从用户态加载到内核中。MemScope 的 Collector 负责这个过程：

```c
// src/collector/collector.c - collector_init()

// 第一步：打开 BPF 对象文件，解析 ELF 中的 BPF section
struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
if (libbpf_get_error(obj)) {
    fprintf(stderr, "failed to open BPF object: %s\n", bpf_obj_path);
    return NULL;
}

// 第二步：加载 BPF 对象到内核
// 这一步会：创建 Maps → 提交程序到验证器 → JIT 编译
if (bpf_object__load(obj)) {
    fprintf(stderr, "failed to load BPF object\n");
    bpf_object__close(obj);
    return NULL;
}
```

**`bpf_object__open_file()` 做了什么？**

1. 解析 ELF 文件格式
2. 识别 BPF section（uprobe、maps 等）
3. 创建 libbpf 内部的 bpf_object 数据结构
4. 此时还没有和内核交互

**`bpf_object__load()` 做了什么？**

1. 对每个 BPF Map，调用 `bpf()` 系统调用创建内核 Map 对象
2. 对每个 BPF 程序，调用 `bpf()` 系统调用提交到内核
3. 内核验证器检查程序安全性
4. 验证通过后，JIT 编译器将 BPF 字节码翻译为原生机器码
5. 返回程序和 Map 的文件描述符（fd）

**`bpf()` 系统调用是用户态和内核态的分界线。** 当用户态调用 `bpf()` 时，控制权转移到内核，内核执行验证、JIT 编译等操作。

### 2.4 验证阶段：内核验证器（Verifier）的严格检查

验证器是 eBPF 安全的核心保障。当 `bpf_object__load()` 将 BPF 程序提交到内核时，验证器会对程序进行全面的静态分析。

#### 验证器检查什么？

| 检查项 | 限制 | 原因 |
|--------|------|------|
| 指令数量 | ≤ 100 万条（5.2+ 内核） | 防止程序执行时间过长 |
| 无限循环 | 不允许（5.3+ 内核允许有界循环） | 保证程序一定会终止 |
| 栈大小 | ≤ 512 字节 | 防止栈溢出 |
| 内存访问 | 必须在已验证的范围内 | 防止越界读写 |
| 指针运算 | 限制指针算术操作 | 防止构造非法指针 |
| 未初始化读取 | 不允许 | 防止信息泄露 |
| 不可达代码 | 不允许 | 简化验证 |

#### 验证器如何工作？

验证器采用**抽象解释（Abstract Interpretation）**的方法：

1. **构建控制流图（CFG）**：将 BPF 程序分解为基本块和跳转边
2. **模拟执行所有可能路径**：对每条路径，跟踪每个寄存器和栈槽的状态
3. **状态跟踪**：对每个寄存器，记录其可能的值范围（最小值、最大值）、类型（指针、标量等）
4. **路径剪枝**：如果某条路径不可能到达（条件永远为假），则剪掉

这个过程类似于"在脑海中走一遍所有可能的执行路径，确保每条路径都是安全的"。

#### MemScope 代码中的验证器友好写法

MemScope 的 BPF 代码中有几处专门为验证器编写的检查：

```c
// memscope.bpf.c - uretprobe_malloc_return
if (!addr)
    return 0;  // ← 验证器要求：使用返回值前必须检查 NULL

size_ptr = bpf_map_lookup_elem(&pending_mallocs, &tid);
if (!size_ptr)
    return 0;  // ← 验证器要求：使用 map 查找结果前必须检查 NULL
```

如果不写这些检查，验证器会拒绝加载程序，因为它无法确定 `addr` 或 `size_ptr` 是否为 NULL，如果为 NULL 则可能导致内核崩溃。

### 2.5 JIT 编译阶段：BPF 字节码 → 原生机器码

验证通过后，JIT 编译器将 BPF 字节码翻译为当前 CPU 架构的原生机器码。

#### 为什么需要 JIT？

BPF 字节码是一种虚拟指令集，CPU 不能直接执行。有两种执行方式：

| 方式 | 原理 | 性能 |
|------|------|------|
| **解释执行** | 内核中的解释器逐条读取 BPF 指令并执行 | 慢，每条指令需要额外的分派开销 |
| **JIT 编译** | 将 BPF 指令一次性翻译为原生机器码，直接在 CPU 上执行 | 快，接近原生 C 代码 |

JIT 编译后的代码就像普通的内核函数一样执行，没有额外的解释开销。

#### JIT 编译过程

以 x86_64 为例，BPF 寄存器到 x86_64 寄存器的映射：

| BPF 寄存器 | x86_64 寄存器 | 用途 |
|------------|---------------|------|
| r0 | rax | 返回值 |
| r1-r5 | rdi, rsi, rdx, rcx, r8 | 函数参数 |
| r6-r9 | rbx, r13, r14, r15 | 被调用者保存寄存器 |
| r10 | rbp | 栈帧指针（只读） |

JIT 编译器会进行一些优化：
- **常量折叠**：编译时已知的常量直接内联
- **死代码消除**：删除不会执行的代码
- **指令合并**：将多条 BPF 指令合并为一条 x86_64 指令

### 2.6 附加阶段：将 BPF 程序挂载到内核钩子

JIT 编译完成后，BPF 程序已经在内核中了，但还没有"挂"到任何地方。需要通过 `attach` 操作将程序附加到指定的内核钩子。

MemScope 的 Collector 在 `attach_uprobes()` 中完成附加：

```c
// src/collector/collector.c - attach_uprobes()

struct bpf_link *link = bpf_program__attach_uprobe(
    prog,           // BPF 程序
    probes[i].retprobe,  // 是否是 return probe
    -1,             // PID（-1 表示所有进程）
    libc_path,      // 目标二进制路径
    offset          // 函数在二进制中的偏移量
);
```

**`bpf_program__attach_uprobe()` 内部做了什么？**

1. libbpf 调用 `bpf()` 系统调用创建一个 perf event
2. perf event 的类型设置为 `PERF_TYPE_TRACEPOINT` 或通过 `ioctl(PERF_EVENT_IOC_SET_BPF)` 关联 BPF 程序
3. 内核在目标函数的入口处插入断点指令
4. 当目标函数被调用时，断点触发，内核执行 BPF 程序

**如何找到函数偏移量？** MemScope 使用 `objdump` 工具：

```c
// src/collector/collector.c - find_func_offset()
snprintf(cmd, sizeof(cmd),
    "objdump -T %s 2>/dev/null | grep ' %s$' | awk '{print $1}'",
    binary_path, func_name);
```

这会调用 `objdump -T /lib/x86_64-linux-gnu/libc.so.6 | grep ' malloc$'` 来获取 malloc 函数在 libc 中的偏移量。

### 2.7 执行阶段：目标函数被调用时自动触发 BPF 程序

当一切就绪后，BPF 程序就"潜伏"在目标函数旁边了。每当目标进程调用 `malloc`：

```
目标进程调用 malloc(40)
    │
    ▼
CPU 执行到 malloc 入口的 int3 断点
    │
    ▼
触发 #BP 异常，内核接管
    │
    ▼
内核执行 uprobe 处理器
    │
    ├── 保存当前寄存器上下文
    ├── 调用 BPF 程序 uprobe_malloc_entry
    │   ├── bpf_get_current_pid_tgid() → 获取 PID/TID
    │   └── bpf_map_update_elem(&pending_mallocs, &tid, &size) → 保存 size
    │
    ├── 恢复原始指令
    ├── 单步执行原始指令（跳过断点）
    └── 恢复断点，继续执行 malloc 函数体
```

当 malloc 返回时：

```
malloc 返回 addr=0x7f8a3c001000
    │
    ▼
CPU 执行到 uretprobe trampoline
    │
    ▼
内核执行 BPF 程序 uretprobe_malloc_return
    │
    ├── bpf_map_lookup_elem(&pending_mallocs, &tid) → 读出 size=40
    ├── bpf_map_delete_elem(&pending_mallocs, &tid) → 清理
    ├── bpf_map_update_elem(&active_allocs, &addr, &info) → 记录活跃分配
    └── bpf_ringbuf_output(&events, &evt) → 发送事件到 Ring Buffer
```

### 2.8 数据传输阶段：Ring Buffer 机制

BPF 程序执行完毕后，需要将采集到的数据传递给用户态。MemScope 使用 BPF Ring Buffer：

```c
// src/bpf/memscope.bpf.c - emit_event()
static __always_inline void emit_event(void *ctx, struct mem_event *evt)
{
    bpf_ringbuf_output(&events, evt, sizeof(*evt), 0);
}
```

用户态的 Collector 通过 `ring_buffer__poll()` 消费事件：

```c
// src/collector/collector.c - collector_init()
ctx->ringbuf = ring_buffer__new(ctx->ringbuf_fd, handle_event, ctx, NULL);

// src/collector/collector.c - collector_poll()
int collector_poll(struct collector_ctx *ctx, int timeout_ms)
{
    return ring_buffer__poll(ctx->ringbuf, timeout_ms);
}
```

`handle_event` 回调函数处理每种事件类型，将数据写入用户态的分配哈希表。

---

## 第三章：uprobe 插桩的底层实现原理

uprobe 是 MemScope 的核心技术基础。理解 uprobe 的底层实现，才能真正理解 eBPF 是如何做到"无损"的。

### 3.1 uprobe 注册过程

当 MemScope 的 Collector 调用 `bpf_program__attach_uprobe()` 时，内核侧发生了以下事情：

```
bpf_program__attach_uprobe(prog, 0, -1, "/lib/x86_64-linux-gnu/libc.so.6", offset)
    │
    ▼ libbpf 内部
创建 perf_event (type=PERF_TYPE_BREAKPOINT)
    │
    ▼ 内核
1. 解析目标文件的 ELF，找到 offset 处的指令
2. 在内核的 uprobes 数据结构中注册这个探测点
3. 调用 install_breakpoint()：
   a. 将 offset 处的原始指令保存到内核中
   b. 将该位置替换为 int3 指令（0xCC）
4. 返回 perf_event fd
```

**关键理解：** uprobe 的工作原理是**修改目标函数的机器码**，在函数入口处插入 `int3` 断点指令。但这个修改是在内存中的，不会修改磁盘上的二进制文件。

### 3.2 uprobe 触发过程

当目标进程执行到被插桩的函数入口时：

```
CPU 执行到 0x7f...xxx 处的 int3 指令 (0xCC)
    │
    ▼
CPU 触发 #BP (Breakpoint) 异常
    │
    ▼
内核异常处理器 do_int3()
    │
    ▼
通知 perf_event 子系统
    │
    ▼
uprobe 处理器 handler_chain()
    │
    ├── 1. 保存当前寄存器上下文（pt_regs）
    ├── 2. 执行所有注册的 BPF 程序
    │      └── uprobe_malloc_entry(ctx, size)
    ├── 3. 临时恢复原始指令（去掉 int3）
    ├── 4. 设置 CPU 单步执行标志（TF=1）
    ├── 5. 返回，CPU 单步执行原始指令
    │
    ▼
CPU 执行完原始指令后触发 #DB (Debug) 异常
    │
    ▼
内核清除单步标志，重新插入 int3 断点
    │
    ▼
CPU 继续执行 malloc 函数的剩余部分
```

**这个过程的开销主要来自：**
1. 两次异常处理（#BP 和 #DB）
2. 上下文保存和恢复
3. BPF 程序执行
4. 单步执行和断点恢复

总计约 **1-3 微秒**，其中大部分开销来自异常处理，而非 BPF 程序本身。

### 3.3 uretprobe 的实现

uretprobe（返回探测）的实现比 uprobe 更巧妙。它不是在函数入口插断点，而是**劫持函数的返回地址**。

```
uprobe 注册 uretprobe 时：
1. 读取函数入口处，保存原始指令
2. 读取栈上的返回地址，保存到内核中
3. 将栈上的返回地址替换为 trampoline 地址

函数执行到 ret 指令时：
    │
    ▼
CPU 跳转到 trampoline（内核提供的特殊代码）
    │
    ▼
trampoline 触发异常，内核接管
    │
    ▼
内核执行所有注册的 BPF 程序
│   └── uretprobe_malloc_return(ctx, ret)
│       └── ret 就是 malloc 的返回值（分配的地址）
    │
    ▼
内核恢复原始返回地址，CPU 跳回调用者
```

**为什么 MemScope 需要同时使用 uprobe 和 uretprobe？**

因为 `malloc` 函数的入参是 `size`（分配大小），返回值是 `addr`（分配地址）。这两个信息分别在不同的时机可用：

- **uprobe（入口）**：只能获取 `size`
- **uretprobe（返回）**：只能获取 `addr`

MemScope 的巧妙设计是：在 uprobe 中将 `size` 保存到 `pending_mallocs` Map 中（以 TID 为键），在 uretprobe 中读出 `size` 并和 `addr` 一起发送事件。这样只需要发送一次 Ring Buffer 事件，而不是两次。

### 3.4 MemScope 的 malloc/free 追踪流程详解

让我们完整走一遍 MemScope 追踪 `malloc(sizeof(struct Point))` 的过程：

```
时间线：
─────────────────────────────────────────────────────────────────→

T1: 目标进程调用 malloc(40)
    │
    ├─→ uprobe_malloc_entry 触发
    │   ├── pid_tgid = bpf_get_current_pid_tgid()  // PID=1234, TID=1234
    │   ├── tid = 1234
    │   └── pending_mallocs[1234] = 40              // 保存 size
    │
T2: malloc 内部执行，分配内存
    │
T3: malloc 返回 addr=0x55a123456000
    │
    ├─→ uretprobe_malloc_return 触发
    │   ├── pid_tgid = bpf_get_current_pid_tgid()   // PID=1234, TID=1234
    │   ├── addr = 0x55a123456000                   // malloc 返回值
    │   ├── size_ptr = pending_mallocs[1234]         // 读出之前保存的 size
    │   ├── size_val = 40
    │   ├── delete pending_mallocs[1234]             // 清理
    │   ├── active_allocs[0x55a123456000] = {size=40, pid=1234, tid=1234, ...}
    │   └── emit_event(EVENT_MALLOC_RETURN, {addr, size=40})
    │       └── bpf_ringbuf_output(&events, &evt)   // 发送到 Ring Buffer
    │
T4: Collector 消费 Ring Buffer 事件
    │
    ├─→ handle_event() 被调用
    │   ├── evt->type == EVENT_MALLOC_RETURN
    │   ├── alloc_record rec = {addr=0x55a123456000, size=40, live=1, ...}
    │   └── add_alloc_record(&ctx->table, &rec)     // 插入哈希表
    │
T5: 目标进程调用 free(0x55a123456000)
    │
    ├─→ uprobe_free 触发
    │   ├── addr = 0x55a123456000
    │   ├── info = active_allocs[0x55a123456000]    // 查找活跃分配
    │   ├── completed_allocs[0x55a123456000] = info  // 移到已完成
    │   ├── delete active_allocs[0x55a123456000]
    │   └── emit_event(EVENT_FREE, {addr=0x55a123456000})
    │
T6: Collector 消费 free 事件
    │
    ├─→ handle_event() 被调用
    │   ├── evt->type == EVENT_FREE
    │   ├── rec = find_live_alloc(addr=0x55a123456000)
    │   └── rec->live = 0; rec->timestamp_free = ...  // 标记为已释放
```

---

## 第四章：BPF Maps——内核态与用户态的数据桥梁

BPF Map 是 eBPF 程序和用户态程序之间共享数据的核心机制。可以把 BPF Map 理解为**内核中的键值存储**，内核态的 BPF 程序和用户态的应用程序都可以读写同一个 Map。

### 4.1 BPF Map 的本质

BPF Map 在内核中是一块共享内存，由内核管理其生命周期。它的特点：

- **内核态创建**：通过 `bpf()` 系统调用创建
- **双向访问**：内核态 BPF 程序和用户态程序都可以读写
- **类型多样**：Hash、Array、Ring Buffer、Stack Trace 等
- **并发安全**：内核使用 RCU 和自旋锁保证并发安全

### 4.2 MemScope 使用的五种 Map 类型详解

MemScope 定义了 5 个 BPF Map，每个都有不同的用途：

#### Map 1：events（Ring Buffer）

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 26);  // 64MB
} events SEC(".maps");
```

**用途**：将事件从内核态流式传输到用户态。

**为什么用 Ring Buffer 而不是旧版 perf_event？**

| 特性 | perf_event buffer | BPF Ring Buffer |
|------|-------------------|-----------------|
| 数据大小 | 固定大小 | 可变大小 |
| 内存拷贝 | 需要额外拷贝 | 零拷贝（mmap） |
| 乱序消费 | 不安全 | 安全（预留/提交协议） |
| 多生产者 | 需要每 CPU 一个 | 全局共享 |

MemScope 配置了 64MB 的 Ring Buffer，以减少事件丢失的可能性。

#### Map 2：stack_traces（栈追踪）

```c
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_EVENTS);  // 16384
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));  // 64 * 8 = 512 bytes
} stack_traces SEC(".maps");
```

**用途**：捕获调用栈。BPF 程序调用 `bpf_get_stackid()` 时，内核会遍历栈帧，将返回地址存入此 Map。

**工作原理**：
1. BPF 程序调用 `bpf_get_stackid(ctx, &stack_traces, flags)`
2. 内核遍历当前线程的栈帧，收集返回地址
3. 对栈内容计算哈希，作为 key
4. 将栈帧数组作为 value 存储
5. 返回 stack_id 给 BPF 程序

用户态可以通过 `bpf_map_lookup_elem(stack_map_fd, &stack_id, values)` 读出栈帧地址。

#### Map 3-5：Hash Maps（状态追踪）

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENTS);  // 16384
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct alloc_info));
} active_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENTS);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct alloc_info));
} completed_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} pending_mallocs SEC(".maps");
```

**用途**：

| Map | Key | Value | 用途 |
|-----|-----|-------|------|
| `active_allocs` | 分配地址（u64） | alloc_info | 追踪当前活跃的分配 |
| `completed_allocs` | 分配地址（u64） | alloc_info | 记录已释放的分配（事后分析） |
| `pending_mallocs` | 线程 TID（u32） | size（u64） | 匹配 malloc 入口和返回 |

**pending_mallocs 的工作流程**：

```
malloc(40) 入口 → pending_mallocs[TID] = 40
malloc 返回 addr → size = pending_mallocs[TID]; delete pending_mallocs[TID]
```

这是一个典型的"跨两个探针传递数据"的模式。

### 4.3 Map 的用户态访问

用户态通过 libbpf 提供的 API 访问 BPF Map：

```c
// 获取 Map 的文件描述符
struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "events");
ctx->ringbuf_fd = bpf_map__fd(events_map);

// 查找 Map 中的元素
int err = bpf_map_lookup_elem(ctx->stack_map_fd, &key, values);

// 更新 Map 中的元素
bpf_map_update_elem(&active_allocs, &addr, &info, BPF_ANY);

// 删除 Map 中的元素
bpf_map_delete_elem(&pending_mallocs, &tid);
```

### 4.4 Map 的内核态访问

BPF 程序通过 BPF helper 函数访问 Map：

```c
// 查找
size_ptr = bpf_map_lookup_elem(&pending_mallocs, &tid);

// 更新
bpf_map_update_elem(&active_allocs, &addr, &info, BPF_ANY);

// 删除
bpf_map_delete_elem(&pending_mallocs, &tid);

// Ring Buffer 输出
bpf_ringbuf_output(&events, evt, sizeof(*evt), 0);

// 获取栈 ID
bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP);
```

---

## 第五章：验证器（Verifier）——eBPF 安全的守护者

### 5.1 为什么需要验证器

内核是操作系统的核心，如果内核崩溃，整个系统都会崩溃。传统内核模块的一个 bug 就可能导致整个系统死机。eBPF 的设计目标是让普通用户也能安全地在内核中运行代码，这就需要一个机制来保证：

1. **eBPF 程序不会导致内核崩溃**
2. **eBPF 程序不会无限执行**
3. **eBPF 程序不会泄露内核数据**

验证器就是实现这三个保证的核心组件。

### 5.2 验证器的工作流程

验证器的工作可以分为三个阶段：

#### 阶段一：控制流图（CFG）构建

验证器首先将 BPF 程序分解为基本块（Basic Block），构建控制流图：

```
基本块1: uprobe_malloc_entry 入口
    │
    ├── bpf_get_current_pid_tgid()
    ├── tid = pid_tgid & 0xFFFFFFFF
    ├── bpf_map_update_elem(...)
    └── return 0

基本块2: uretprobe_malloc_return 入口
    │
    ├── if (!addr) → 基本块3 (return 0)
    ├── size_ptr = bpf_map_lookup_elem(...)
    ├── if (!size_ptr) → 基本块3 (return 0)
    ├── ... 正常处理逻辑 ...
    └── return 0

基本块3: return 0
```

#### 阶段二：路径探索与状态跟踪

验证器模拟执行所有可能的路径。对于每条路径，它跟踪：

- **每个寄存器的状态**：类型（指针/标量/NULL）、值范围（最小值、最大值）
- **每个栈槽的状态**：是否已初始化、类型
- **程序的执行深度**：防止无限递归

例如，对于 `uretprobe_malloc_return`：

```
路径1: addr == NULL → return 0 (安全)
路径2: addr != NULL, size_ptr == NULL → return 0 (安全)
路径3: addr != NULL, size_ptr != NULL → 正常处理 (需要继续验证)
```

验证器会确保**所有路径**都是安全的。

#### 阶段三：寄存器状态追踪

验证器对每个寄存器维护一个"状态"，包括：

- **类型**：NOT_INIT（未初始化）、SCALAR_VALUE（标量）、PTR_TO_CTX（上下文指针）、PTR_TO_MAP_VALUE（Map 值指针）等
- **值范围**：umin, umax, smin, smax（无符号/有符号的最小/最大值）

当 BPF 程序执行 `if (!size_ptr) return 0;` 后，验证器知道在 if 之后，`size_ptr` 一定不为 NULL。这样后续对 `size_ptr` 的解引用就是安全的。

### 5.3 常见验证失败原因及解决方法

#### 原因一：未检查指针是否为 NULL

```c
// ❌ 验证失败
size_ptr = bpf_map_lookup_elem(&pending_mallocs, &tid);
size_val = *size_ptr;  // size_ptr 可能为 NULL！

// ✅ 验证通过
size_ptr = bpf_map_lookup_elem(&pending_mallocs, &tid);
if (!size_ptr)
    return 0;
size_val = *size_ptr;  // 验证器知道 size_ptr 不为 NULL
```

MemScope 中所有 `bpf_map_lookup_elem()` 的返回值都有 NULL 检查。

#### 原因二：越界访问

```c
// ❌ 验证失败
struct mem_event *evt = ...;
evt[100].type = 1;  // 可能越界

// ✅ 验证通过
struct mem_event evt = {};  // 在栈上分配，大小已知
evt.type = EVENT_MALLOC_RETURN;
```

MemScope 中所有事件都是在栈上分配的局部变量，大小已知，不会越界。

#### 原因三：无限循环

```c
// ❌ 验证失败（5.3 之前的内核）
while (1) { ... }

// ✅ 验证通过（有界循环，5.3+ 内核）
for (int i = 0; i < MAX_STACK_DEPTH; i++) { ... }
```

MemScope 的 BPF 程序中没有循环，所以不存在这个问题。

#### 原因四：栈溢出

```c
// ❌ 验证失败
char big_buffer[1024];  // 超过 512 字节限制

// ✅ 验证通过
struct mem_event evt = {};  // 大小约 100 字节，远小于 512 字节限制
```

MemScope 中最大的栈分配是 `struct mem_event`，大小约 100 字节，远小于 512 字节限制。

### 5.4 结合 MemScope 代码看验证器如何通过

让我们逐行分析 `uretprobe_malloc_return` 为什么能通过验证器：

```c
SEC("uretprobe/libc.so.6:malloc")
int BPF_KRETPROBE(uprobe_malloc_return, void *ret)
{
    struct mem_event evt = {};          // ① 栈分配，大小已知，验证器满意
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 addr = (__u64)ret;
    __u64 *size_ptr;
    __u64 size_val;

    if (!addr)                          // ② 检查 addr 是否为 NULL
        return 0;                       //    如果为 NULL，直接返回，安全

    size_ptr = bpf_map_lookup_elem(&pending_mallocs, &tid);
    if (!size_ptr)                      // ③ 检查 map 查找结果是否为 NULL
        return 0;                       //    如果为 NULL，直接返回，安全

    size_val = *size_ptr;               // ④ 此时验证器知道 size_ptr 不为 NULL
                                        //    解引用是安全的
    bpf_map_delete_elem(&pending_mallocs, &tid);

    struct alloc_info info = {};        // ⑤ 栈分配，大小已知
    info.size = size_val;
    // ... 填充 info ...

    bpf_map_update_elem(&active_allocs, &addr, &info, BPF_ANY);

    evt.type = EVENT_MALLOC_RETURN;
    // ... 填充 evt ...

    emit_event(ctx, &evt);              // ⑥ bpf_ringbuf_output，大小已知
    return 0;
}
```

每一步都是验证器友好的：没有未检查的指针、没有越界访问、没有无限循环、栈使用远小于 512 字节。

---

## 第六章：JIT 编译——从字节码到机器码

### 6.1 BPF 指令集架构

BPF 指令集是一个精简的 RISC 风格指令集，设计目标是既能在内核中高效执行，又便于验证器分析。

#### 寄存器

BPF 有 10 个 64 位通用寄存器：

| 寄存器 | 用途 | 对应 x86_64 |
|--------|------|-------------|
| r0 | 返回值 | rax |
| r1 | 第 1 个参数 | rdi |
| r2 | 第 2 个参数 | rsi |
| r3 | 第 3 个参数 | rdx |
| r4 | 第 4 个参数 | rcx |
| r5 | 第 5 个参数 | r8 |
| r6-r9 | 被调用者保存 | rbx, r13, r14, r15 |
| r10 | 栈帧指针（只读） | rbp |

#### 指令格式

每条 BPF 指令固定 8 字节：

```
+--------+--------+--------+--------+--------+--------+--------+--------+
| opcode |  regs  | offset16           | immediate32                        |
| 8 bit  | 8 bit  | 16 bit             | 32 bit                            |
+--------+--------+--------+--------+--------+--------+--------+--------+
```

- **opcode**：操作码（加载、存储、算术、跳转等）
- **regs**：源寄存器和目标寄存器
- **offset16**：偏移量（用于内存访问和跳转）
- **immediate32**：立即数

### 6.2 JIT 编译过程

JIT 编译器将 BPF 字节码翻译为 x86_64 机器码。以一个简单的例子说明：

**BPF 字节码：**
```
mov64 r0, 0          // r0 = 0
exit                  // 返回 r0
```

**JIT 编译后的 x86_64 机器码：**
```
xor eax, eax         // r0 = 0（xor 比 mov 0 更短更快）
ret                   // 返回
```

JIT 编译器会进行以下优化：

1. **常量折叠**：编译时已知的常量直接计算
2. **死代码消除**：删除不会执行的代码
3. **指令选择**：选择更短的等价指令（如 xor 代替 mov 0）
4. **寄存器分配**：将 BPF 寄存器映射到 x86_64 寄存器

### 6.3 JIT 后的执行效率

JIT 编译后的 BPF 程序执行效率接近原生 C 代码。原因是：

1. **直接执行**：编译后的机器码直接在 CPU 上执行，没有解释器开销
2. **优化**：JIT 编译器会进行常量折叠、死代码消除等优化
3. **内联**：BPF helper 函数调用会被优化为直接调用内核函数

实际测量中，一个简单的 BPF 程序（如 MemScope 的 uprobe_malloc_entry）执行时间约 **200-500 纳秒**，其中大部分时间花在 BPF helper 函数（如 `bpf_map_update_elem`）上，而非 BPF 程序本身。

---

## 第七章：Ring Buffer——高效的数据传输管道

### 7.1 Ring Buffer 的内存布局

BPF Ring Buffer 是一块环形内存区域，由内核和用户态共享：

```
┌──────────────────────────────────────────────────────────────┐
│                    Ring Buffer 内存布局                        │
│                                                              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │ header  │ │ header  │ │ header  │ │ header  │  ...       │
│  │ len=32  │ │ len=64  │ │ len=48  │ │ (free)  │           │
│  ├─────────┤ ├─────────┤ ├─────────┤ ├─────────┤           │
│  │ data    │ │ data    │ │ data    │ │         │           │
│  │ 32B     │ │ 64B     │ │ 48B     │ │         │           │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘           │
│                                                              │
│  ↑ consumer_pos                          producer_pos ↑      │
│  (用户态读位置)                          (内核态写位置)       │
└──────────────────────────────────────────────────────────────┘
```

每个记录由两部分组成：
- **header**：8 字节，包含记录长度和标志位
- **data**：实际数据，长度可变

### 7.2 零拷贝机制

Ring Buffer 实现零拷贝的关键是 **mmap**：

1. 用户态通过 `mmap()` 将 Ring Buffer 的内核内存映射到用户态地址空间
2. 内核写入数据时，直接写入这块共享内存
3. 用户态读取数据时，直接从这块共享内存读取
4. **全程没有数据拷贝**

对比旧版 perf_event buffer：
- perf_event 需要将数据从内核缓冲区拷贝到用户态缓冲区
- 每次读取都需要一次 `read()` 系统调用

### 7.3 可变大小记录

Ring Buffer 支持可变大小的记录，这对 MemScope 非常重要：

```c
// MemScope 的事件大小是固定的（sizeof(struct mem_event)）
bpf_ringbuf_output(&events, evt, sizeof(*evt), 0);

// 但 Ring Buffer 也支持不同大小的事件
// 例如，一个程序可能发送 32 字节的事件，另一个发送 128 字节的事件
```

旧版 perf_event buffer 只支持固定大小的事件，这导致：
- 如果事件较小，会浪费空间
- 如果事件较大，需要拆分

Ring Buffer 的可变大小设计完美解决了这个问题。

### 7.4 MemScope 中的 Ring Buffer 使用

MemScope 的 Ring Buffer 使用分为内核态写入和用户态读取两部分：

**内核态写入（BPF 程序）：**

```c
// src/bpf/memscope.bpf.c
static __always_inline void emit_event(void *ctx, struct mem_event *evt)
{
    bpf_ringbuf_output(&events, evt, sizeof(*evt), 0);
}
```

`bpf_ringbuf_output()` 的工作流程：
1. 在 Ring Buffer 中预留 `sizeof(*evt)` 字节的空间
2. 将 `evt` 的内容拷贝到预留空间
3. 提交记录，更新 producer_pos

**用户态读取（Collector）：**

```c
// src/collector/collector.c

// 创建 Ring Buffer 消费者
ctx->ringbuf = ring_buffer__new(ctx->ringbuf_fd, handle_event, ctx, NULL);

// 轮询 Ring Buffer
int collector_poll(struct collector_ctx *ctx, int timeout_ms)
{
    return ring_buffer__poll(ctx->ringbuf, timeout_ms);
}
```

`ring_buffer__poll()` 的工作流程：
1. 检查 producer_pos 是否大于 consumer_pos
2. 如果有新数据，遍历记录，对每条记录调用 `handle_event` 回调
3. 更新 consumer_pos

**handle_event 回调：**

```c
static int handle_event(void *ctx, void *data, size_t size)
{
    struct collector_ctx *cctx = (struct collector_ctx *)ctx;
    struct mem_event *evt = (struct mem_event *)data;

    if (cctx->target_pid && evt->pid != cctx->target_pid)
        return 0;  // 过滤非目标 PID

    switch (evt->type) {
    case EVENT_MALLOC_RETURN: {
        struct alloc_record rec = {};
        rec.addr = evt->malloc_ret.addr;
        rec.size = evt->malloc_ret.size;
        rec.timestamp_alloc = evt->timestamp;
        rec.live = 1;
        add_alloc_record(&cctx->table, &rec);
        break;
    }
    case EVENT_FREE: {
        struct alloc_record *rec = find_live_alloc(&cctx->table, evt->free_evt.addr);
        if (rec) {
            rec->live = 0;
            rec->timestamp_free = evt->timestamp;
        }
        break;
    }
    // ...
    }
    return 0;
}
```

---

## 第八章：MemScope 完整工作链路串联

### 8.1 从源码到运行的全流程图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          MemScope 完整工作链路                                │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 编译时                                                               │    │
│  │                                                                     │    │
│  │  memscope.bpf.c ──clang -target bpf──→ memscope.bpf.o              │    │
│  │  (BPF C 源码)     (BPF 字节码)         (ELF 格式的 BPF 目标文件)    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 加载时（collector_init）                                              │    │
│  │                                                                     │    │
│  │  memscope.bpf.o                                                     │    │
│  │    │                                                                │    │
│  │    ├── bpf_object__open_file()  → 解析 ELF，识别 BPF section        │    │
│  │    │                                                                │    │
│  │    └── bpf_object__load()       → 提交到内核                        │    │
│  │          │                                                          │    │
│  │          ├── 创建 BPF Maps（内核创建 Map 对象，返回 fd）             │    │
│  │          │                                                          │    │
│  │          ├── 验证器检查 BPF 程序                                     │    │
│  │          │     ├── 检查指令数量、栈大小、内存访问...                  │    │
│  │          │     └── 通过 ✓                                           │    │
│  │          │                                                          │    │
│  │          └── JIT 编译 BPF 字节码 → x86_64 机器码                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 附加时（collector_start → attach_uprobes）                            │    │
│  │                                                                     │    │
│  │  bpf_program__attach_uprobe(prog, 0, -1, libc_path, offset)        │    │
│  │    │                                                                │    │
│  │    ├── malloc 入口：插入 int3 断点                                   │    │
│  │    ├── malloc 返回：劫持返回地址到 trampoline                        │    │
│  │    ├── free 入口：插入 int3 断点                                     │    │
│  │    ├── mmap 入口：插入 int3 断点                                     │    │
│  │    └── munmap 入口：插入 int3 断点                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 运行时（主循环 collector_poll）                                       │    │
│  │                                                                     │    │
│  │  目标进程调用 malloc(40)                                             │    │
│  │    │                                                                │    │
│  │    ├── int3 → #BP 异常 → uprobe_malloc_entry 执行                   │    │
│  │    │     └── pending_mallocs[TID] = 40                              │    │
│  │    │                                                                │    │
│  │    ├── malloc 执行，返回 addr                                        │    │
│  │    │                                                                │    │
│  │    ├── trampoline → uretprobe_malloc_return 执行                    │    │
│  │    │     ├── size = pending_mallocs[TID]                            │    │
│  │    │     ├── active_allocs[addr] = {size=40, ...}                   │    │
│  │    │     └── Ring Buffer ← EVENT_MALLOC_RETURN                      │    │
│  │    │                                                                │    │
│  │    └── Collector 消费 Ring Buffer                                    │    │
│  │          └── hash_table.insert(addr → {size=40, live=1})            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 离线分析（memscope-resolve）                                          │    │
│  │                                                                     │    │
│  │  allocs.csv + 目标二进制文件                                         │    │
│  │    │                                                                │    │
│  │    ├── DwarfAnalyzer.load_binary()                                  │    │
│  │    │     ├── 解析 ELF 符号表                                        │    │
│  │    │     ├── 解析 DWARF .debug_info → 类型数据库                     │    │
│  │    │     └── 构建 size_index（大小→类型映射）                         │    │
│  │    │                                                                │    │
│  │    └── AddressResolver.batch()                                      │    │
│  │          └── 对每条分配：size_index[40] → struct Point               │    │
│  │              → 展开 Point 所有字段 → resolved.csv                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 每一步对应的内核机制

| 步骤 | 用户态操作 | 内核机制 |
|------|-----------|----------|
| 编译 | `clang -target bpf` | 无（纯编译时操作） |
| 打开 | `bpf_object__open_file()` | 无（解析 ELF） |
| 加载 | `bpf_object__load()` | `bpf()` 系统调用 → 验证器 + JIT |
| 创建 Map | 自动（load 时） | `bpf(BPF_MAP_CREATE)` |
| 附加 uprobe | `bpf_program__attach_uprobe()` | `perf_event_open()` + `ioctl()` |
| 触发 BPF | 目标进程调用 malloc | `int3` 异常 → uprobe handler |
| 发送事件 | `bpf_ringbuf_output()` | Ring Buffer 写入 |
| 消费事件 | `ring_buffer__poll()` | mmap 共享内存读取 |
| 查询 Map | `bpf_map_lookup_elem()` | `bpf(BPF_MAP_LOOKUP_ELEM)` |

### 8.3 性能开销的来源分析

| 开销来源 | 开销量 | 说明 |
|----------|--------|------|
| int3 异常处理 | ~1μs | uprobe 触发时的主要开销 |
| BPF 程序执行 | ~200-500ns | JIT 编译后接近原生速度 |
| Ring Buffer 写入 | ~100-200ns | 零拷贝，但需要更新指针 |
| Map 操作 | ~100-300ns | Hash 查找/更新 |
| **总计（单次 malloc 追踪）** | **~2-3μs** | 包含 entry + return 两个探针 |

对比：一次 `malloc` 调用本身大约需要 100-500ns。所以 eBPF 追踪会让 `malloc` 慢约 5-10 倍。但这比 ptrace 的 100 倍慢要好得多，而且：

- 只影响被追踪的函数（malloc/free/mmap），不影响程序的其他部分
- 只影响被追踪的进程（通过 PID 过滤），不影响其他进程
- 可以随时停止追踪（Ctrl-C），移除断点后程序恢复正常速度

### 8.4 对原始程序和数据的影响总结

#### 对原始程序的影响

| 影响类型 | 程度 | 说明 |
|----------|------|------|
| 执行速度 | 中等（5-10x 慢） | 仅限被追踪的函数 |
| 内存占用 | 极小 | BPF Map 和 Ring Buffer 在内核中，不占用用户态内存 |
| 程序行为 | 无 | 不改变函数的输入/输出 |
| 程序稳定性 | 无 | 验证器保证 BPF 程序不会导致崩溃 |

#### 对原始数据的影响

| 影响类型 | 程度 | 说明 |
|----------|------|------|
| 数据内容 | **零** | eBPF 程序无法修改用户态内存 |
| 数据完整性 | **零** | uprobe 不改变函数的输入参数和返回值 |
| 数据时序 | 极小 | 追踪会引入微秒级延迟，但不影响数据本身 |

**结论：eBPF 对原始数据的影响为零，对原始程序的执行速度有一定影响（被追踪函数慢 5-10 倍），但不影响程序的正确性和稳定性。这就是 eBPF 被称为"无损"的原因。**

---

## 第九章：核心难题——只有 addr 和 size，如何知道 type 是什么？

这是 MemScope 项目中最精妙、也最容易让人困惑的部分。

### 9.1 问题的本质

eBPF 追踪到的信息只有两个：

- **addr**：malloc 返回的内存起始地址（如 `0x55a123456000`）
- **size**：malloc 申请的字节数（如 `40`）

但 DWARF 调试信息中存储的是**类型定义**，比如 `struct Point` 的大小是 40 字节，`struct Buffer` 的大小也是 40 字节。

**核心问题：给定 addr=0x55a123456000, size=40，你怎么知道这块内存里存的是 `struct Point` 还是 `struct Buffer`？**

答案是：**你无法 100% 确定。** 但 MemScope 通过两种策略来"推断"类型，其中最核心的是**大小匹配（Size Matching）**。

### 9.2 完整推理链路总览

```
eBPF 追踪到的原始数据          DWARF 调试信息              推理结果
─────────────────────      ──────────────────      ──────────────

addr = 0x55a123456000       struct Point {           推断：这是 struct Point
size = 40                     double x;  // +0, 8B
                              double y;  // +8, 8B
                              double z;  // +16, 8B
                              int label; // +24, 4B
                              double w;  // +28, 8B
                            }  // 总大小 = 40 字节

                            struct Buffer {          不匹配（大小不同）
                              size_t cap;  // +0, 8B
                              size_t len;  // +8, 8B
                              char *data;  // +16, 8B
                              int flags;   // +24, 4B
                              int refcnt;  // +28, 4B
                            }  // 总大小 = 32 字节

推理链路：
  size=40 → size_index[40] → [struct Point] → 唯一匹配！→ type = struct Point
  offset = addr - base_addr → 在 struct Point 的字段列表中查找 → Point.y
```

下面我们逐步拆解这个推理链路，配合源码逐行讲解。

### 9.3 第一步：eBPF 采集——我们只有 addr 和 size

当目标进程执行 `malloc(sizeof(struct Point))` 时，eBPF 追踪到的原始数据：

```c
// src/bpf/memscope.bpf.c - uretprobe_malloc_return

SEC("uretprobe/libc.so.6:malloc")
int BPF_KRETPROBE(uprobe_malloc_return, void *ret)
{
    // ...
    __u64 addr = (__u64)ret;           // malloc 返回的地址
    size_ptr = bpf_map_lookup_elem(&pending_mallocs, &tid);
    size_val = *size_ptr;              // 之前保存的 size

    // 发送事件：只有 addr 和 size，没有类型信息！
    evt.type = EVENT_MALLOC_RETURN;
    evt.malloc_ret.addr = addr;        // 0x55a123456000
    evt.malloc_ret.size = size_val;    // 40

    emit_event(ctx, &evt);
    return 0;
}
```

**关键理解：eBPF 运行在内核中，它只能看到 malloc 的参数和返回值。它根本不知道你用这块内存来存什么类型。** C 语言的 `malloc(40)` 和 `malloc(sizeof(struct Point))` 在运行时是完全一样的——都是调用 libc 的 malloc 函数，传入参数 40。

### 9.4 第二步：DWARF 解析——构建"类型数据库"

MemScope 在离线阶段解析目标二进制文件的 DWARF 调试信息，构建一个"类型数据库"。

#### 9.4.1 DWARF 中的类型信息长什么样？

当你用 `gcc -g` 编译 `bench_target.c` 时，编译器会在二进制文件中生成 DWARF 调试信息。对于 `struct Point`：

```c
// bench_target.c 中的定义
struct Point {
    double x;       // 偏移 0, 大小 8
    double y;       // 偏移 8, 大小 8
    double z;       // 偏移 16, 大小 8
    int    label;   // 偏移 24, 大小 4
    double weight;  // 偏移 28, 大小 8（注意：4字节对齐填充后从28开始）
};  // 总大小 = 40 字节
```

DWARF 中存储的信息等价于：

```
DW_TAG_structure_type "Point"
  ├── DW_AT_byte_size = 40
  ├── DW_TAG_member "x"
  │     ├── DW_AT_data_member_location = 0
  │     ├── DW_AT_type → DW_TAG_base_type "double"
  │     └── DW_AT_byte_size = 8
  ├── DW_TAG_member "y"
  │     ├── DW_AT_data_member_location = 8
  │     ├── DW_AT_type → DW_TAG_base_type "double"
  │     └── DW_AT_byte_size = 8
  ├── DW_TAG_member "z"
  │     ├── DW_AT_data_member_location = 16
  │     ├── DW_AT_type → DW_TAG_base_type "double"
  │     └── DW_AT_byte_size = 8
  ├── DW_TAG_member "label"
  │     ├── DW_AT_data_member_location = 24
  │     ├── DW_AT_type → DW_TAG_base_type "int"
  │     └── DW_AT_byte_size = 4
  └── DW_TAG_member "weight"
        ├── DW_AT_data_member_location = 28
        ├── DW_AT_type → DW_TAG_base_type "double"
        └── DW_AT_byte_size = 8
```

**关键信息：DWARF 告诉我们 `struct Point` 的总大小是 40 字节，以及每个字段的偏移和大小。**

#### 9.4.2 DwarfAnalyzer 如何解析这些信息？

```cpp
// src/dwarf/dwarf_analyzer.cpp - process_type_die()

void DwarfAnalyzer::process_type_die(void *die_v)
{
    Dwarf_Die *die = (Dwarf_Die *)die_v;

    // 1. 获取类型名称
    const char *name = dwarf_diename(die);  // "Point"
    if (!name) return;

    TypeInfo info = {};
    info.name = name;                        // "Point"

    // 2. 获取类型总大小 —— 这是大小匹配的关键！
    Dwarf_Attribute attr;
    if (dwarf_attr(die, DW_AT_byte_size, &attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&attr, &val) == 0)
            info.byte_size = val;            // 40
    }

    // 3. 遍历所有成员（字段）
    Dwarf_Die child;
    if (dwarf_child(die, &child) == 0) {
        do {
            int child_tag = dwarf_tag(&child);
            if (child_tag == DW_TAG_member) {
                process_member_die(&child, info);  // 解析每个字段
            }
        } while (dwarf_siblingof(&child, &child) == 0);
    }

    // 4. 存入类型列表
    types_.push_back(info);
    type_name_index_[info.name] = idx;
}
```

```cpp
// src/dwarf/dwarf_analyzer.cpp - process_member_die()

void DwarfAnalyzer::process_member_die(void *die_v, TypeInfo &parent)
{
    Dwarf_Die *die = (Dwarf_Die *)die_v;

    // 1. 获取字段名称
    const char *name = dwarf_diename(die);   // "x", "y", "z", "label", "weight"
    if (!name) return;

    FieldInfo field = {};
    field.name = name;

    // 2. 获取字段偏移 —— 这是字段定位的关键！
    if (dwarf_attr(die, DW_AT_data_member_location, &attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&attr, &val) == 0) {
            field.byte_offset = val;          // 0, 8, 16, 24, 28
        }
    }

    // 3. 获取字段大小
    if (dwarf_attr(die, DW_AT_byte_size, &attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&attr, &val) == 0)
            field.byte_size = val;            // 8, 8, 8, 4, 8
    }

    // 4. 获取字段类型
    if (dwarf_attr(die, DW_AT_type, &type_attr)) {
        Dwarf_Die type_die;
        if (dwarf_formref_die(&type_attr, &type_die)) {
            const char *type_name = dwarf_diename(&type_die);
            if (type_name)
                field.type_name = type_name;  // "double", "int"
        }
    }

    parent.fields.push_back(field);
}
```

解析完成后，`DwarfAnalyzer` 内部的数据结构如下：

```
types_ = [
    TypeInfo {
        name = "Point",
        byte_size = 40,
        fields = [
            FieldInfo { name="x",      byte_offset=0,  byte_size=8, type_name="double" },
            FieldInfo { name="y",      byte_offset=8,  byte_size=8, type_name="double" },
            FieldInfo { name="z",      byte_offset=16, byte_size=8, type_name="double" },
            FieldInfo { name="label",  byte_offset=24, byte_size=4, type_name="int" },
            FieldInfo { name="weight", byte_offset=28, byte_size=8, type_name="double" },
        ]
    },
    TypeInfo {
        name = "Node",
        byte_size = 56,
        fields = [ ... ]
    },
    TypeInfo {
        name = "Buffer",
        byte_size = 32,
        fields = [ ... ]
    },
    TypeInfo {
        name = "Packet",
        byte_size = 80,
        fields = [ ... ]
    },
    ...
]
```

### 9.5 第三步：构建大小索引——size 到 type 的桥梁

这是 MemScope 最关键的"桥梁"设计。

#### 9.5.1 问题：如何从 size=40 找到 struct Point？

types_ 是一个列表，里面有几十甚至几百个类型。如果每次都要遍历整个列表来找 `byte_size == 40` 的类型，效率太低了。

#### 9.5.2 解决方案：size_index_ 哈希表

```cpp
// src/resolver/address_resolver.cpp - build_size_index()

void AddressResolver::build_size_index()
{
    size_index_.clear();
    const auto &types = analyzer_.get_all_types();

    // 遍历所有类型，按 byte_size 分组
    for (size_t i = 0; i < types.size(); i++) {
        if (types[i].byte_size > 0 && !types[i].fields.empty()) {
            // key = byte_size, value = 类型索引列表
            size_index_[types[i].byte_size].push_back(i);
        }
    }
}
```

构建完成后，`size_index_` 的内容如下：

```
size_index_ = {
    40 → [0],           // 只有 struct Point 大小是 40
    56 → [1],           // 只有 struct Node 大小是 56
    32 → [2],           // 只有 struct Buffer 大小是 32
    80 → [3],           // 只有 struct Packet 大小是 80
    16 → [4, 7, 12],    // 可能有多个类型大小都是 16（歧义！）
    ...
}
```

**关键理解：**
- 如果某个 size 只对应一个类型，那就是**唯一匹配**，可以确定类型
- 如果某个 size 对应多个类型，那就是**歧义匹配**，只能猜测
- 如果某个 size 没有对应任何类型，那就是**无法推断**

### 9.6 第四步：类型推断——infer_type_from_size()

当用户调用 `resolve(addr)` 解析一个堆地址时，MemScope 的推理过程如下：

```cpp
// src/resolver/address_resolver.cpp - resolve_heap()

std::optional<ResolvedAddress> AddressResolver::resolve_heap(
    uint64_t address, uint32_t pid) const
{
    // 第一步：在分配表中查找这个地址属于哪次 malloc
    const AllocInfo *alloc = find_alloc(address);
    if (!alloc)
        return std::nullopt;

    // 此时我们知道：
    //   alloc->addr = 0x55a123456000  (malloc 返回的起始地址)
    //   alloc->size = 40              (malloc 申请的字节数)

    // 第二步：计算地址在分配块内的偏移
    uint64_t offset = address - alloc->addr;
    // 例如：address = 0x55a123456008, alloc->addr = 0x55a123456000
    //       offset = 8

    // 第三步：推断类型（两种策略，优先级从高到低）
    std::string type_name = infer_type_from_callsite(alloc->stack_id);  // 策略1：调用点推断
    if (type_name.empty())
        type_name = infer_type_from_size(alloc->size);                  // 策略2：大小匹配

    // 第四步：如果推断出了类型，解析具体字段
    if (!type_name.empty()) {
        auto field = analyzer_.resolve_field_at_offset(type_name, offset);
        // ...
    }

    return result;
}
```

#### 策略1：调用点推断（infer_type_from_callsite）

```cpp
// src/resolver/address_resolver.cpp

std::string AddressResolver::infer_type_from_callsite(int64_t stack_id) const
{
    return "";  // 当前为桩实现，返回空字符串
}
```

**这个策略的思路是**：如果 eBPF 捕获了 malloc 调用时的栈回溯，我们可以分析调用点上下文来推断类型。例如：

```c
// 如果栈回溯显示调用点是 bench_point_alloc() 函数
// 那么可以推断 malloc(40) 分配的是 struct Point
void bench_point_alloc() {
    struct Point *p = (struct Point *)malloc(sizeof(struct Point));
    //                          ^^^^^^
    //                          从这里可以推断类型是 Point
}
```

但这个功能目前**尚未实现**（返回空字符串），所以实际使用的是策略2。

#### 策略2：大小匹配（infer_type_from_size）——当前实际使用的策略

```cpp
// src/resolver/address_resolver.cpp - infer_type_from_size()

std::string AddressResolver::infer_type_from_size(uint64_t size) const
{
    if (size == 0)
        return "";

    // 在 size_index_ 中查找 size 对应的类型
    auto it = size_index_.find(size);
    if (it == size_index_.end())
        return "";                    // 没有任何类型匹配这个大小

    const auto &candidates = it->second;
    const auto &types = analyzer_.get_all_types();

    if (candidates.size() == 1)
        return types[candidates[0]].name;   // 唯一匹配！确定类型

    if (candidates.size() > 1)
        // 多个类型大小相同，返回第一个并标记"歧义"
        return types[candidates[0]].name +
               " (ambiguous: " + std::to_string(candidates.size()) + " candidates)";

    return "";
}
```

**用具体例子走一遍：**

```
输入：size = 40

1. size_index_.find(40)  →  找到了！candidates = [0]

2. candidates.size() == 1  →  唯一匹配！

3. types[0].name = "Point"

4. 返回 "Point"
```

```
输入：size = 16

1. size_index_.find(16)  →  找到了！candidates = [4, 7, 12]

2. candidates.size() == 3  →  歧义匹配！

3. types[4].name = "SmallStruct"

4. 返回 "SmallStruct (ambiguous: 3 candidates)"
```

```
输入：size = 12345

1. size_index_.find(12345)  →  没找到！

2. 返回 ""  （无法推断类型）
```

### 9.7 第五步：字段解析——从 offset 到具体字段

一旦知道了类型，就可以根据偏移量定位到具体字段。

#### 9.7.1 计算偏移量

```cpp
// src/resolver/address_resolver.cpp - resolve_heap()

uint64_t offset = address - alloc->addr;
```

例如：
- `address = 0x55a123456008`（你要查询的地址）
- `alloc->addr = 0x55a123456000`（malloc 返回的起始地址）
- `offset = 0x55a123456008 - 0x55a123456000 = 8`

**偏移量 8 的含义：这个地址在分配块内部，距离起始位置 8 个字节。**

#### 9.7.2 在类型字段列表中查找

```cpp
// src/dwarf/dwarf_analyzer.cpp - resolve_field_at_offset()

std::optional<FieldInfo> DwarfAnalyzer::resolve_field_at_offset(
    uint64_t type_die_offset, uint64_t byte_offset) const
{
    const TypeInfo *type = find_type_by_offset(type_die_offset);
    if (!type)
        return std::nullopt;

    const FieldInfo *best = nullptr;
    uint64_t best_distance = UINT64_MAX;

    // 遍历类型的所有字段，找到包含该偏移的字段
    for (const auto &field : type->fields) {
        // 情况1：精确匹配——偏移恰好等于字段起始位置
        if (byte_offset == field.byte_offset) {
            if (!best || field.byte_size > best->byte_size) {
                best = &field;
                best_distance = 0;
            }
        }

        // 情况2：范围匹配——偏移落在字段范围内
        // 例如：offset=10 落在 field[offset=8, size=8] 的范围内
        if (field.byte_size > 0 &&
            byte_offset >= field.byte_offset &&
            byte_offset < field.byte_offset + field.byte_size) {
            uint64_t dist = byte_offset - field.byte_offset;
            if (dist < best_distance) {
                best_distance = dist;
                best = &field;
            }
        }
    }

    if (best)
        return *best;
    return std::nullopt;
}
```

**用具体例子走一遍：**

```
类型：struct Point
偏移量：8

遍历字段列表：
  field "x":      byte_offset=0,  byte_size=8  → 8 不在 [0, 8) 范围内 ✗
  field "y":      byte_offset=8,  byte_size=8  → 8 == 8，精确匹配！✓
  field "z":      byte_offset=16, byte_size=8  → 8 不在 [16, 24) 范围内 ✗
  field "label":  byte_offset=24, byte_size=4  → 8 不在 [24, 28) 范围内 ✗
  field "weight": byte_offset=28, byte_size=8  → 8 不在 [28, 36) 范围内 ✗

结果：best = field "y"
返回：FieldInfo { name="y", byte_offset=8, byte_size=8, type_name="double" }
```

### 9.8 完整推理链路：从 addr 到 struct.field 的端到端示例

让我们用一个完整的例子走一遍全流程：

```
目标进程执行：
  struct Point *p = (struct Point *)malloc(sizeof(struct Point));
  p->y = 3.14;   // 访问地址 p + 8 = 0x55a123456008
```

```
步骤1：eBPF 追踪
  uprobe_malloc_entry: size = 40 → pending_mallocs[TID] = 40
  uretprobe_malloc_return: addr = 0x55a123456000, size = 40
  → Ring Buffer 事件: {addr=0x55a123456000, size=40}

步骤2：Collector 消费
  → allocs.csv: 0x55a123456000,40,1234,1234,1,...

步骤3：离线解析 - DWARF 加载
  DwarfAnalyzer.load_binary("bench_target")
  → types_ = [
      TypeInfo{name="Point", byte_size=40, fields=[x(+0,8B), y(+8,8B), z(+16,8B), label(+24,4B), weight(+28,8B)]},
      TypeInfo{name="Node", byte_size=56, fields=[...]},
      TypeInfo{name="Buffer", byte_size=32, fields=[...]},
      TypeInfo{name="Packet", byte_size=80, fields=[...]},
    ]

步骤4：构建大小索引
  build_size_index()
  → size_index_ = {
      40 → [0],   // Point
      56 → [1],   // Node
      32 → [2],   // Buffer
      80 → [3],   // Packet
    }

步骤5：解析地址 0x55a123456008
  resolve_heap(0x55a123456008)

  5a. find_alloc(0x55a123456008)
      → alloc = {addr=0x55a123456000, size=40, live=1}

  5b. offset = 0x55a123456008 - 0x55a123456000 = 8

  5c. infer_type_from_callsite(stack_id)
      → ""  （桩实现，返回空）

  5d. infer_type_from_size(40)
      → size_index_[40] = [0]
      → candidates.size() == 1  → 唯一匹配！
      → types[0].name = "Point"
      → 返回 "Point"

  5e. resolve_field_at_offset("Point", 8)
      → 遍历 Point 的字段：
         x: offset=0,  8 不在 [0,8)   ✗
         y: offset=8,  8 == 8          ✓ 精确匹配！
      → 返回 FieldInfo{name="y", byte_offset=8, byte_size=8, type_name="double"}

步骤6：输出结果
  Address: 0x55a123456008
  Class:   HEAP
  Type:    struct Point
  Alloc:   40 bytes
  Field:   Point.y (offset=8, size=8, type=double)
```

### 9.9 大小匹配的局限性与调用点推断的实现

#### 局限性1：大小歧义

如果两个不同类型的大小相同，大小匹配就无法区分：

```c
struct A { int x, y, z, w; };     // 16 字节
struct B { double p, q; };         // 16 字节
// malloc(16) 到底是 A 还是 B？无法确定
```

#### 局限性2：大小不匹配

如果 malloc 的大小和任何 DWARF 类型都不匹配：

```c
char *buf = (char *)malloc(100);  // 100 字节，可能没有对应的 struct
```

#### 已实现：调用点推断（Callsite Inference）

为了解决大小匹配的歧义问题，MemScope 现已实现基于调用点的类型推断。核心思路是：

**eBPF 采集 malloc 调用时的栈回溯 → 从栈帧中提取函数名 → 在 DWARF 子程序信息中查找该函数的局部变量 → 筛选指针类型的局部变量 → 提取指针指向的类型**

##### 实现步骤1：BPF 采集调用栈

修复了 BPF 程序中 stack_id 硬编码为 0 的问题：

```c
// src/bpf/memscope.bpf.c - uretprobe_malloc_return（修复后）
info.stack_id = get_stack_id(ctx);   // 原来是硬编码 0
evt.stack_id = info.stack_id;        // 原来是硬编码 0
```

```c
// src/bpf/memscope.bpf.c - uprobe_free（修复后）
evt.stack_id = get_stack_id(ctx);    // 原来没有采集
```

##### 实现步骤2：DWARF 子程序-变量关联

在 `process_subprogram_die` 中新增局部变量提取：

```cpp
// src/dwarf/dwarf_analyzer.cpp - process_subprogram_die（增强后）
// 遍历子程序的子 DIE，提取局部变量
Dwarf_Die child;
if (dwarf_child(die, &child) == 0) {
    do {
        if (dwarf_tag(&child) == DW_TAG_variable) {
            LocalVariableInfo var = {};
            var.name = dwarf_diename(&child);
            // 获取 DW_AT_type
            if (dwarf_attr(&child, DW_AT_type, &type_attr)) {
                Dwarf_Die type_die;
                if (dwarf_formref_die(&type_attr, &type_die)) {
                    // 如果是指针类型，进一步获取指向的目标类型
                    if (dwarf_tag(&type_die) == DW_TAG_pointer_type) {
                        var.is_pointer = true;
                        // 跟踪指针指向的类型
                        Dwarf_Die target_die;
                        if (dwarf_attr(&type_die, DW_AT_type, &target_attr)) {
                            var.pointer_target_type_name = dwarf_diename(&target_die);
                        }
                    }
                }
            }
            info.local_variables.push_back(var);
        }
    } while (dwarf_siblingof(&child, &child) == 0);
}
```

DWARF 中的信息结构：

```
DW_TAG_subprogram "bench_point_alloc"
  └── DW_TAG_variable "p"
        ├── DW_AT_type → DW_TAG_pointer_type
        │                   └── DW_AT_type → DW_TAG_structure_type "Point"
        └── DW_AT_location → 栈上的位置
```

解析后，`SubprogramInfo::local_variables` 包含：

```
LocalVariableInfo {
    name = "p",
    is_pointer = true,
    pointer_target_type_name = "Point"   ← 这就是我们要的类型！
}
```

##### 实现步骤3：调用点推断逻辑

```cpp
// src/resolver/address_resolver.cpp - infer_type_from_callsite()

std::string AddressResolver::infer_type_from_callsite(int64_t stack_id) const
{
    // 1. 通过 stack_id 从 BPF stack map 获取栈帧 PC 列表
    auto func_names = resolve_stack_function_names(stack_id);

    // 2. 对每个函数名，查找 DWARF 子程序信息
    std::vector<std::string> candidates;
    for (const auto &func_name : func_names) {
        const SubprogramInfo *subprog = analyzer_.find_subprogram_by_name(func_name);
        if (!subprog) continue;

        // 3. 筛选指针类型的局部变量
        for (const auto &var : subprog->local_variables) {
            if (var.is_pointer && !var.pointer_target_type_name.empty()) {
                candidates.push_back(var.pointer_target_type_name);
            }
        }
    }

    // 4. 返回推断结果
    if (candidates.size() == 1) return candidates[0];  // 唯一匹配
    if (candidates.size() > 1) return candidates[0] + " (ambiguous)";
    return "";  // 无法推断
}
```

##### 实现步骤4：组合推断策略

```cpp
// src/resolver/address_resolver.cpp - infer_type_combined()

// 组合调用点推断和大小匹配，取交集缩小歧义
std::string AddressResolver::infer_type_combined(int64_t stack_id, uint64_t size) const
{
    // 1. 获取调用点候选（指针目标类型）
    auto callsite_candidates = ...;  // 从 infer_type_from_callsite 获取

    // 2. 如果只有 1 个调用点候选，直接返回（高置信度）
    if (callsite_candidates.size() == 1) return callsite_candidates[0];

    // 3. 获取大小匹配候选
    auto size_candidates = ...;  // 从 size_index_ 获取

    // 4. 计算交集
    auto intersection = ...;  // 两个候选集的交集

    // 5. 交集唯一则返回，否则回退到大小匹配
}
```

`resolve_heap()` 中使用组合推断：

```cpp
// src/resolver/address_resolver.cpp - resolve_heap()
std::string type_name = infer_type_combined(alloc->stack_id, alloc->size);
```

##### 完整推理链路示例

```
目标进程执行：
  void bench_point_alloc() {
      struct Point *p = (struct Point *)malloc(sizeof(struct Point));
  }

步骤1：eBPF 追踪
  uprobe_malloc_entry: size = 40
  uretprobe_malloc_return: addr = 0x55a123456000, stack_id = 42（非 0！）

步骤2：解析 stack_id = 42
  bpf_map_lookup_elem(stack_traces, 42) → PC 列表
  PC[0] = malloc+0x5
  PC[1] = bench_point_alloc+0x20  ← 关键函数！
  PC[2] = main+0x30

步骤3：调用点推断
  函数名 "bench_point_alloc" → 查找 SubprogramInfo
  → local_variables = [LocalVariableInfo{name="p", is_pointer=true, pointer_target_type_name="Point"}]
  → 候选：["Point"]
  → 唯一匹配！返回 "Point"

步骤4：字段解析
  offset = addr - base_addr = 8
  resolve_field_at_offset("Point", 8) → Point.y

结果：struct Point.y (offset=8, size=8, type=double)  ✓ 精确推断！
```

### 9.10 全局变量的类型推断——一种更精确的方式

与堆分配不同，全局变量的类型推断是**精确的**，不需要"猜测"。

```cpp
// src/resolver/address_resolver.cpp - resolve_global()

std::optional<ResolvedAddress> AddressResolver::resolve_global(uint64_t address) const
{
    // 1. 在符号表中查找包含该地址的全局符号
    const SymbolInfo *sym = analyzer_.find_symbol_by_addr(address);
    if (!sym)
        return std::nullopt;

    // 2. 符号直接关联了类型名！不需要大小匹配
    result.type_name = sym->type_name;   // ← 精确的类型信息

    // 3. 解析字段
    if (!sym->type_name.empty()) {
        uint64_t offset = address - sym->address;
        auto field = analyzer_.resolve_field_at_offset(sym->type_name, offset);
        // ...
    }
}
```

**为什么全局变量可以精确推断类型？**

因为全局变量在 DWARF 中有完整的类型关联：

```
// C 代码
struct Point global_point;  // 全局变量

// DWARF 中的信息
DW_TAG_variable "global_point"
  ├── DW_AT_type → DW_TAG_structure_type "Point"   ← 直接关联了类型！
  ├── DW_AT_location → DW_OP_addr 0x401000         ← 精确的地址
  └── DW_AT_byte_size = 40
```

DWARF 中的 `DW_AT_type` 属性直接告诉我们这个变量的类型是 `struct Point`，不需要任何猜测。

MemScope 的 `process_variable_die()` 解析了这个关联：

```cpp
// src/dwarf/dwarf_analyzer.cpp - process_variable_die()

void DwarfAnalyzer::process_variable_die(void *die_v)
{
    // ...
    // 获取变量的地址
    if (ops[0].atom == DW_OP_addr) {
        addr = ops[0].number;          // 0x401000
    }

    // 获取变量的类型 —— 这是精确类型推断的关键！
    Dwarf_Attribute type_attr;
    if (dwarf_attr(die, DW_AT_type, &type_attr)) {
        Dwarf_Die type_die;
        if (dwarf_formref_die(&type_attr, &type_die)) {
            const char *type_name = dwarf_diename(&type_die);
            if (type_name)
                sym.type_name = type_name;  // "Point" ← 直接从 DWARF 获取！
        }
    }
}
```

### 9.11 三种地址类型的类型推断方式对比

| 地址类型 | 类型推断方式 | 精确度 | 源码位置 |
|----------|-------------|--------|----------|
| **全局（Global）** | 符号的 `DW_AT_type` 属性 | **100% 精确** | `resolve_global()` → `sym->type_name` |
| **堆（Heap）** | 调用点推断（优先）+ 大小匹配（回退） | **调用点唯一时精确** | `resolve_heap()` → `infer_type_combined()` |
| **栈（Stack）** | DWARF 局部变量 `DW_AT_location` + `DW_AT_type` | **精确**（已实现） | `resolve_stack()` → `find_stack_variables()` |

### 9.12 栈变量解析——从 DWARF 局部变量信息到栈地址映射

栈地址解析是 MemScope 新增的重要能力。与堆分配不同，栈上的局部变量在 DWARF 中有精确的位置和类型信息。

#### DWARF 中的栈变量信息

当编译器生成调试信息时，每个函数的局部变量都会记录在 DWARF 中：

```
DW_TAG_subprogram "bench_point_alloc"
  ├── DW_AT_low_pc = 0x401100
  ├── DW_AT_high_pc = 0x401200
  ├── DW_TAG_variable "p"
  │     ├── DW_AT_type → DW_TAG_pointer_type → "Point"
  │     └── DW_AT_location → DW_OP_fbreg -32    ← 栈帧基址偏移 -32
  └── DW_TAG_variable "count"
        ├── DW_AT_type → DW_TAG_base_type "int"
        └── DW_AT_location → DW_OP_fbreg -36    ← 栈帧基址偏移 -36
```

`DW_AT_location` 中的 `DW_OP_fbreg -32` 表示：这个变量位于栈帧基址（frame base）偏移 -32 的位置。

#### 栈变量解析的实现

```cpp
// src/dwarf/dwarf_analyzer.cpp - find_stack_variables()

std::vector<StackVariableInfo> DwarfAnalyzer::find_stack_variables(uint64_t pc) const
{
    // 1. 找到包含 PC 的子程序
    for (const auto &subprog : subprograms_) {
        if (pc >= subprog.low_pc && pc < subprog.low_pc + subprog.high_pc) {
            // 2. 通过 die_offset 恢复子程序 DIE
            Dwarf_Die die;
            dwarf_offdie(dbg, subprog.die_offset, &die);

            // 3. 遍历子 DIE，找 DW_TAG_variable
            Dwarf_Die child;
            if (dwarf_child(&die, &child) == 0) {
                do {
                    if (dwarf_tag(&child) == DW_TAG_variable) {
                        // 4. 解析 DW_AT_location
                        Dwarf_Op *ops;
                        size_t ops_len;
                        dwarf_getlocation(&loc_attr, &ops, &ops_len);

                        // 5. 提取栈偏移
                        if (ops[0].atom == DW_OP_fbreg) {
                            stack_offset = ops[0].number + ops[0].offset;
                        }

                        // 6. 获取类型和大小
                        // ...
                    }
                } while (dwarf_siblingof(&child, &child) == 0);
            }
        }
    }
}
```

```cpp
// src/resolver/address_resolver.cpp - resolve_stack_field()

std::optional<ResolvedField> AddressResolver::resolve_stack_field(
    uint64_t frame_base, int64_t stack_offset,
    const std::string &func_name) const
{
    // 1. 查找函数对应的子程序
    const SubprogramInfo *subprog = analyzer_.find_subprogram_by_name(func_name);

    // 2. 获取该函数的栈变量列表
    auto stack_vars = analyzer_.find_stack_variables(subprog->low_pc);

    // 3. 在栈变量列表中查找匹配的变量
    for (const auto &var : stack_vars) {
        if (stack_offset >= var.stack_offset &&
            stack_offset < var.stack_offset + (int64_t)var.byte_size) {
            // 找到了！返回变量信息
            ResolvedField rf = {};
            rf.type_name = var.type_name;
            rf.field_name = var.name;
            // ...
            return rf;
        }
    }
    return std::nullopt;
}
```

#### DWARF CFI 帧信息解析

为了支持栈展开，MemScope 现在解析 `.debug_frame` 中的 FDE/CIE 记录：

```cpp
// src/dwarf/dwarf_analyzer.cpp - parse_dwarf_frames()

// 使用 libdw 的 dwarf_getcfi() 获取 CFI 数据
Dwarf_CFI *cfi = dwarf_getcfi(dbg);

// 遍历所有 CFI 条目
while (dwarf_next_cfi(...) == 0) {
    if (is_cie) {
        // 解析 CIE：版本、对齐因子、返回地址寄存器等
        cie_records_.push_back(cie_record);
    } else {
        // 解析 FDE：函数起始地址、地址范围、CFI 指令
        fde_records_.push_back(fde_record);
    }
}

// 关联 FDE 到对应的 CIE
for (auto &fde : fde_records_) {
    fde.cie = find_cie_by_offset(fde.cie_pointer);
}
```

#### DWARF 行号信息解析

栈帧现在可以显示源码位置：

```cpp
// src/dwarf/dwarf_analyzer.cpp - resolve_source_line()

std::optional<std::pair<std::string, uint32_t>>
DwarfAnalyzer::resolve_source_line(uint64_t pc) const
{
    // 遍历编译单元，找到包含 PC 的 CU
    // 使用 dwarf_getsrc_die() 查找 PC 对应的行号记录
    // 返回 {源文件路径, 行号}
}
```

解析后，栈帧输出从：

```
#0 0x401123 bench_point_alloc+0x23
```

变为：

```
#0 0x401123 bench_point_alloc+0x23 (bench_target.c:47)
```

**总结：MemScope 现已实现三级类型推断策略——调用点推断（最精确）→ 调用点+大小组合推断（消除歧义）→ 纯大小匹配（回退），同时栈变量解析和 CFI/行号信息解析也已实现，大幅提升了地址解析的精确度和信息丰富度。**

### 9.13 测试场景设计——bench_target 验证方案

为了全面验证堆类型推断、全局变量解析和栈变量解析的能力，bench_target 设计了 11 个测试场景：

| 编号 | 场景 | 验证目标 | 关键类型 |
|------|------|---------|---------|
| 1 | Point allocation | 基础堆分配 | `struct Point` (40B) |
| 2 | Tree allocation | 递归堆分配 | `struct Node` (56B) |
| 3 | Buffer allocation | 嵌套堆分配 | `struct Buffer` (32B) + 内部 `char*` |
| 4 | Packet allocation | 大结构体分配 | `struct Packet` (84B) |
| 5 | Mixed allocation | 混合大小分配 | 多种 size 交替 |
| 6 | Sequential access | 数组式堆访问 | `struct Point[]` |
| 7 | Random access | 随机堆访问 | `struct Node[]` |
| **8** | **Ambiguous size** | **大小歧义测试** | `Vec3`/`Color`(12B), `Coord`/`Triple`(16B), `Counter`/`Pair`(16B) |
| **9** | **Global access** | **全局变量解析** | 10 个 static 全局变量 |
| **10** | **Stack variables** | **栈变量解析** | 10 个局部变量 |
| **11** | **Multi-struct** | **多类型同函数** | 3 Point + 2 Node + 1 Buffer + 1 Packet |

#### 场景 8：大小歧义测试（核心验证）

这是验证调用点推断的关键场景。设计了三组大小相同但类型不同的 struct：

```
struct Vec3   { float x, y, z; }        // 12 字节
struct Color  { float r, g, b; }        // 12 字节  ← 与 Vec3 大小相同！

struct Coord  { double lat, lon; }      // 16 字节
struct Triple { int a, b, c; }          // 12 字节（实际 12B，对齐后可能 16B）
struct Counter{ long value, step; }     // 16 字节  ← 与 Coord 大小相同！
struct Pair   { int first, second; }    // 8 字节
```

**纯大小匹配的结果**：`Vec3` 和 `Color` 都匹配 12 字节 → 歧义！
**调用点推断的结果**：`bench_ambiguous_size_alloc` 函数中，`vec` 的类型是 `Vec3*`，`clr` 的类型是 `Color*` → 精确！

#### 场景 9：全局变量解析

定义了 10 个 static 全局变量，覆盖所有类型：

```c
static struct Point g_point = {1.0, 2.0, 3.0, 0, 1.5};
static struct Node  g_node  = {NULL, NULL, 42, 3.14, "global_node"};
static struct Buffer g_buf  = {4096, 0, NULL, 0, 1};
static struct Vec3   g_vec  = {1.0f, 2.0f, 3.0f};
static struct Color  g_clr  = {0.5f, 0.25f, 0.75f};
// ... 等
```

全局变量的类型通过 DWARF 的 `DW_AT_type` 直接关联，解析精确度为 100%。

#### 场景 10：栈变量解析

在 `bench_stack_variables()` 函数中定义了 10 个局部变量：

```c
struct Point  local_point  = {100.0, 200.0, 300.0, 1, 99.9};
struct Node   local_node   = {NULL, NULL, 7, 2.71, "stack_node"};
struct Vec3   local_vec    = {4.0f, 5.0f, 6.0f};
int local_int = 42;
double local_double = 3.14159;
// ... 等
```

栈变量通过 DWARF 的 `DW_AT_location`（`DW_OP_fbreg` 偏移）解析。

#### 场景 11：多类型同函数分配

在 `bench_multi_struct_alloc()` 中同时分配 7 个不同类型的堆变量：

```c
struct Point *p1 = malloc(sizeof(struct Point));
struct Point *p2 = malloc(sizeof(struct Point));
struct Point *p3 = malloc(sizeof(struct Point));
struct Node  *n1 = malloc(sizeof(struct Node));
struct Node  *n2 = malloc(sizeof(struct Node));
struct Buffer *b1 = malloc(sizeof(struct Buffer));
struct Packet *pkt = malloc(sizeof(struct Packet));
```

这个场景验证调用点推断在多候选情况下的表现：函数中有 `Point*`、`Node*`、`Buffer*`、`Packet*` 四种指针类型，调用点推断会返回多个候选，需要结合大小匹配来缩小范围。

---

## 附录：关键术语速查表

| 术语 | 全称 | 含义 |
|------|------|------|
| eBPF | extended Berkeley Packet Filter | 扩展伯克利包过滤器，在内核中安全运行沙箱程序的技术 |
| uprobe | User-Level Probe | 用户态探测点，在用户态函数入口/出口处插桩 |
| uretprobe | User-Level Return Probe | 用户态返回探测点，在函数返回时触发 |
| kprobe | Kernel Probe | 内核探测点，在内核函数入口处插桩 |
| JIT | Just-In-Time Compilation | 即时编译，将字节码翻译为原生机器码 |
| Verifier | BPF Verifier | BPF 验证器，在加载时检查程序安全性 |
| Ring Buffer | BPF Ring Buffer | BPF 环形缓冲区，内核态到用户态的高效数据传输机制 |
| BPF Map | BPF Map | BPF 映射，内核态和用户态共享的键值存储 |
| libbpf | libbpf | BPF 用户态库，提供加载、附加、Map 操作等 API |
| int3 | Interrupt 3 | x86 断点指令，触发 #BP 异常 |
| trampoline | Trampoline | 蹦床代码，用于 uretprobe 的返回地址劫持 |
| DWARF | Debugging With Attributed Record Formats | 调试信息格式，包含类型、变量、行号等信息 |
| ELF | Executable and Linkable Format | 可执行可链接格式，Linux 上的标准二进制格式 |
| CFG | Control Flow Graph | 控制流图，程序的基本块和跳转关系 |
| RCU | Read-Copy-Update | 读-拷贝-更新，内核中的无锁并发机制 |
