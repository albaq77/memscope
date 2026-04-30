# MemScope Architecture

## Overview

MemScope is a production-grade toolchain that combines eBPF runtime tracing with offline DWARF debug information analysis to map runtime memory addresses to struct fields. It enables developers to understand exactly which field of which struct a given memory address corresponds to, bridging the gap between runtime observability and compile-time type information.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Target Process                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                      │
│  │  malloc() │  │  free()  │  │  mmap()  │  ...                 │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                      │
└───────┼──────────────┼──────────────┼───────────────────────────┘
        │ uprobe       │ uprobe       │ uprobe
        ▼              ▼              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    eBPF Programs (Kernel)                        │
│  ┌─────────────────┐  ┌──────────────────┐                      │
│  │ uprobe_malloc   │  │ uretprobe_malloc │  Capture:            │
│  │   → size (map)  │  │   → addr + size  │   • allocation size  │
│  ├─────────────────┤  ├──────────────────┤   • PID/TID          │
│  │ uprobe_free     │  │ uprobe_mmap      │   • timestamps       │
│  │   → address     │  │   → addr+size    │                      │
│  └────────┬────────┘  └────────┬─────────┘                      │
│           │                    │                                 │
│           ▼                    ▼                                 │
│  ┌─────────────────────────────────────────┐                    │
│  │     BPF Ring Buffer (64MB, events)      │                    │
│  └────────────────────┬────────────────────┘                    │
└───────────────────────┼─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Userspace Collector                            │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐     │
│  │ Ring Buffer   │  │ Stack Trace   │  │ Alloc Hash Table │     │
│  │ Consumer      │  │ Resolver      │  │ {addr→info} O(1) │     │
│  └──────┬───────┘  └───────────────┘  └────────┬─────────┘     │
│         │                                       │               │
│         │            CSV Export                  │               │
│         └───────────────────────────────────────┘               │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Offline DWARF Analyzer                         │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐     │
│  │ ELF Parser   │  │ DWARF .debug  │  │ CFI Frame Info   │     │
│  │  • symbols   │  │  • types      │  │  • FDE/CIE       │     │
│  │  • sections  │  │  • fields     │  │  • unwinding     │     │
│  └──────┬───────┘  └──────┬────────┘  └────────┬─────────┘     │
│         │                 │                     │               │
│         ▀                 ▼                     ▼               │
│  ┌──────────────────────────────────────────────────────┐      │
│  │              Type Database + Size Index               │      │
│  │  struct Point { offset=0: x, offset=8: y, ... }     │      │
│  │  size_index: {40 → [Point], 32 → [Buffer], ...}     │      │
│  └──────────────────────────┬───────────────────────────┘      │
└─────────────────────────────┼───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Address Resolver                               │
│                                                                  │
│  Input:  address 0x7f8a3c001048                                 │
│                                                                  │
│  Step 1: Classify address                                        │
│    ├─ Global? → Symbol table binary search                       │
│    ├─ Heap?   → Allocation hash table O(1) lookup                │
│    └─ Stack?  → CFI unwinding + DW_AT_location                  │
│                                                                  │
│  Step 2: Determine containing type                               │
│    ├─ Global → symbol's DW_AT_type                               │
│    ├─ Heap   → callsite inference / size matching (via index)    │
│    └─ Stack  → subprogram local variable DWARF                   │
│                                                                  │
│  Step 3: Resolve field                                           │
│    offset = address - base_address                               │
│    field  = type_db.find_field_at_offset(type, offset)           │
│                                                                  │
│  Batch mode: expand ALL fields for each matched type             │
│                                                                  │
│  Output: struct Point.y (offset=8, size=8, type=double)          │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. eBPF Programs (`src/bpf/memscope.bpf.c`)

The kernel-side eBPF programs attach to userspace functions via uprobes:

| Probe | Target | Captures |
|-------|--------|----------|
| `uprobe_malloc` | `libc:malloc` | size argument (stored in BPF map only, not emitted) |
| `uretprobe_malloc` | `libc:malloc` | returned address + size |
| `uprobe_free` | `libc:free` | freed address |
| `uprobe_mmap` | `libc:mmap` | address, size, prot, flags |
| `uprobe_munmap` | `libc:munmap` | address, size |

**Performance optimization**: `uprobe_malloc` no longer emits a ring buffer event — it only writes the size to `pending_mallocs` map. The `uretprobe_malloc` combines both address and size into a single event, halving ring buffer writes.

**BPF Maps:**
- `events`: BPF_RINGBUF (64MB) for streaming events to userspace
- `stack_traces`: BPF_MAP_TYPE_STACK_TRACE (16K entries) for call stack capture
- `active_allocs`: Tracks live allocations (addr → alloc_info, 16K entries)
- `completed_allocs`: Records freed allocations for post-mortem
- `pending_mallocs`: Matches malloc entry/return by TID (4K entries)

### 2. Userspace Collector (`src/collector/`)

The collector is responsible for:
- Loading and attaching eBPF programs via libbpf
- Consuming events from the ring buffer
- Building a **hash table** mapping addresses to allocation metadata (O(1) lookup)
- Resolving stack traces from the BPF stack trace map
- Exporting allocation data as CSV for offline analysis

**Key optimization**: Allocation lookup uses a murmur3-finalizer hash table with 64K buckets and chaining, replacing the previous O(n) linear scan. This provides ~1000x speedup for 10K+ allocations.

**Hash table structure**:
```
alloc_table
├── records[]      — contiguous array of alloc_record
├── hash_buckets[] — 64K bucket heads (index into records)
└── hash_next[]    — chain links for collision resolution
```

### 3. DWARF Analyzer (`src/dwarf/dwarf_analyzer.cpp`)

Uses `elfutils/libdw` to parse:
- **ELF symbol table** (`.symtab`, `.dynsym`) for global symbol resolution
- **DWARF debug info** (`.debug_info`) for type definitions and field layouts
- **DWARF CFI** (`.debug_frame`) for stack frame unwinding (stubbed)
- **DWARF line info** (`.debug_line`) for source location mapping

Key data structures:
- `TypeInfo`: Complete struct/union/enum type with all fields and offsets
- `SymbolInfo`: Global symbol with address, size, type reference
- `CIERecord`/`FDERecord`: Call frame information for stack unwinding
- `SubprogramInfo`: Function metadata for callsite analysis

Field size resolution uses `dwarf_aggregate_size()` to follow type chains when `DW_AT_byte_size` is absent on member DIEs.

### 4. Address Resolver (`src/resolver/address_resolver.cpp`)

The resolver combines runtime data (from collector) with compile-time data (from DWARF) to produce field-level resolution:

**Address Classification:**
1. **Global**: Binary search in sorted symbol table
2. **Heap**: O(1) hash table lookup in allocation table, then type inference
3. **Stack**: CFI-based frame unwinding + DW_AT_location

**Type Inference Strategies:**
- **Direct**: Symbol has DW_AT_type → exact type known
- **Callsite**: Analyze malloc callsite stack → infer from context
- **Size matching**: O(1) lookup via pre-built `size_index_` hash map (size → type indices)

**Size Index**:
Built once at `load_binary()` time. Maps `byte_size → vector<type_index>` for O(1) type lookup by allocation size.

**Batch Resolution**:
The `batch` command loads DWARF once, then for each allocation:
1. Classify address → find containing allocation
2. Infer type from size via `size_index_`
3. Look up `TypeInfo` and expand **ALL fields** (not just offset=0)
4. Output one row per field per allocation

**Field Resolution:**
Given a type and byte offset within the allocation, binary search the type's field list to find the containing field.

## Build System

The project uses CMake with a modular structure:

```
CMakeLists.txt (top-level)
├── src/bpf/CMakeLists.txt       → memscope_bpf_obj (custom target)
├── src/collector/CMakeLists.txt → memscope_collector_lib + memscope-collect
├── src/dwarf/CMakeLists.txt     → memscope_dwarf_lib
├── src/resolver/CMakeLists.txt  → memscope_resolver_lib + memscope-resolve
└── src/benchmark/CMakeLists.txt → bench_target
```

Each module has its own CMakeLists.txt with explicit dependencies. Cross-module variables (compiler flags, include paths, BPF arch) are propagated via `CACHE INTERNAL` variables.

## Data Flow

```
1. Target process calls malloc(sizeof(struct Point))
2. eBPF uprobe: stores size=40 in pending_mallocs[tid]
3. malloc returns addr=0x7f8a3c001000
4. eBPF uretprobe: emits {addr=0x7f8a3c001000, size=40} via ring buffer
5. Collector: hash_table.insert(0x7f8a3c001000, {size=40, pid=1234})

6. User runs: batch -b target -f allocs.csv
7. Resolver:
   a. Load DWARF once → build type_db + size_index
   b. For each allocation in CSV:
      - Find alloc by addr → {size=40, live=1}
      - size_index[40] → struct Point
      - Expand all Point fields:
        · Point.x  offset=0  size=8  double
        · Point.y  offset=8  size=8  double
        · Point.z  offset=16 size=8  double
        · Point.label offset=24 size=8  char*
        · Point.count  offset=32 size=4  int
        · Point.flags  offset=36 size=4  int
8. Output: one CSV row per field per allocation
```

## Build Dependencies

- Linux kernel ≥ 5.8 (BPF ring buffer support)
- clang ≥ 12 (BPF target compilation)
- libbpf ≥ 0.5
- elfutils (libdw, libelf)
- cmake ≥ 3.16
- gcc / g++ (C11 / C++17)
