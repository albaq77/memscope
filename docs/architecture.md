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
│  │   → size+stack  │  │   → address      │   • allocation size  │
│  ├─────────────────┤  ├──────────────────┤   • call stack       │
│  │ uprobe_free     │  │ uprobe_mmap      │   • timestamps       │
│  │   → address     │  │   → addr+size    │   • PID/TID          │
│  └────────┬────────┘  └────────┬─────────┘                      │
│           │                    │                                 │
│           ▼                    ▼                                 │
│  ┌─────────────────────────────────────────┐                    │
│  │          BPF Ring Buffer (events)       │                    │
│  └────────────────────┬────────────────────┘                    │
└───────────────────────┼─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Userspace Collector                            │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐     │
│  │ Ring Buffer   │  │ Stack Trace   │  │ Allocation Table │     │
│  │ Consumer      │  │ Resolver      │  │ {addr→info}      │     │
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
│         ▼                 ▼                     ▼               │
│  ┌──────────────────────────────────────────────────────┐      │
│  │              Type Database                            │      │
│  │  struct Point { offset=0: x, offset=8: y, ... }     │      │
│  │  struct Node { offset=0: left, offset=8: right, .. }│      │
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
│    ├─ Heap?   → Allocation table lookup                          │
│    └─ Stack?  → CFI unwinding + DW_AT_location                  │
│                                                                  │
│  Step 2: Determine containing type                               │
│    ├─ Global → symbol's DW_AT_type                               │
│    ├─ Heap   → callsite inference / size matching                │
│    └─ Stack  → subprogram local variable DWARF                   │
│                                                                  │
│  Step 3: Resolve field                                           │
│    offset = address - base_address                               │
│    field  = type_db.find_field_at_offset(type, offset)           │
│                                                                  │
│  Output: struct Point.y (offset=8, size=8, type=double)          │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. eBPF Programs (`src/bpf/memscope.bpf.c`)

The kernel-side eBPF programs attach to userspace functions via uprobes:

| Probe | Target | Captures |
|-------|--------|----------|
| `uprobe_malloc` | `libc:malloc` | size argument, call stack |
| `uretprobe_malloc` | `libc:malloc` | returned address |
| `uprobe_free` | `libc:free` | freed address, call stack |
| `uprobe_mmap` | `libc:mmap` | address, size, prot, flags |
| `uprobe_munmap` | `libc:munmap` | address, size |

**BPF Maps:**
- `events`: BPF_RINGBUF for streaming events to userspace
- `stack_traces`: BPF_MAP_TYPE_STACK_TRACE for call stack capture
- `active_allocs`: Tracks live allocations (addr → alloc_info)
- `completed_allocs`: Records freed allocations for post-mortem
- `pending_mallocs`: Matches malloc entry/return by TID

### 2. Userspace Collector (`src/collector/`)

The collector is responsible for:
- Loading and attaching eBPF programs via libbpf
- Consuming events from the ring buffer
- Building an allocation table mapping addresses to allocation metadata
- Resolving stack traces from the BPF stack trace map
- Exporting allocation data as CSV for offline analysis

### 3. DWARF Analyzer (`src/dwarf/dwarf_analyzer.cpp`)

Uses `elfutils/libdw` to parse:
- **ELF symbol table** (`.symtab`, `.dynsym`) for global symbol resolution
- **DWARF debug info** (`.debug_info`) for type definitions and field layouts
- **DWARF CFI** (`.debug_frame`) for stack frame unwinding
- **DWARF line info** (`.debug_line`) for source location mapping

Key data structures:
- `TypeInfo`: Complete struct/union/enum type with all fields and offsets
- `SymbolInfo`: Global symbol with address, size, type reference
- `CIERecord`/`FDERecord`: Call frame information for stack unwinding
- `SubprogramInfo`: Function metadata for callsite analysis

### 4. Address Resolver (`src/resolver/address_resolver.cpp`)

The resolver combines runtime data (from collector) with compile-time data (from DWARF) to produce field-level resolution:

**Address Classification:**
1. **Global**: Binary search in sorted symbol table
2. **Heap**: Lookup in allocation table, then type inference
3. **Stack**: CFI-based frame unwinding + DW_AT_location

**Type Inference Strategies:**
- **Direct**: Symbol has DW_AT_type → exact type known
- **Callsite**: Analyze malloc callsite stack → infer from context
- **Size matching**: Match allocation size to struct byte_size (heuristic)

**Field Resolution:**
Given a type and byte offset within the allocation, binary search the type's field list to find the containing field.

## Data Flow

```
1. Target process calls malloc(sizeof(struct Point))
2. eBPF captures: {size=24, stack_id=5, tid=1234}
3. malloc returns addr=0x7f8a3c001000
4. eBPF captures: {addr=0x7f8a3c001000}
5. Collector records: alloc_table[0x7f8a3c001000] = {size=24, stack=5}

6. User queries: resolve(0x7f8a3c001008)
7. Resolver:
   a. Not in symbol table → not global
   b. Found in alloc_table: base=0x7f8a3c001000, size=24 → heap
   c. offset = 0x7f8a3c001008 - 0x7f8a3c001000 = 8
   d. size=24 → candidate type: struct Point (byte_size=24)
   e. Point field at offset 8: y (double, 8 bytes)
8. Result: struct Point.y at offset 8
```

## Build Dependencies

- Linux kernel ≥ 5.8 (BPF ring buffer support)
- clang ≥ 12 (BPF target compilation)
- libbpf ≥ 0.8
- elfutils (libdw, libelf)
- bpftool (for skeleton generation)
- gcc / g++ (C17 / C++17)
