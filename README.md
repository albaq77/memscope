# MemScope

**eBPF + Offline DWARF Analysis: Runtime Address → Struct Field Mapping**

MemScope is a production-grade toolchain that combines eBPF runtime memory tracing with offline DWARF debug information analysis to map runtime memory addresses to their corresponding struct fields. It answers the question: *"Given a runtime address, which field of which struct does it correspond to?"*

## Features

- **eBPF-based memory tracing**: Hooks malloc/free/mmap via uprobes with minimal overhead
- **DWARF type analysis**: Parses ELF + DWARF debug info for complete type layouts
- **Address classification**: Automatically classifies addresses as global, heap, or stack
- **Field-level resolution**: Maps addresses to specific struct fields with offset and size
- **Type inference**: Infers heap allocation types from callsite analysis and size matching
- **Stack unwinding**: CFI-based frame unwinding for stack address resolution
- **Benchmark integration**: Built-in benchmark suite for performance validation
- **CSV export**: Allocation data export for offline analysis

## Architecture

```
Target Process → eBPF uprobes → Ring Buffer → Collector → CSV
                                                        ↓
Binary (ELF+DWARF) → DWARF Analyzer → Type Database → Address Resolver → struct.field
```

See [architecture.md](docs/architecture.md) for detailed design.

## Quick Start

```bash
# Build
make

# Trace a process
sudo ./build/memscope-collect -p <PID> -b ./target_binary -d 10 -o allocs.csv

# List types
./build/memscope-resolve types -b ./target_binary

# Print struct layout
./build/memscope-resolve layout -b ./target_binary -t Point

# Resolve an address
./build/memscope-resolve resolve -b ./target_binary -a 0x55a123456008 -f allocs.csv
```

See [usage.md](docs/usage.md) for complete documentation.

## Project Structure

```
memscope/
├── Makefile
├── docs/
│   ├── architecture.md          # Architecture documentation
│   └── usage.md                 # Usage guide
├── src/
│   ├── bpf/
│   │   ├── memscope.bpf.c       # eBPF kernel-side program
│   │   ├── memscope_common.h    # Shared data structures
│   │   └── vmlinux.h            # Minimal kernel type definitions
│   ├── collector/
│   │   ├── main.c               # Userspace eBPF loader & CLI
│   │   ├── collector.c          # Event collection & allocation tracking
│   │   └── collector.h          # Collector API
│   ├── dwarf/
│   │   ├── dwarf_analyzer.cpp   # DWARF analysis engine
│   │   └── dwarf_analyzer.h     # Analyzer API & data structures
│   ├── resolver/
│   │   ├── address_resolver.cpp # Address → struct.field mapper
│   │   ├── address_resolver.h   # Resolver API
│   │   └── main.cpp             # Resolver CLI
│   └── benchmark/
│       ├── bench_target.c       # Benchmark target program
│       └── bench_runner.sh      # Benchmark runner script
└── tests/
    └── test_cases/
        ├── test_struct_layout.c
        ├── test_alloc_tracking.c
        └── test_field_resolution.c
```

## Requirements

- Linux kernel ≥ 5.8 (BPF ring buffer)
- clang ≥ 12
- libbpf ≥ 0.8
- elfutils (libdw, libelf)
- bpftool
- gcc / g++ (C17 / C++17)

## License

Dual BSD/GPL
