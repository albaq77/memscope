# MemScope

**eBPF + Offline DWARF Analysis: Runtime Address → Struct Field Mapping**

MemScope is a production-grade toolchain that combines eBPF runtime memory tracing with offline DWARF debug information analysis to map runtime memory addresses to their corresponding struct fields. It answers the question: *"Given a runtime address, which field of which struct does it correspond to?"*

## Features

- **eBPF-based memory tracing**: Hooks malloc/free/mmap via uprobes with minimal overhead
- **DWARF type analysis**: Parses ELF + DWARF debug info for complete type layouts
- **Address classification**: Automatically classifies addresses as global, heap, or stack
- **Field-level resolution**: Maps addresses to specific struct fields with offset and size
- **Type inference**: Infers heap allocation types from callsite analysis and size matching
- **Batch resolution**: One-shot DWARF load + bulk resolve all allocations with full field expansion
- **Concurrent lookup**: O(1) hash table for allocation lookup and size→type index
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
# Build with CMake
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build . -j$(nproc)

# Trace a process
sudo ./build/src/collector/memscope-collect -p <PID> -b ./target_binary -d 10 -o allocs.csv

# List types
./build/src/resolver/memscope-resolve types -b ./target_binary

# Print struct layout
./build/src/resolver/memscope-resolve layout -b ./target_binary -t Point

# Batch resolve all allocations to struct fields
./build/src/resolver/memscope-resolve batch -b ./target_binary -f allocs.csv -o resolved.csv

# Resolve a single address
./build/src/resolver/memscope-resolve resolve -b ./target_binary -a 0x55a123456008 -f allocs.csv
```

See [usage.md](docs/usage.md) for complete documentation.

## Project Structure

```
memscope/
├── CMakeLists.txt              # Top-level CMake: global settings + add_subdirectory
├── src/
│   ├── config.h.in             # Version template
│   ├── bpf/
│   │   ├── CMakeLists.txt      # BPF compilation (clang -target bpf)
│   │   ├── memscope.bpf.c      # eBPF kernel-side program
│   │   ├── memscope_common.h   # Shared data structures
│   │   └── vmlinux.h           # Minimal kernel type definitions
│   ├── collector/
│   │   ├── CMakeLists.txt      # Collector library + executable
│   │   ├── main.c              # Userspace eBPF loader & CLI
│   │   ├── collector.c         # Event collection & hash-table allocation tracking
│   │   └── collector.h         # Collector API
│   ├── dwarf/
│   │   ├── CMakeLists.txt      # DWARF analysis library
│   │   ├── dwarf_analyzer.cpp  # DWARF analysis engine
│   │   └── dwarf_analyzer.h    # Analyzer API & data structures
│   ├── resolver/
│   │   ├── CMakeLists.txt      # Resolver library + executable
│   │   ├── address_resolver.cpp # Address → struct.field mapper with size index
│   │   ├── address_resolver.h  # Resolver API
│   │   └── main.cpp            # Resolver CLI (types/layout/resolve/batch/lookup)
│   └── benchmark/
│       ├── CMakeLists.txt      # Benchmark target
│       ├── bench_target.c      # Benchmark target program
│       ├── bench_runner.sh     # Benchmark runner script
│       └── demo_resolve.sh     # End-to-end demo script
└── docs/
    ├── architecture.md         # Architecture documentation
    └── usage.md                # Usage guide
```

## Requirements

- Linux kernel ≥ 5.8 (BPF ring buffer)
- clang ≥ 12
- libbpf ≥ 0.5
- elfutils (libdw, libelf)
- cmake ≥ 3.16
- gcc / g++ (C11 / C++17)

## License

Dual BSD/GPL
