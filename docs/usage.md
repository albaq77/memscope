# MemScope Usage Guide

## Prerequisites

```bash
# Ubuntu/Debian
sudo apt install clang llvm cmake libbpf-dev libelf-dev libdw-dev

# Fedora
sudo dnf install clang llvm cmake libbpf-devel elfutils-libelf-devel elfutils-devel
```

## Building

```bash
cd memscope
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build . -j$(nproc)
```

This produces:
- `build/src/collector/memscope-collect` - eBPF collector (attach to running process)
- `build/src/resolver/memscope-resolve` - Offline DWARF resolver
- `build/src/bpf/memscope.bpf.o` - Compiled BPF object
- `build/src/benchmark/bench_target` - Benchmark target program

### Build Options

```bash
# Release build (optimized)
cmake -DCMAKE_BUILD_TYPE=Release ..

# Clean rebuild
rm -rf build && mkdir build && cd build
cmake .. && cmake --build . -j$(nproc)
```

## Quick Start

### Step 1: Trace a Target Process

```bash
# Start the target in background
./build/src/benchmark/bench_target &
BENCH_PID=$!

# Run the collector (requires root for eBPF)
sudo ./build/src/collector/memscope-collect -p $BENCH_PID -b ./build/src/benchmark/bench_target -d 10 -o allocs.csv
```

### Step 2: Analyze DWARF Types

```bash
# List all types found in the binary
./build/src/resolver/memscope-resolve types -b ./build/src/benchmark/bench_target

# Search for a specific type
./build/src/resolver/memscope-resolve types -b ./build/src/benchmark/bench_target -n Point

# Print struct layout
./build/src/resolver/memscope-resolve layout -b ./build/src/benchmark/bench_target -t Point
```

### Step 3: Resolve Addresses

```bash
# Resolve a global symbol address
./build/src/resolver/memscope-resolve resolve -b ./target_binary -a 0x401000

# Resolve a heap address using collected allocation data
./build/src/resolver/memscope-resolve resolve -b ./target_binary -a 0x55a123456010 -f allocs.csv
```

### Step 4: Batch Resolve All Allocations

```bash
# One-shot: load DWARF once, resolve all allocations, expand all fields
./build/src/resolver/memscope-resolve batch -b ./target_binary -f allocs.csv -o resolved.csv
```

This produces a CSV with every field of every matched type:
```
address,size,region,type,field,offset,size_bytes,field_type
0x55a123456000,40,HEAP,Point,Point.x,0,8,double
0x55a123456000,40,HEAP,Point,Point.y,8,8,double
0x55a123456000,40,HEAP,Point,Point.z,16,8,double
0x55a123456000,40,HEAP,Point,Point.label,24,8,char*
0x55a123456000,40,HEAP,Point,Point.count,32,4,int
0x55a123456000,40,HEAP,Point,Point.flags,36,4,int
```

### Step 5: List Symbols

```bash
# List all symbols
./build/src/resolver/memscope-resolve symbols -b ./target_binary

# Filter symbols by name
./build/src/resolver/memscope-resolve symbols -b ./target_binary -n create_tree
```

## Command Reference

### memscope-collect

```
Usage: memscope-collect [OPTIONS]

Options:
  -p, --pid PID        Target process PID (0 = all processes)
  -b, --binary PATH    Path to target binary for symbol resolution
  -B, --bpf PATH       Path to BPF object file
  -o, --output FILE    Output CSV file for allocation data
  -d, --duration SEC   Trace duration in seconds (0 = until Ctrl-C)
  -v, --verbose        Verbose output
  -h, --help           Show help
```

**Output CSV format:**
```
address,size,pid,tid,live,timestamp_alloc,timestamp_free
0x55a123456000,40,1234,1234,1,1698765432109876543,0
0x55a123456020,48,1234,1235,0,1698765432109876544,1698765433109876543
```

### memscope-resolve

```
Usage: memscope-resolve <command> [OPTIONS]

Commands:
  types     List/search types in binary
  layout    Print struct layout with offsets
  symbols   List/search symbols
  resolve   Resolve a single address to struct field
  batch     Bulk resolve all allocations with full field expansion
  lookup    Concise address → field lookup

Options:
  -b <path>   Binary file path (required)
  -a <addr>   Address to resolve (hex: 0x..., can specify multiple)
  -t <type>   Type name
  -f <csv>    Allocation CSV from collector
  -o <file>   Output file for batch results
  -p <pid>    Process PID for heap resolution
  -n <name>   Search filter for symbols/types
  -h          Show help
```

## Workflow Examples

### End-to-End Demo

```bash
# Run the automated demo script
bash src/benchmark/demo_resolve.sh
```

This script automatically:
1. Builds the project with CMake
2. Displays struct types and layouts
3. Runs the eBPF collector + benchmark target
4. Batch resolves all allocations to struct fields

### Finding Memory Leaks

```bash
# 1. Trace the process
sudo ./build/src/collector/memscope-collect -p $PID -b ./myapp -d 60 -o trace.csv

# 2. Find live (leaked) allocations in the CSV
awk -F, 'NR>1 && $5=="1" {print $1, $2}' trace.csv

# 3. Batch resolve all live allocations
./build/src/resolver/memscope-resolve batch -b ./myapp -f trace.csv -o resolved.csv
```

### Understanding Access Patterns

```bash
# 1. Identify a hot address from perf/cachegrind
HOT_ADDR=0x7f8a3c001048

# 2. Resolve what field it corresponds to
./build/src/resolver/memscope-resolve resolve -b ./myapp -a $HOT_ADDR -f trace.csv

# Output example:
# Address: 0x7f8a3c001048
# Class:   HEAP
# Type:    struct Point
# Alloc:   40 bytes
# Field:   Point.y (offset=8, size=8, type=double)
```

### Analyzing Struct Padding

```bash
# Print layout to see padding
./build/src/resolver/memscope-resolve layout -b ./myapp -t PaddedStruct

# Output:
# struct PaddedStruct (size=24, align=8)
#   Offset  Size  Type            Name
#   ------  ----  ----            ----
#        0     1  char            flag
#        8     8  double          value
#       16     2  short           count
#       24     8  long            total
#        8     7  <padding>       <padding after flag>
```

## Benchmarking

```bash
# Run all benchmarks with MemScope tracing (requires sudo for eBPF)
sudo bash src/benchmark/bench_runner.sh

# Results are saved in results/ directory
```

## Performance Characteristics

| Component | Optimization | Complexity |
|-----------|-------------|------------|
| Collector allocation lookup | Murmur3 hash table (64K buckets) | O(1) |
| Resolver size→type mapping | Pre-built size_index hash map | O(1) |
| Resolver allocation lookup | Binary search on sorted allocs | O(log n) |
| BPF event emission | malloc entry not emitted (map only) | ~2x fewer events |
| BPF ring buffer | 64MB buffer | Fewer drops |
| Batch DWARF load | One-time parse + index build | Amortized O(1) per query |

## Troubleshooting

### "failed to open BPF object"
- Ensure `memscope.bpf.o` exists: `ls build/src/bpf/memscope.bpf.o`
- Rebuild: `cmake --build build`

### "Operation not permitted" on BPF
- Run collector with `sudo`
- Or set `kernel.perf_event_paranoid = -1`

### "no DWARF info"
- Compile target with `-g` flag: `gcc -g ...`
- Check with `readelf -S binary | grep debug`

### "stack id not found"
- Stack traces are ephemeral; they may be evicted from the BPF map
- Increase `MAX_EVENTS` in `memscope_common.h`

### "libbpf version too old"
- Minimum required: libbpf ≥ 0.5
- To upgrade from source:
  ```bash
  git clone --depth 1 --branch v1.4.0 https://github.com/libbpf/libbpf.git
  cd libbpf && make -C src && sudo make -C src install && sudo ldconfig
  ```
