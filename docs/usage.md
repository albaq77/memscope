# MemScope Usage Guide

## Prerequisites

```bash
# Ubuntu/Debian
sudo apt install clang llvm bpftool libbpf-dev libelf-dev libdw-dev

# Fedora
sudo dnf install clang llvm bpftool libbpf-devel elfutils-libelf-devel elfutils-devel
```

## Building

```bash
cd memscope
make
```

This produces:
- `build/memscope-collect` - eBPF collector (attach to running process)
- `build/memscope-resolve` - Offline DWARF resolver
- `build/bench_target` - Benchmark target program

## Quick Start

### Step 1: Trace a Target Process

```bash
# Build the benchmark target with debug info
gcc -g -O2 src/benchmark/bench_target.c -o build/bench_target -lm

# Start the target in background
./build/bench_target &
BENCH_PID=$!

# Run the collector
sudo ./build/memscope-collect -p $BENCH_PID -b ./build/bench_target -d 10 -o allocs.csv
```

### Step 2: Analyze DWARF Types

```bash
# List all types found in the binary
./build/memscope-resolve types -b ./build/bench_target

# Search for a specific type
./build/memscope-resolve types -b ./build/bench_target -n Point

# Print struct layout
./build/memscope-resolve layout -b ./build/bench_target -t Point
```

### Step 3: Resolve Addresses

```bash
# Resolve a global symbol address
./build/memscope-resolve resolve -b ./build/bench_target -a 0x401000

# Resolve a heap address using collected allocation data
./build/memscope-resolve resolve -b ./build/bench_target -a 0x55a123456010 -f allocs.csv

# Resolve with PID context
./build/memscope-resolve resolve -b ./build/bench_target -a 0x55a123456010 -p 12345 -f allocs.csv
```

### Step 4: List Symbols

```bash
# List all symbols
./build/memscope-resolve symbols -b ./build/bench_target

# Filter symbols by name
./build/memscope-resolve symbols -b ./build/bench_target -n create_tree
```

## Command Reference

### memscope-collect

```
Usage: memscope-collect [OPTIONS]

Options:
  -p, --pid PID        Target process PID (0 = all processes)
  -b, --binary PATH    Path to target binary for symbol resolution
  -o, --output FILE    Output CSV file for allocation data
  -d, --duration SEC   Trace duration in seconds (0 = until Ctrl-C)
  -v, --verbose        Verbose output
  -h, --help           Show help
```

**Output CSV format:**
```
address,size,pid,tid,live,timestamp_alloc,timestamp_free
0x55a123456000,24,1234,1234,1,1698765432109876543,0
0x55a123456020,48,1234,1235,0,1698765432109876544,1698765433109876543
```

### memscope-resolve

```
Usage: memscope-resolve <command> [OPTIONS]

Commands:
  analyze   Analyze binary DWARF info
  resolve   Resolve address to struct field
  layout    Print struct layout with offsets
  symbols   List/search symbols
  types     List/search types

Options:
  -b <path>   Binary file path (required)
  -a <addr>   Address to resolve (hex: 0x...)
  -t <type>   Type name
  -l <type>   Print layout for type
  -p <pid>    Process PID for heap resolution
  -f <csv>    Allocation CSV from collector
  -n <name>   Search filter for symbols/types
  -h          Show help
```

## Workflow Examples

### Finding Memory Leaks

```bash
# 1. Trace the process
sudo ./build/memscope-collect -p $PID -b ./myapp -d 60 -o trace.csv

# 2. Find live (leaked) allocations in the CSV
awk -F, 'NR>1 && $5=="1" {print $1, $2}' trace.csv

# 3. For each leaked address, resolve the type
./build/memscope-resolve resolve -b ./myapp -a 0x55a123456000 -f trace.csv
```

### Understanding Access Patterns

```bash
# 1. Identify a hot address from perf/cachegrind
HOT_ADDR=0x7f8a3c001048

# 2. Resolve what field it corresponds to
./build/memscope-resolve resolve -b ./myapp -a $HOT_ADDR -f trace.csv

# Output example:
# Address: 0x7f8a3c001048
# Class:   HEAP
# Type:    struct Point
# Alloc:   24 bytes
# Field:   Point.y (offset=8, size=8, type=double)
```

### Analyzing Struct Padding

```bash
# Print layout to see padding
./build/memscope-resolve layout -b ./myapp -t PaddedStruct

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
# Run all benchmarks with MemScope tracing
bash src/benchmark/bench_runner.sh

# Results are saved in results/ directory
```

## Troubleshooting

### "failed to open BPF object"
- Ensure `memscope.bpf.o` exists in the current directory
- Run `make` to build the BPF object

### "no DWARF info"
- Compile target with `-g` flag: `gcc -g ...`
- Check with `readelf -S binary | grep debug`

### "Permission denied" on BPF
- Run with `sudo` or set `kernel.perf_event_paranoid = -1`
- Ensure BTF is available: `bpftool btf dump file /sys/kernel/btf/vmlinux`

### "stack id not found"
- Stack traces are ephemeral; they may be evicted from the BPF map
- Increase `MAX_EVENTS` in `memscope_common.h`
