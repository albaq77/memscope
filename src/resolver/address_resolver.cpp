#include "address_resolver.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdio>

namespace memscope {

AddressResolver::AddressResolver()
{
}

AddressResolver::~AddressResolver()
{
}

int AddressResolver::load_binary(const std::string &path)
{
    binary_path_ = path;
    return analyzer_.load_binary(path);
}

void AddressResolver::set_alloc_table(const std::vector<AllocInfo> &allocs)
{
    allocs_ = allocs;
    std::sort(allocs_.begin(), allocs_.end(),
              [](const AllocInfo &a, const AllocInfo &b) {
                  return a.addr < b.addr;
              });
}

const AllocInfo *AddressResolver::find_alloc(uint64_t addr) const
{
    auto cmp = [](uint64_t v, const AllocInfo &a) { return v < a.addr; };
    auto it = std::upper_bound(allocs_.begin(), allocs_.end(), addr, cmp);
    if (it == allocs_.begin())
        return nullptr;

    --it;
    if (addr >= it->addr && addr < it->addr + it->size && it->live)
        return &(*it);
    return nullptr;
}

std::string AddressResolver::infer_type_from_callsite(int64_t stack_id) const
{
    return "";
}

std::string AddressResolver::infer_type_from_size(uint64_t size) const
{
    if (size == 0)
        return "";

    const auto &types = analyzer_.get_all_types();
    std::vector<std::string> candidates;
    for (const auto &t : types) {
        if (t.byte_size == size && !t.fields.empty()) {
            candidates.push_back(t.name);
        }
    }
    if (candidates.size() == 1)
        return candidates[0];
    if (candidates.size() > 1)
        return candidates[0] + " (ambiguous: " + std::to_string(candidates.size()) + " candidates)";
    return "";
}

std::optional<ResolvedAddress> AddressResolver::resolve(
    uint64_t address, uint32_t pid,
    const std::vector<uint64_t> &stack_frames) const
{
    auto global = resolve_global(address);
    if (global)
        return global;

    auto heap = resolve_heap(address, pid);
    if (heap)
        return heap;

    auto stack = resolve_stack(address, stack_frames);
    if (stack)
        return stack;

    ResolvedAddress result = {};
    result.addr_class = ResolvedAddress::ADDR_UNKNOWN;
    result.address = address;
    return result;
}

std::optional<ResolvedAddress> AddressResolver::resolve_global(uint64_t address) const
{
    const SymbolInfo *sym = analyzer_.find_symbol_by_addr(address);
    if (!sym)
        return std::nullopt;

    ResolvedAddress result = {};
    result.addr_class = ResolvedAddress::ADDR_GLOBAL;
    result.address = address;
    result.symbol_name = sym->name;
    result.type_name = sym->type_name;

    if (!sym->type_name.empty()) {
        uint64_t offset = address - sym->address;
        auto field = analyzer_.resolve_field_at_offset(sym->type_name, offset);
        if (field) {
            ResolvedField rf = {};
            rf.type_name = sym->type_name;
            rf.field_name = field->name;
            rf.full_path = sym->type_name + "." + field->name;
            rf.field_byte_offset = field->byte_offset;
            rf.field_byte_size = field->byte_size;
            rf.base_address = sym->address;
            rf.resolved_address = address;
            rf.field_type_name = field->type_name;
            rf.is_bitfield = field->is_bitfield;
            rf.bit_offset_within_field = field->is_bitfield
                ? (offset * 8 - field->bit_offset) : 0;
            result.fields.push_back(rf);
        }
    }

    return result;
}

std::optional<ResolvedAddress> AddressResolver::resolve_heap(uint64_t address,
                                                              uint32_t pid) const
{
    const AllocInfo *alloc = find_alloc(address);
    if (!alloc)
        return std::nullopt;

    ResolvedAddress result = {};
    result.addr_class = ResolvedAddress::ADDR_HEAP;
    result.address = address;
    result.allocation_size = alloc->size;
    result.pid = alloc->pid;
    result.tid = alloc->tid;

    uint64_t offset = address - alloc->addr;

    std::string type_name = infer_type_from_callsite(alloc->stack_id);
    if (type_name.empty())
        type_name = infer_type_from_size(alloc->size);

    result.type_name = type_name;

    if (!type_name.empty()) {
        auto field = analyzer_.resolve_field_at_offset(type_name, offset);
        if (field) {
            ResolvedField rf = {};
            rf.type_name = type_name;
            rf.field_name = field->name;
            rf.full_path = type_name + "." + field->name;
            rf.field_byte_offset = field->byte_offset;
            rf.field_byte_size = field->byte_size;
            rf.base_address = alloc->addr;
            rf.resolved_address = address;
            rf.field_type_name = field->type_name;
            rf.is_bitfield = field->is_bitfield;
            rf.bit_offset_within_field = field->is_bitfield
                ? (offset * 8 - field->bit_offset) : 0;
            result.fields.push_back(rf);
        }
    }

    return result;
}

std::optional<ResolvedAddress> AddressResolver::resolve_stack(
    uint64_t address,
    const std::vector<uint64_t> &frames) const
{
    if (frames.empty())
        return std::nullopt;

    const SymbolInfo *sym = analyzer_.find_symbol_by_addr(frames[0]);
    if (!sym)
        return std::nullopt;

    ResolvedAddress result = {};
    result.addr_class = ResolvedAddress::ADDR_STACK;
    result.address = address;
    result.symbol_name = sym->name;

    result.stack_trace = resolve_stack_trace(frames);

    return result;
}

std::optional<ResolvedField> AddressResolver::resolve_heap_field(
    uint64_t base_addr, uint64_t offset) const
{
    const AllocInfo *alloc = find_alloc(base_addr);
    if (!alloc)
        return std::nullopt;

    std::string type_name = infer_type_from_size(alloc->size);
    if (type_name.empty())
        return std::nullopt;

    auto field = analyzer_.resolve_field_at_offset(type_name, offset);
    if (!field)
        return std::nullopt;

    ResolvedField rf = {};
    rf.type_name = type_name;
    rf.field_name = field->name;
    rf.full_path = type_name + "." + field->name;
    rf.field_byte_offset = field->byte_offset;
    rf.field_byte_size = field->byte_size;
    rf.base_address = base_addr;
    rf.resolved_address = base_addr + offset;
    rf.field_type_name = field->type_name;
    rf.is_bitfield = field->is_bitfield;
    return rf;
}

std::optional<ResolvedField> AddressResolver::resolve_global_field(
    const std::string &symbol_name, uint64_t offset) const
{
    const SymbolInfo *sym = analyzer_.find_symbol_by_name(symbol_name);
    if (!sym || sym->type_name.empty())
        return std::nullopt;

    auto field = analyzer_.resolve_field_at_offset(sym->type_name, offset);
    if (!field)
        return std::nullopt;

    ResolvedField rf = {};
    rf.type_name = sym->type_name;
    rf.field_name = field->name;
    rf.full_path = sym->type_name + "." + field->name;
    rf.field_byte_offset = field->byte_offset;
    rf.field_byte_size = field->byte_size;
    rf.base_address = sym->address;
    rf.resolved_address = sym->address + offset;
    rf.field_type_name = field->type_name;
    rf.is_bitfield = field->is_bitfield;
    return rf;
}

std::optional<ResolvedField> AddressResolver::resolve_stack_field(
    uint64_t frame_base, int64_t stack_offset,
    const std::string &func_name) const
{
    return std::nullopt;
}

std::vector<ResolvedStackFrame> AddressResolver::resolve_stack_trace(
    const std::vector<uint64_t> &frames) const
{
    std::vector<ResolvedStackFrame> result;
    result.reserve(frames.size());

    for (uint64_t pc : frames) {
        ResolvedStackFrame frame = {};
        frame.pc = pc;

        const SymbolInfo *sym = analyzer_.find_symbol_by_addr(pc);
        if (sym) {
            frame.function_name = sym->name;
            frame.offset_within_func = (int64_t)(pc - sym->address);
        } else {
            std::ostringstream oss;
            oss << "0x" << std::hex << pc;
            frame.function_name = oss.str();
            frame.offset_within_func = 0;
        }

        result.push_back(frame);
    }

    return result;
}

std::string AddressResolver::resolved_to_string(const ResolvedAddress &resolved) const
{
    std::ostringstream oss;
    oss << "Address: 0x" << std::hex << resolved.address << std::dec << "\n";

    switch (resolved.addr_class) {
    case ResolvedAddress::ADDR_GLOBAL:
        oss << "Class:   GLOBAL\n";
        break;
    case ResolvedAddress::ADDR_STACK:
        oss << "Class:   STACK\n";
        break;
    case ResolvedAddress::ADDR_HEAP:
        oss << "Class:   HEAP\n";
        break;
    default:
        oss << "Class:   UNKNOWN\n";
        break;
    }

    if (!resolved.symbol_name.empty())
        oss << "Symbol:  " << resolved.symbol_name << "\n";
    if (!resolved.type_name.empty())
        oss << "Type:    " << resolved.type_name << "\n";
    if (resolved.allocation_size)
        oss << "Alloc:   " << resolved.allocation_size << " bytes\n";
    if (resolved.pid)
        oss << "PID:     " << resolved.pid << " TID: " << resolved.tid << "\n";

    for (const auto &field : resolved.fields) {
        oss << "Field:   " << field.full_path
            << " (offset=" << field.field_byte_offset
            << ", size=" << field.field_byte_size;
        if (!field.field_type_name.empty())
            oss << ", type=" << field.field_type_name;
        if (field.is_bitfield)
            oss << ", bit_offset=" << field.bit_offset_within_field;
        oss << ")\n";
    }

    if (!resolved.stack_trace.empty()) {
        oss << "Stack:\n";
        for (size_t i = 0; i < resolved.stack_trace.size(); i++) {
            const auto &frame = resolved.stack_trace[i];
            oss << "  #" << i << " 0x" << std::hex << frame.pc << std::dec
                << " " << frame.function_name;
            if (frame.offset_within_func)
                oss << "+" << frame.offset_within_func;
            if (!frame.source_file.empty())
                oss << " (" << frame.source_file << ":" << frame.source_line << ")";
            oss << "\n";
        }
    }

    return oss.str();
}

}
