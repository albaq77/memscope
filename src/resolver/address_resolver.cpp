#include "address_resolver.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace memscope {

static FILE *debug_log_fp = nullptr;

static void debug_log(const char *fmt, ...)
{
    if (!debug_log_fp)
        return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(debug_log_fp, fmt, ap);
    va_end(ap);
    fflush(debug_log_fp);
}

AddressResolver::AddressResolver()
    : stack_map_fd_(-1)
    , aslr_offset_(0)
{
}

AddressResolver::~AddressResolver()
{
}

int AddressResolver::load_binary(const std::string &path)
{
    binary_path_ = path;
    int rc = analyzer_.load_binary(path);
    if (rc == 0)
        build_size_index();
    return rc;
}

void AddressResolver::build_size_index()
{
    size_index_.clear();
    const auto &types = analyzer_.get_all_types();
    for (size_t i = 0; i < types.size(); i++) {
        if (types[i].byte_size > 0 && !types[i].fields.empty()) {
            size_index_[types[i].byte_size].push_back(i);
        }
    }
}

void AddressResolver::set_alloc_table(const std::vector<AllocInfo> &allocs)
{
    allocs_ = allocs;
    std::sort(allocs_.begin(), allocs_.end(),
              [](const AllocInfo &a, const AllocInfo &b) {
                  return a.addr < b.addr;
              });
}

void AddressResolver::set_stack_map_fd(int fd)
{
    stack_map_fd_ = fd;
}

void AddressResolver::set_debug_log(const std::string &path)
{
    if (debug_log_fp) {
        fclose(debug_log_fp);
        debug_log_fp = nullptr;
    }
    if (!path.empty()) {
        debug_log_fp = fopen(path.c_str(), "a");
    }
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

std::vector<std::string> AddressResolver::resolve_stack_function_names(int64_t stack_id) const
{
    std::vector<std::string> result;

    if (stack_map_fd_ < 0 || stack_id < 0)
        return result;

    uint64_t pcs[128];
    memset(pcs, 0, sizeof(pcs));
    int64_t key = stack_id;

    int err = bpf_map_lookup_elem(stack_map_fd_, &key, pcs);
    if (err != 0)
        return result;

    static const std::vector<std::string> skip_names = {
        "malloc", "free", "__libc_malloc", "__libc_free",
        "calloc", "realloc", "__libc_calloc", "__libc_realloc",
        "memalign", "__libc_memalign", "posix_memalign",
        "aligned_alloc", "valloc", "pvalloc"
    };

    for (int i = 0; i < 128; i++) {
        if (pcs[i] == 0)
            break;

        const SymbolInfo *sym = analyzer_.find_symbol_by_addr(pcs[i]);
        if (!sym)
            continue;

        bool skip = false;
        for (const auto &s : skip_names) {
            if (sym->name == s) {
                skip = true;
                break;
            }
        }
        if (!skip)
            result.push_back(sym->name);
    }

    return result;
}

std::vector<std::string> AddressResolver::resolve_function_names_from_pcs(
    const std::vector<uint64_t> &pcs) const
{
    std::vector<std::string> result;

    static const std::vector<std::string> skip_names = {
        "malloc", "free", "__libc_malloc", "__libc_free",
        "calloc", "realloc", "__libc_calloc", "__libc_realloc",
        "memalign", "__libc_memalign", "posix_memalign",
        "aligned_alloc", "valloc", "pvalloc"
    };

    for (uint64_t pc : pcs) {
        uint64_t file_pc = va_to_file_offset(pc);
        const SymbolInfo *sym = analyzer_.find_symbol_by_addr(file_pc);
        if (!sym) {
            sym = analyzer_.find_symbol_by_addr(pc);
        }
        if (!sym)
            continue;

        bool skip = false;
        for (const auto &s : skip_names) {
            if (sym->name == s) {
                skip = true;
                break;
            }
        }
        if (!skip)
            result.push_back(sym->name);
    }

    return result;
}

std::string AddressResolver::infer_type_from_callsite(int64_t stack_id) const
{
    if (stack_id <= 0)
        return "";

    auto func_names = resolve_stack_function_names(stack_id);
    if (func_names.empty())
        return "";

    std::vector<std::string> candidates;

    for (const auto &func_name : func_names) {
        const SubprogramInfo *subprog = analyzer_.find_subprogram_by_name(func_name);
        if (!subprog)
            continue;

        for (const auto &var : subprog->local_variables) {
            if (var.is_pointer && !var.pointer_target_type_name.empty()) {
                candidates.push_back(var.pointer_target_type_name);
            }
        }
    }

    if (candidates.empty())
        return "";

    if (candidates.size() == 1)
        return candidates[0];

    return candidates[0] + " (ambiguous: " + std::to_string(candidates.size()) + " callsite candidates)";
}

std::string AddressResolver::infer_type_from_size(uint64_t size) const
{
    if (size == 0)
        return "";

    auto it = size_index_.find(size);
    if (it == size_index_.end())
        return "";

    const auto &candidates = it->second;
    const auto &types = analyzer_.get_all_types();

    if (candidates.size() == 1)
        return types[candidates[0]].name;
    if (candidates.size() > 1)
        return types[candidates[0]].name + " (ambiguous: " + std::to_string(candidates.size()) + " candidates)";
    return "";
}

std::string AddressResolver::infer_type_combined(int64_t stack_id, uint64_t size) const
{
    std::vector<std::string> callsite_candidates;

    if (stack_id > 0) {
        auto func_names = resolve_stack_function_names(stack_id);
        for (const auto &func_name : func_names) {
            const SubprogramInfo *subprog = analyzer_.find_subprogram_by_name(func_name);
            if (!subprog)
                continue;

            for (const auto &var : subprog->local_variables) {
                if (var.is_pointer && !var.pointer_target_type_name.empty()) {
                    callsite_candidates.push_back(var.pointer_target_type_name);
                }
            }
        }
    }

    if (callsite_candidates.size() == 1)
        return callsite_candidates[0];

    std::vector<std::string> size_candidates;

    if (size > 0) {
        auto it = size_index_.find(size);
        if (it != size_index_.end()) {
            const auto &indices = it->second;
            const auto &types = analyzer_.get_all_types();
            for (size_t idx : indices) {
                size_candidates.push_back(types[idx].name);
            }
        }
    }

    if (!callsite_candidates.empty() && !size_candidates.empty()) {
        std::vector<std::string> intersection;
        for (const auto &c : callsite_candidates) {
            for (const auto &s : size_candidates) {
                if (c == s) {
                    intersection.push_back(c);
                    break;
                }
            }
        }

        if (intersection.size() == 1)
            return intersection[0];
        if (intersection.size() > 1)
            return intersection[0] + " (ambiguous: " + std::to_string(intersection.size()) + " candidates)";
    }

    if (!callsite_candidates.empty())
        return callsite_candidates[0] + " (ambiguous: " + std::to_string(callsite_candidates.size()) + " callsite candidates)";

    return infer_type_from_size(size);
}

std::vector<uint64_t> AddressResolver::resolve_stack_pcs(int64_t stack_id) const
{
    std::vector<uint64_t> result;

    if (stack_map_fd_ < 0 || stack_id < 0)
        return result;

    uint64_t pcs[128];
    memset(pcs, 0, sizeof(pcs));
    int64_t key = stack_id;

    if (bpf_map_lookup_elem(stack_map_fd_, &key, pcs) != 0)
        return result;

    for (int i = 0; i < 128; i++) {
        if (pcs[i] == 0)
            break;
        result.push_back(pcs[i]);
    }

    return result;
}

int64_t AddressResolver::compute_aslr_offset(const std::vector<uint64_t> &runtime_pcs) const
{
    if (aslr_offset_ != 0)
        return aslr_offset_;

    const auto &syms = analyzer_.get_all_symbols();
    const auto &subprogs = analyzer_.get_subprograms();

    for (uint64_t runtime_pc : runtime_pcs) {
        for (const auto &sp : subprogs) {
            if (sp.low_pc == 0 || sp.high_pc == 0)
                continue;

            uint64_t compile_start = sp.low_pc;
            uint64_t compile_size = sp.high_pc_is_offset ? sp.high_pc : (sp.high_pc - sp.low_pc);

            for (const auto &sym : syms) {
                if (sym.sym_type != SymbolInfo::SYM_FUNC || sym.address == 0)
                    continue;

                if (sym.name == sp.name || sym.name == sp.linkage_name) {
                    int64_t offset = (int64_t)sym.address - (int64_t)compile_start;
                    if (offset != 0) {
                        debug_log("[DEBUG] ASLR offset computed: sym_addr=0x%lx compile_low_pc=0x%lx offset=%ld (from %s)\n",
                                  sym.address, compile_start, offset, sp.name.c_str());
                        const_cast<int64_t&>(aslr_offset_) = offset;
                        return offset;
                    }
                }
            }
        }
    }

    debug_log("[DEBUG] ASLR offset: could not compute, assuming 0\n");
    return 0;
}

uint64_t AddressResolver::va_to_file_offset(uint64_t va) const
{
    if (aslr_offset_ != 0)
        return (uint64_t)((int64_t)va - aslr_offset_);
    return va;
}

std::vector<std::string> AddressResolver::get_size_candidates(uint64_t size) const
{
    std::vector<std::string> result;
    auto it = size_index_.find(size);
    if (it == size_index_.end())
        return result;

    const auto &types = analyzer_.get_all_types();
    for (size_t idx : it->second)
        result.push_back(types[idx].name);

    return result;
}

TypeInferenceResult AddressResolver::try_array_size_match(uint64_t size) const
{
    TypeInferenceResult result = {};
    const auto &types = analyzer_.get_all_types();

    for (const auto &type : types) {
        if (type.fields.empty())
            continue;
        if (type.byte_size < 8)
            continue;
        if (size % type.byte_size != 0)
            continue;

        uint64_t count = size / type.byte_size;
        if (count < 2 || count > 100000)
            continue;

        if (result.type_name.empty()) {
            result.type_name = type.name;
            result.alloc_count = count;
            result.method = "array_size_match";
            result.confidence = 0.35f;
        } else {
            result.type_name += " (ambiguous)";
            result.confidence = 0.15f;
            break;
        }
    }

    return result;
}

TypeInferenceResult AddressResolver::infer_type_combined_v2(
    int64_t stack_id, uint64_t size,
    const std::vector<uint64_t> &inline_pcs) const
{
    TypeInferenceResult result = {};
    result.alloc_count = 1;

    std::vector<uint64_t> pcs;

    if (!inline_pcs.empty()) {
        pcs = inline_pcs;
        debug_log("[DEBUG] infer_type_combined_v2: using %zu inline PCs (stack_id=%ld, size=%lu)\n",
                  pcs.size(), stack_id, size);
    } else if (stack_id > 0) {
        pcs = resolve_stack_pcs(stack_id);
        debug_log("[DEBUG] infer_type_combined_v2: using stack_map PCs (stack_id=%ld, size=%lu, got %zu PCs)\n",
                  stack_id, size, pcs.size());
    } else {
        debug_log("[DEBUG] infer_type_combined_v2: NO stack info (stack_id=%ld, size=%lu)\n",
                  stack_id, size);
    }

    if (!pcs.empty()) {
        compute_aslr_offset(pcs);
        debug_log("[DEBUG]   ASLR offset: %ld\n", aslr_offset_);

        for (size_t i = 1; i < pcs.size(); i++) {
            uint64_t caller_pc = pcs[i] > 0 ? pcs[i] - 1 : pcs[i];
            uint64_t file_offset = va_to_file_offset(caller_pc);
            debug_log("[DEBUG]   pcs[%zu]=0x%lx caller=0x%lx file_off=0x%lx\n",
                      i, pcs[i], caller_pc, file_offset);

            auto pc_types = analyzer_.find_pointer_target_types_at_pc(file_offset);
            debug_log("[DEBUG]   find_pointer_target_types_at_pc(0x%lx): %zu candidates\n",
                      file_offset, pc_types.size());
            for (const auto &t : pc_types)
                debug_log("[DEBUG]     candidate: %s\n", t.c_str());

            if (pc_types.size() == 1) {
                result.type_name = pc_types[0];
                result.method = "callsite_pc";
                result.confidence = 0.95f;

                const TypeInfo *ti = analyzer_.find_type_by_name(result.type_name);
                if (ti && ti->byte_size > 0 && size % ti->byte_size == 0) {
                    result.alloc_count = size / ti->byte_size;
                    if (result.alloc_count > 1)
                        result.note = "array allocation (" +
                                      std::to_string(result.alloc_count) + " elements)";
                }

                return result;
            }

            if (pc_types.size() > 1) {
                auto size_candidates = get_size_candidates(size);

                std::vector<std::string> intersection;
                for (const auto &c : pc_types) {
                    for (const auto &s : size_candidates) {
                        if (c == s) {
                            intersection.push_back(c);
                            break;
                        }
                    }
                }

                if (intersection.size() == 1) {
                    result.type_name = intersection[0];
                    result.method = "combined";
                    result.confidence = 0.80f;

                    const TypeInfo *ti = analyzer_.find_type_by_name(result.type_name);
                    if (ti && ti->byte_size > 0 && size % ti->byte_size == 0) {
                        result.alloc_count = size / ti->byte_size;
                        if (result.alloc_count > 1)
                            result.note = "array allocation (" +
                                          std::to_string(result.alloc_count) + " elements)";
                    }

                    return result;
                }

                if (intersection.size() > 1) {
                    result.type_name = intersection[0];
                    result.method = "combined_ambiguous";
                    result.confidence = 0.40f;
                    result.note = std::to_string(intersection.size()) + " combined candidates";
                    return result;
                }

                if (!pc_types.empty()) {
                    result.type_name = pc_types[0];
                    result.method = "callsite_ambiguous";
                    result.confidence = 0.40f;
                    result.note = std::to_string(pc_types.size()) + " callsite candidates";
                    return result;
                }
            }
        }

        auto func_names = resolve_function_names_from_pcs(pcs);
        std::vector<std::string> all_ptr_types;
        for (const auto &func_name : func_names) {
            const SubprogramInfo *subprog = analyzer_.find_subprogram_by_name(func_name);
            if (!subprog)
                continue;

            for (const auto &var : subprog->local_variables) {
                if (var.is_pointer && !var.pointer_target_type_name.empty())
                    all_ptr_types.push_back(var.pointer_target_type_name);
            }
        }

        std::sort(all_ptr_types.begin(), all_ptr_types.end());
        all_ptr_types.erase(std::unique(all_ptr_types.begin(), all_ptr_types.end()), all_ptr_types.end());

        if (all_ptr_types.size() == 1) {
            result.type_name = all_ptr_types[0];
            result.method = "callsite_func";
            result.confidence = 0.70f;
        } else if (all_ptr_types.size() > 1) {
            auto size_candidates = get_size_candidates(size);
            std::vector<std::string> intersection;
            for (const auto &c : all_ptr_types) {
                for (const auto &s : size_candidates) {
                    if (c == s) {
                        intersection.push_back(c);
                        break;
                    }
                }
            }

            if (intersection.size() == 1) {
                result.type_name = intersection[0];
                result.method = "callsite_func+size";
                result.confidence = 0.75f;
            } else if (intersection.size() > 1) {
                result.type_name = intersection[0];
                result.method = "callsite_func_ambiguous";
                result.confidence = 0.35f;
                result.note = std::to_string(intersection.size()) + " func+size candidates";
            } else {
                result.type_name = all_ptr_types[0];
                result.method = "callsite_func_ambiguous";
                result.confidence = 0.30f;
                result.note = std::to_string(all_ptr_types.size()) + " func ptr candidates";
            }
        }

        if (!result.type_name.empty() && result.type_name.find("ambiguous") == std::string::npos) {
            const TypeInfo *ti = analyzer_.find_type_by_name(result.type_name);
            if (ti && ti->byte_size > 0 && size % ti->byte_size == 0) {
                result.alloc_count = size / ti->byte_size;
                if (result.alloc_count > 1)
                    result.note = "array allocation (" +
                                  std::to_string(result.alloc_count) + " elements)";
            }
            return result;
        }
    }

    auto size_candidates = get_size_candidates(size);
    if (size_candidates.size() == 1) {
        result.type_name = size_candidates[0];
        result.method = "size_match";
        result.confidence = 0.60f;
        result.alloc_count = 1;
        return result;
    }

    if (size_candidates.size() > 1) {
        result.type_name = size_candidates[0];
        result.method = "size_ambiguous";
        result.confidence = 0.20f;
        result.note = std::to_string(size_candidates.size()) + " size candidates";
        return result;
    }

    auto array_result = try_array_size_match(size);
    if (!array_result.type_name.empty())
        return array_result;

    result.method = "unknown";
    result.confidence = 0.0f;
    return result;
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

    TypeInferenceResult type_result = infer_type_combined_v2(alloc->stack_id, alloc->size, alloc->stack_pcs);
    result.type_name = type_result.type_name;
    result.allocation_callsite = type_result.method + " (confidence=" +
                                  std::to_string(type_result.confidence).substr(0, 4) + ")" +
                                  (type_result.note.empty() ? "" : " " + type_result.note);

    if (!type_result.type_name.empty()) {
        const TypeInfo *ti = analyzer_.find_type_by_name(type_result.type_name);

        if (type_result.alloc_count > 1 && ti && ti->byte_size > 0) {
            uint64_t elem_size = ti->byte_size;
            uint64_t elem_index = offset / elem_size;
            uint64_t elem_offset = offset % elem_size;

            auto field = analyzer_.resolve_field_at_offset(type_result.type_name, elem_offset);
            if (field) {
                ResolvedField rf = {};
                rf.type_name = type_result.type_name;
                rf.field_name = field->name;
                rf.full_path = type_result.type_name + "[" +
                               std::to_string(elem_index) + "]." + field->name;
                rf.field_byte_offset = offset;
                rf.field_byte_size = field->byte_size;
                rf.base_address = alloc->addr;
                rf.resolved_address = address;
                rf.field_type_name = field->type_name;
                rf.is_bitfield = field->is_bitfield;
                result.fields.push_back(rf);
            }
        } else {
            auto field = analyzer_.resolve_field_at_offset(type_result.type_name, offset);
            if (field) {
                ResolvedField rf = {};
                rf.type_name = type_result.type_name;
                rf.field_name = field->name;
                rf.full_path = type_result.type_name + "." + field->name;
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

    const SubprogramInfo *subprog = analyzer_.find_subprogram_by_name(sym->name);
    if (subprog) {
        auto stack_vars = analyzer_.find_stack_variables(subprog->low_pc);
        for (const auto &var : stack_vars) {
            ResolvedField rf = {};
            rf.type_name = var.type_name;
            rf.field_name = var.name;
            rf.full_path = var.type_name + "." + var.name;
            rf.field_byte_offset = (uint64_t)var.stack_offset;
            rf.field_byte_size = var.byte_size;
            result.fields.push_back(rf);
        }
    }

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
    const SubprogramInfo *subprog = analyzer_.find_subprogram_by_name(func_name);
    if (!subprog)
        return std::nullopt;

    auto stack_vars = analyzer_.find_stack_variables(subprog->low_pc);

    for (const auto &var : stack_vars) {
        if (stack_offset >= var.stack_offset &&
            stack_offset < var.stack_offset + (int64_t)var.byte_size) {
            ResolvedField rf = {};
            rf.type_name = var.type_name;
            rf.field_name = var.name;
            rf.full_path = var.type_name + "." + var.name;
            rf.field_byte_offset = (uint64_t)var.stack_offset;
            rf.field_byte_size = var.byte_size;
            rf.base_address = frame_base;
            rf.resolved_address = frame_base + stack_offset;
            return rf;
        }
    }
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

        auto src_line = analyzer_.resolve_source_line(pc);
        if (src_line) {
            frame.source_file = src_line->first;
            frame.source_line = src_line->second;
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
