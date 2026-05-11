#ifndef ADDRESS_RESOLVER_H
#define ADDRESS_RESOLVER_H

#include <stdint.h>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <unordered_map>
#include "dwarf_analyzer.h"
#include "source_code_analyzer.h"

namespace memscope {

struct ResolvedField {
    std::string type_name;
    std::string field_name;
    std::string full_path;
    uint64_t    field_byte_offset;
    uint64_t    field_byte_size;
    uint64_t    base_address;
    uint64_t    resolved_address;
    std::string field_type_name;
    bool        is_bitfield;
    uint64_t    bit_offset_within_field;
    std::string source_file;
    uint32_t    source_line;
};

struct ResolvedStackFrame {
    uint64_t    pc;
    std::string function_name;
    std::string source_file;
    uint32_t    source_line;
    int64_t     offset_within_func;
};

struct ResolvedAddress {
    enum AddrClass {
        ADDR_GLOBAL,
        ADDR_STACK,
        ADDR_HEAP,
        ADDR_UNKNOWN
    } addr_class;

    uint64_t address;
    std::string symbol_name;
    std::string type_name;
    std::vector<ResolvedField>  fields;
    std::vector<ResolvedStackFrame> stack_trace;
    std::string allocation_callsite;
    uint64_t    allocation_size;
    uint32_t    pid;
    uint32_t    tid;
};

struct AllocInfo {
    uint64_t addr;
    uint64_t size;
    int64_t  stack_id;
    uint64_t timestamp;
    uint32_t pid;
    uint32_t tid;
    int      live;
    int      stack_depth;
    std::vector<uint64_t> stack_pcs;
};

struct TypeInferenceResult {
    std::string type_name;
    uint64_t    alloc_count;
    std::string method;
    float       confidence;
    std::string note;
};

class AddressResolver {
public:
    explicit AddressResolver();
    ~AddressResolver();

    int load_binary(const std::string &path);
    void set_alloc_table(const std::vector<AllocInfo> &allocs);
    void set_stack_map_fd(int fd);
    void set_debug_log(const std::string &path);

    std::optional<ResolvedAddress> resolve(uint64_t address,
                                            uint32_t pid = 0,
                                            const std::vector<uint64_t> &stack_frames = {}) const;

    std::optional<ResolvedField> resolve_heap_field(uint64_t base_addr,
                                                     uint64_t offset) const;

    std::optional<ResolvedField> resolve_global_field(const std::string &symbol_name,
                                                       uint64_t offset) const;

    std::optional<ResolvedField> resolve_stack_field(uint64_t frame_base,
                                                      int64_t stack_offset,
                                                      const std::string &func_name) const;

    std::vector<ResolvedStackFrame> resolve_stack_trace(
        const std::vector<uint64_t> &frames) const;

    std::string resolved_to_string(const ResolvedAddress &resolved) const;

    const DwarfAnalyzer &analyzer() const { return analyzer_; }

private:
    void build_size_index();

    std::optional<ResolvedAddress> resolve_global(uint64_t address) const;
    std::optional<ResolvedAddress> resolve_heap(uint64_t address, uint32_t pid) const;
    std::optional<ResolvedAddress> resolve_stack(uint64_t address,
                                                   const std::vector<uint64_t> &frames) const;

    const AllocInfo *find_alloc(uint64_t addr) const;

    std::string infer_type_from_callsite(int64_t stack_id) const;
    std::string infer_type_from_size(uint64_t size) const;
    std::string infer_type_combined(int64_t stack_id, uint64_t size) const;
    TypeInferenceResult infer_type_combined_v2(int64_t stack_id, uint64_t size,
                                                const std::vector<uint64_t> &inline_pcs = {}) const;
    TypeInferenceResult infer_type_from_source_text(uint64_t pc) const;
    TypeInferenceResult try_array_size_match(uint64_t size) const;
    std::vector<std::string> get_size_candidates(uint64_t size) const;

    std::vector<std::string> resolve_stack_function_names(int64_t stack_id) const;
    std::vector<std::string> resolve_function_names_from_pcs(const std::vector<uint64_t> &pcs) const;
    std::vector<uint64_t> resolve_stack_pcs(int64_t stack_id) const;
    uint64_t va_to_file_offset(uint64_t va) const;
    int64_t compute_aslr_offset(const std::vector<uint64_t> &runtime_pcs) const;

    DwarfAnalyzer analyzer_;
    SourceCodeAnalyzer source_analyzer_;
    std::vector<AllocInfo> allocs_;
    std::string binary_path_;

    std::unordered_map<uint64_t, std::vector<size_t>> size_index_;
    int stack_map_fd_;
    int64_t aslr_offset_;
};

}

#endif
