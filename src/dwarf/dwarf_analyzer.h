#ifndef DWARF_ANALYZER_H
#define DWARF_ANALYZER_H

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

namespace memscope {

struct FieldInfo {
    std::string name;
    uint64_t    bit_offset;
    uint64_t    bit_size;
    uint64_t    byte_offset;
    uint64_t    byte_size;
    bool        is_bitfield;
    std::string type_name;
    bool        is_pointer;
    bool        is_array;
    uint64_t    array_element_count;
    std::string full_qualified_name;
};

struct TypeInfo {
    uint64_t              die_offset;
    std::string           name;
    std::string           linkage_name;
    uint64_t              byte_size;
    uint64_t              alignment;
    enum Tag {
        TAG_STRUCT,
        TAG_UNION,
        TAG_ENUM,
        TAG_TYPEDEF,
        TAG_BASE_TYPE,
        TAG_POINTER,
        TAG_ARRAY,
        TAG_FUNCTION,
        TAG_UNKNOWN
    } tag;
    std::vector<FieldInfo> fields;
    std::string            source_file;
    uint32_t               source_line;
};

struct SymbolInfo {
    std::string  name;
    uint64_t     address;
    uint64_t     size;
    std::string  type_name;
    uint64_t     type_die_offset;
    enum Binding {
        BIND_LOCAL,
        BIND_GLOBAL,
        BIND_WEAK
    } binding;
    enum SymType {
        SYM_FUNC,
        SYM_OBJECT,
        SYM_UNKNOWN
    } sym_type;
};

struct CIERecord {
    uint64_t  cie_offset;
    uint32_t  version;
    uint8_t   address_size;
    uint8_t   segment_size;
    uint64_t  code_alignment_factor;
    int64_t   data_alignment_factor;
    uint64_t  return_address_register;
    std::vector<uint8_t> initial_instructions;
    std::string           augmentation;
};

struct FDERecord {
    uint64_t  fde_offset;
    uint64_t  cie_pointer;
    uint64_t  initial_location;
    uint64_t  address_range;
    std::vector<uint8_t> instructions;
    const CIERecord *cie;
};

struct LocationEntry {
    uint64_t begin;
    uint64_t end;
    int      reg;
    int64_t  offset;
    bool     is_cfa;
};

struct SubprogramInfo {
    std::string name;
    std::string linkage_name;
    uint64_t    low_pc;
    uint64_t    high_pc;
    bool        high_pc_is_offset;
    std::vector<LocationEntry> frame_base;
    std::string source_file;
    uint32_t    source_line;
};

class DwarfAnalyzer {
public:
    explicit DwarfAnalyzer();
    ~DwarfAnalyzer();

    int load_binary(const std::string &path);

    const TypeInfo *find_type_by_name(const std::string &name) const;
    const TypeInfo *find_type_by_offset(uint64_t offset) const;
    const SymbolInfo *find_symbol_by_addr(uint64_t addr) const;
    const SymbolInfo *find_symbol_by_name(const std::string &name) const;

    const std::vector<TypeInfo> &get_all_types() const { return types_; }
    const std::vector<SymbolInfo> &get_all_symbols() const { return symbols_; }
    const std::vector<FDERecord> &get_fde_records() const { return fde_records_; }
    const std::vector<CIERecord> &get_cie_records() const { return cie_records_; }
    const std::vector<SubprogramInfo> &get_subprograms() const { return subprograms_; }

    std::optional<FieldInfo> resolve_field_at_offset(const std::string &type_name,
                                                      uint64_t byte_offset) const;
    std::optional<FieldInfo> resolve_field_at_offset(uint64_t type_die_offset,
                                                      uint64_t byte_offset) const;

    std::string type_layout_to_string(const std::string &type_name) const;

    int64_t unwind_frame(uint64_t pc, uint64_t *regs, int reg_count) const;

    const std::string &binary_path() const { return binary_path_; }
    bool is_loaded() const { return loaded_; }

private:
    int parse_elf_headers();
    int parse_dwarf_info();
    int parse_dwarf_abbrev();
    int parse_dwarf_types();
    int parse_dwarf_symbols();
    int parse_dwarf_frames();
    int parse_dwarf_line();
    int parse_symbol_table();

    void process_die(void *die, int depth);
    void process_type_die(void *die);
    void process_subprogram_die(void *die);
    void process_variable_die(void *die);
    void process_member_die(void *die, TypeInfo &parent);

    TypeInfo::Tag map_tag(uint64_t dwarf_tag);
    SymbolInfo::Binding map_binding(uint64_t elf_binding);
    SymbolInfo::SymType map_sym_type(uint64_t elf_type);

    std::string binary_path_;
    bool        loaded_;

    void *elf_ptr_;
    void *dwarf_ptr_;
    int   elf_fd_;
    uint8_t *elf_data_;
    size_t   elf_size_;

    std::vector<TypeInfo>       types_;
    std::vector<SymbolInfo>     symbols_;
    std::vector<CIERecord>      cie_records_;
    std::vector<FDERecord>      fde_records_;
    std::vector<SubprogramInfo> subprograms_;

    std::unordered_map<std::string, size_t>    type_name_index_;
    std::unordered_map<uint64_t, size_t>       type_offset_index_;
    std::unordered_map<std::string, size_t>    symbol_name_index_;
    std::unordered_map<uint64_t, size_t>       symbol_addr_index_;

    std::unordered_map<uint64_t, std::string>  file_table_;
};

}

#endif
