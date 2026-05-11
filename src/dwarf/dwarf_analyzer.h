#ifndef DWARF_ANALYZER_H
#define DWARF_ANALYZER_H

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <elf.h>
#include <dwarf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

namespace memscope {

class ScopedFd {
public:
    explicit ScopedFd(int fd = -1) : fd_(fd) {}
    ~ScopedFd() { if (fd_ >= 0) close(fd_); }

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    ScopedFd(ScopedFd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) close(fd_);
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    int get() const { return fd_; }
    int release() { int fd = fd_; fd_ = -1; return fd; }
    bool valid() const { return fd_ >= 0; }

private:
    int fd_;
};

class ScopedMmap {
public:
    ScopedMmap() : ptr_(nullptr), size_(0) {}
    ScopedMmap(void* ptr, size_t size) : ptr_(ptr), size_(size) {}
    ~ScopedMmap() { if (ptr_ && ptr_ != MAP_FAILED) munmap(ptr_, size_); }

    ScopedMmap(const ScopedMmap&) = delete;
    ScopedMmap& operator=(const ScopedMmap&) = delete;

    ScopedMmap(ScopedMmap&& other) noexcept
        : ptr_(other.ptr_), size_(other.size_) {
        other.ptr_ = nullptr;
        other.size_ = 0;
    }
    ScopedMmap& operator=(ScopedMmap&& other) noexcept {
        if (this != &other) {
            if (ptr_ && ptr_ != MAP_FAILED) munmap(ptr_, size_);
            ptr_ = other.ptr_;
            size_ = other.size_;
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    void* get() const { return ptr_; }
    size_t size() const { return size_; }
    void release() { ptr_ = nullptr; size_ = 0; }
    bool valid() const { return ptr_ != nullptr && ptr_ != MAP_FAILED; }

private:
    void*  ptr_;
    size_t size_;
};

class ScopedElf {
public:
    explicit ScopedElf(Elf* elf = nullptr) : elf_(elf) {}
    ~ScopedElf() { if (elf_) elf_end(elf_); }

    ScopedElf(const ScopedElf&) = delete;
    ScopedElf& operator=(const ScopedElf&) = delete;

    ScopedElf(ScopedElf&& other) noexcept : elf_(other.elf_) { other.elf_ = nullptr; }
    ScopedElf& operator=(ScopedElf&& other) noexcept {
        if (this != &other) {
            if (elf_) elf_end(elf_);
            elf_ = other.elf_;
            other.elf_ = nullptr;
        }
        return *this;
    }

    Elf* get() const { return elf_; }
    Elf* release() { Elf* e = elf_; elf_ = nullptr; return e; }
    bool valid() const { return elf_ != nullptr; }

private:
    Elf* elf_;
};

class ScopedDwarf {
public:
    explicit ScopedDwarf(Dwarf* dwarf = nullptr) : dwarf_(dwarf) {}
    ~ScopedDwarf() { if (dwarf_) dwarf_end(dwarf_); }

    ScopedDwarf(const ScopedDwarf&) = delete;
    ScopedDwarf& operator=(const ScopedDwarf&) = delete;

    ScopedDwarf(ScopedDwarf&& other) noexcept : dwarf_(other.dwarf_) { other.dwarf_ = nullptr; }
    ScopedDwarf& operator=(ScopedDwarf&& other) noexcept {
        if (this != &other) {
            if (dwarf_) dwarf_end(dwarf_);
            dwarf_ = other.dwarf_;
            other.dwarf_ = nullptr;
        }
        return *this;
    }

    Dwarf* get() const { return dwarf_; }
    Dwarf* release() { Dwarf* d = dwarf_; dwarf_ = nullptr; return d; }
    bool valid() const { return dwarf_ != nullptr; }

private:
    Dwarf* dwarf_;
};

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

struct LocalVariableInfo {
    std::string name;
    std::string type_name;
    uint64_t    type_die_offset;
    bool        is_pointer;
    uint64_t    pointer_target_type_offset;
    std::string pointer_target_type_name;
};

struct SubprogramInfo {
    std::string name;
    std::string linkage_name;
    uint64_t    low_pc;
    uint64_t    high_pc;
    bool        high_pc_is_offset;
    uint64_t    die_offset;
    std::vector<LocationEntry> frame_base;
    std::string source_file;
    uint32_t    source_line;
    std::vector<LocalVariableInfo> local_variables;
};

struct StackVariableInfo {
    std::string name;
    std::string type_name;
    int64_t     stack_offset;
    uint64_t    byte_size;
};

class DwarfAnalyzer {
public:
    explicit DwarfAnalyzer();
    ~DwarfAnalyzer();

    DwarfAnalyzer(const DwarfAnalyzer&) = delete;
    DwarfAnalyzer& operator=(const DwarfAnalyzer&) = delete;

    DwarfAnalyzer(DwarfAnalyzer&&) = default;
    DwarfAnalyzer& operator=(DwarfAnalyzer&&) = default;

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

    const SubprogramInfo *find_subprogram_by_name(const std::string &name) const;
    std::vector<StackVariableInfo> find_stack_variables(uint64_t pc) const;
    std::vector<std::string> find_pointer_target_types_at_pc(uint64_t pc) const;

    std::optional<FieldInfo> resolve_field_at_offset(const std::string &type_name,
                                                      uint64_t byte_offset) const;
    std::optional<FieldInfo> resolve_field_at_offset(uint64_t type_die_offset,
                                                      uint64_t byte_offset) const;

    std::optional<std::pair<std::string, uint32_t>> resolve_source_line(uint64_t pc) const;

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

    ScopedFd       elf_fd_;
    ScopedMmap     elf_mmap_;
    ScopedElf      elf_ptr_;
    ScopedDwarf    dwarf_ptr_;

    std::vector<TypeInfo>       types_;
    std::vector<SymbolInfo>     symbols_;
    std::vector<CIERecord>      cie_records_;
    std::vector<FDERecord>      fde_records_;
    std::vector<SubprogramInfo> subprograms_;

    std::unordered_map<std::string, size_t>    type_name_index_;
    std::unordered_map<uint64_t, size_t>       type_offset_index_;
    std::unordered_map<std::string, size_t>    symbol_name_index_;
    std::unordered_map<uint64_t, size_t>       symbol_addr_index_;
    std::unordered_map<std::string, size_t>    subprogram_name_index_;

    std::unordered_map<uint64_t, std::string>  file_table_;
};

}

#endif
