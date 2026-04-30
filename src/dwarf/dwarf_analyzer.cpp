#include "dwarf_analyzer.h"
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <elf.h>
#include <dwarf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstdio>

namespace memscope {

DwarfAnalyzer::DwarfAnalyzer()
    : loaded_(false)
    , elf_ptr_(nullptr)
    , dwarf_ptr_(nullptr)
    , elf_fd_(-1)
    , elf_data_(nullptr)
    , elf_size_(0)
{
}

DwarfAnalyzer::~DwarfAnalyzer()
{
    if (elf_data_ && elf_size_) {
        munmap(elf_data_, elf_size_);
    }
    if (elf_fd_ >= 0) {
        close(elf_fd_);
    }
    if (dwarf_ptr_) {
        dwarf_end((Dwarf *)dwarf_ptr_);
    }
    if (elf_ptr_) {
        elf_end((Elf *)elf_ptr_);
    }
}

int DwarfAnalyzer::load_binary(const std::string &path)
{
    binary_path_ = path;

    elf_version(EV_CURRENT);

    elf_fd_ = open(path.c_str(), O_RDONLY);
    if (elf_fd_ < 0) {
        fprintf(stderr, "cannot open %s: %s\n", path.c_str(), strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(elf_fd_, &st) < 0) {
        fprintf(stderr, "cannot stat %s: %s\n", path.c_str(), strerror(errno));
        return -1;
    }
    elf_size_ = st.st_size;

    elf_data_ = (uint8_t *)mmap(nullptr, elf_size_, PROT_READ, MAP_PRIVATE, elf_fd_, 0);
    if (elf_data_ == MAP_FAILED) {
        fprintf(stderr, "cannot mmap %s: %s\n", path.c_str(), strerror(errno));
        elf_data_ = nullptr;
        return -1;
    }

    elf_ptr_ = elf_begin(elf_fd_, ELF_C_READ_MMAP, nullptr);
    if (!elf_ptr_) {
        fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
        return -1;
    }

    if (elf_kind((Elf *)elf_ptr_) != ELF_K_ELF) {
        fprintf(stderr, "%s is not an ELF file\n", path.c_str());
        return -1;
    }

    dwarf_ptr_ = dwarf_begin_elf((Elf *)elf_ptr_, DWARF_C_READ, nullptr);
    if (!dwarf_ptr_) {
        fprintf(stderr, "no DWARF info in %s, falling back to symbol table\n", path.c_str());
    }

    int rc = 0;
    rc |= parse_symbol_table();
    rc |= parse_dwarf_info();
    rc |= parse_dwarf_frames();

    loaded_ = true;
    return rc;
}

int DwarfAnalyzer::parse_symbol_table()
{
    Elf *elf = (Elf *)elf_ptr_;
    Elf_Scn *scn = nullptr;
    GElf_Shdr shdr;

    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) < 0)
        return -1;

    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            continue;

        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
            continue;

        Elf_Data *data = elf_getdata(scn, nullptr);
        if (!data)
            continue;

        size_t sym_count = shdr.sh_size / shdr.sh_entsize;
        for (size_t i = 0; i < sym_count; i++) {
            GElf_Sym sym;
            if (gelf_getsym(data, (int)i, &sym) != &sym)
                continue;

            if (sym.st_value == 0 || sym.st_name == 0)
                continue;

            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || name[0] == '\0')
                continue;

            SymbolInfo info = {};
            info.name = name;
            info.address = sym.st_value;
            info.size = sym.st_size;

            switch (GELF_ST_BIND(sym.st_info)) {
            case STB_LOCAL:  info.binding = SymbolInfo::BIND_LOCAL;  break;
            case STB_GLOBAL: info.binding = SymbolInfo::BIND_GLOBAL; break;
            case STB_WEAK:   info.binding = SymbolInfo::BIND_WEAK;   break;
            default:         info.binding = SymbolInfo::BIND_LOCAL;   break;
            }

            switch (GELF_ST_TYPE(sym.st_info)) {
            case STT_FUNC:   info.sym_type = SymbolInfo::SYM_FUNC;   break;
            case STT_OBJECT: info.sym_type = SymbolInfo::SYM_OBJECT; break;
            default:         info.sym_type = SymbolInfo::SYM_UNKNOWN; break;
            }

            size_t idx = symbols_.size();
            symbols_.push_back(info);
            symbol_name_index_[info.name] = idx;
            symbol_addr_index_[info.address] = idx;
        }
    }

    std::sort(symbols_.begin(), symbols_.end(),
              [](const SymbolInfo &a, const SymbolInfo &b) {
                  return a.address < b.address;
              });

    for (size_t i = 0; i < symbols_.size(); i++)
        symbol_addr_index_[symbols_[i].address] = i;

    return 0;
}

TypeInfo::Tag DwarfAnalyzer::map_tag(uint64_t dwarf_tag)
{
    switch (dwarf_tag) {
    case DW_TAG_structure_type:      return TypeInfo::TAG_STRUCT;
    case DW_TAG_union_type:          return TypeInfo::TAG_UNION;
    case DW_TAG_enumeration_type:    return TypeInfo::TAG_ENUM;
    case DW_TAG_typedef:             return TypeInfo::TAG_TYPEDEF;
    case DW_TAG_base_type:           return TypeInfo::TAG_BASE_TYPE;
    case DW_TAG_pointer_type:        return TypeInfo::TAG_POINTER;
    case DW_TAG_array_type:          return TypeInfo::TAG_ARRAY;
    case DW_TAG_subroutine_type:     return TypeInfo::TAG_FUNCTION;
    default:                         return TypeInfo::TAG_UNKNOWN;
    }
}

int DwarfAnalyzer::parse_dwarf_info()
{
    Dwarf *dbg = (Dwarf *)dwarf_ptr_;
    if (!dbg)
        return -1;

    Dwarf_Off off = 0;
    Dwarf_Off next_off;
    size_t    cu_hdr_size;

    while (dwarf_nextcu(dbg, off, &next_off, &cu_hdr_size, nullptr, nullptr, nullptr) == 0) {
        Dwarf_Die die;
        if (dwarf_offdie(dbg, off + cu_hdr_size, &die) == nullptr)
            break;

        Dwarf_Die child;
        if (dwarf_child(&die, &child) == 0) {
            do {
                process_die(&child, 1);
            } while (dwarf_siblingof(&child, &child) == 0);
        }

        off = next_off;
    }

    return 0;
}

void DwarfAnalyzer::process_die(void *die_v, int depth)
{
    Dwarf_Die *die = (Dwarf_Die *)die_v;
    int tag = dwarf_tag(die);

    switch (tag) {
    case DW_TAG_structure_type:
    case DW_TAG_union_type:
    case DW_TAG_enumeration_type:
    case DW_TAG_typedef:
    case DW_TAG_base_type:
        process_type_die(die);
        break;
    case DW_TAG_subprogram:
        process_subprogram_die(die);
        break;
    case DW_TAG_variable:
        process_variable_die(die);
        break;
    default:
        break;
    }

    Dwarf_Die child;
    if (dwarf_child(die, &child) == 0) {
        do {
            process_die(&child, depth + 1);
        } while (dwarf_siblingof(&child, &child) == 0);
    }
}

void DwarfAnalyzer::process_type_die(void *die_v)
{
    Dwarf_Die *die = (Dwarf_Die *)die_v;

    const char *name = dwarf_diename(die);
    if (!name)
        return;

    TypeInfo info = {};
    info.die_offset = dwarf_dieoffset(die);
    info.name = name;
    info.tag = map_tag(dwarf_tag(die));

    Dwarf_Attribute attr;
    if (dwarf_attr(die, DW_AT_byte_size, &attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&attr, &val) == 0)
            info.byte_size = val;
    }

    if (dwarf_attr(die, DW_AT_alignment, &attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&attr, &val) == 0)
            info.alignment = val;
    }

    Dwarf_Die child;
    if (dwarf_child(die, &child) == 0) {
        do {
            int child_tag = dwarf_tag(&child);
            if (child_tag == DW_TAG_member) {
                process_member_die(&child, info);
            }
        } while (dwarf_siblingof(&child, &child) == 0);
    }

    Dwarf_Attribute decl_file_attr;
    if (dwarf_attr(die, DW_AT_decl_file, &decl_file_attr)) {
        Dwarf_Word file_idx;
        if (dwarf_formudata(&decl_file_attr, &file_idx) == 0) {
            auto it = file_table_.find(file_idx);
            if (it != file_table_.end())
                info.source_file = it->second;
        }
    }

    Dwarf_Attribute decl_line_attr;
    if (dwarf_attr(die, DW_AT_decl_line, &decl_line_attr)) {
        Dwarf_Word line;
        if (dwarf_formudata(&decl_line_attr, &line) == 0)
            info.source_line = (uint32_t)line;
    }

    size_t idx = types_.size();
    types_.push_back(info);
    type_name_index_[info.name] = idx;
    type_offset_index_[info.die_offset] = idx;
}

void DwarfAnalyzer::process_member_die(void *die_v, TypeInfo &parent)
{
    Dwarf_Die *die = (Dwarf_Die *)die_v;

    const char *name = dwarf_diename(die);
    if (!name)
        return;

    FieldInfo field = {};
    field.name = name;
    field.full_qualified_name = parent.name + "::" + name;

    Dwarf_Attribute attr;
    if (dwarf_attr(die, DW_AT_data_member_location, &attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&attr, &val) == 0) {
            field.byte_offset = val;
            field.bit_offset = val * 8;
        }
    }

    if (dwarf_attr(die, DW_AT_data_bit_offset, &attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&attr, &val) == 0) {
            field.bit_offset = val;
            field.byte_offset = val / 8;
        }
    }

    if (dwarf_attr(die, DW_AT_byte_size, &attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&attr, &val) == 0)
            field.byte_size = val;
    }

    if (dwarf_attr(die, DW_AT_bit_size, &attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&attr, &val) == 0) {
            field.bit_size = val;
            field.is_bitfield = true;
        }
    }

    Dwarf_Attribute type_attr;
    if (dwarf_attr(die, DW_AT_type, &type_attr)) {
        Dwarf_Die type_die;
        if (dwarf_formref_die(&type_attr, &type_die)) {
            const char *type_name = dwarf_diename(&type_die);
            if (type_name)
                field.type_name = type_name;

            int type_tag = dwarf_tag(&type_die);
            field.is_pointer = (type_tag == DW_TAG_pointer_type);
            field.is_array = (type_tag == DW_TAG_array_type);

            if (field.byte_size == 0) {
                Dwarf_Word type_size = 0;
                if (dwarf_aggregate_size(&type_die, &type_size) == 0 && type_size > 0)
                    field.byte_size = type_size;
            }
        }
    }

    parent.fields.push_back(field);
}

void DwarfAnalyzer::process_subprogram_die(void *die_v)
{
    Dwarf_Die *die = (Dwarf_Die *)die_v;

    SubprogramInfo info = {};

    const char *name = dwarf_diename(die);
    if (name)
        info.name = name;

    Dwarf_Attribute attr;
    if (dwarf_attr(die, DW_AT_linkage_name, &attr)) {
        const char *linkage = dwarf_formstring(&attr);
        if (linkage)
            info.linkage_name = linkage;
    }

    if (dwarf_attr(die, DW_AT_low_pc, &attr)) {
        Dwarf_Addr addr;
        if (dwarf_formaddr(&attr, &addr) == 0)
            info.low_pc = addr;
    }

    if (dwarf_attr(die, DW_AT_high_pc, &attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&attr, &val) == 0) {
            info.high_pc = val;
            info.high_pc_is_offset = true;
        } else {
            Dwarf_Addr addr;
            if (dwarf_formaddr(&attr, &addr) == 0) {
                info.high_pc = addr;
                info.high_pc_is_offset = false;
            }
        }
    }

    if (dwarf_attr(die, DW_AT_decl_file, &attr)) {
        Dwarf_Word file_idx;
        if (dwarf_formudata(&attr, &file_idx) == 0) {
            auto it = file_table_.find(file_idx);
            if (it != file_table_.end())
                info.source_file = it->second;
        }
    }

    if (dwarf_attr(die, DW_AT_decl_line, &attr)) {
        Dwarf_Word line;
        if (dwarf_formudata(&attr, &line) == 0)
            info.source_line = (uint32_t)line;
    }

    subprograms_.push_back(info);
}

void DwarfAnalyzer::process_variable_die(void *die_v)
{
    Dwarf_Die *die = (Dwarf_Die *)die_v;

    const char *name = dwarf_diename(die);
    if (!name)
        return;

    Dwarf_Attribute attr;
    if (!dwarf_attr(die, DW_AT_location, &attr))
        return;

    Dwarf_Addr addr = 0;
    Dwarf_Op *ops = nullptr;
    size_t ops_len = 0;
    if (dwarf_getlocation(&attr, &ops, &ops_len) == 0 && ops_len == 1) {
        if (ops[0].atom == DW_OP_addr) {
            addr = ops[0].number;
        }
    }

    if (addr == 0)
        return;

    SymbolInfo sym = {};
    sym.name = name;
    sym.address = addr;
    sym.sym_type = SymbolInfo::SYM_OBJECT;
    sym.binding = SymbolInfo::BIND_GLOBAL;

    Dwarf_Attribute type_attr;
    if (dwarf_attr(die, DW_AT_type, &type_attr)) {
        Dwarf_Die type_die;
        if (dwarf_formref_die(&type_attr, &type_die)) {
            const char *type_name = dwarf_diename(&type_die);
            if (type_name)
                sym.type_name = type_name;
            sym.type_die_offset = dwarf_dieoffset(&type_die);
        }
    }

    Dwarf_Attribute size_attr;
    if (dwarf_attr(die, DW_AT_byte_size, &size_attr)) {
        Dwarf_Word val;
        if (dwarf_formudata(&size_attr, &val) == 0)
            sym.size = val;
    }

    size_t idx = symbols_.size();
    symbols_.push_back(sym);
    symbol_name_index_[sym.name] = idx;
    symbol_addr_index_[sym.address] = idx;
}

int DwarfAnalyzer::parse_dwarf_frames()
{
    return 0;
}

int DwarfAnalyzer::parse_dwarf_abbrev()
{
    return 0;
}

int DwarfAnalyzer::parse_dwarf_types()
{
    return 0;
}

int DwarfAnalyzer::parse_dwarf_line()
{
    return 0;
}

int DwarfAnalyzer::parse_elf_headers()
{
    return 0;
}

const TypeInfo *DwarfAnalyzer::find_type_by_name(const std::string &name) const
{
    auto it = type_name_index_.find(name);
    if (it != type_name_index_.end())
        return &types_[it->second];
    return nullptr;
}

const TypeInfo *DwarfAnalyzer::find_type_by_offset(uint64_t offset) const
{
    auto it = type_offset_index_.find(offset);
    if (it != type_offset_index_.end())
        return &types_[it->second];
    return nullptr;
}

const SymbolInfo *DwarfAnalyzer::find_symbol_by_addr(uint64_t addr) const
{
    if (symbols_.empty())
        return nullptr;

    auto it = symbol_addr_index_.find(addr);
    if (it != symbol_addr_index_.end())
        return &symbols_[it->second];

    auto cmp = [](uint64_t v, const SymbolInfo &a) { return v < a.address; };
    auto ub = std::upper_bound(symbols_.begin(), symbols_.end(), addr, cmp);
    if (ub == symbols_.begin())
        return nullptr;

    --ub;
    if (addr >= ub->address && addr < ub->address + ub->size)
        return &(*ub);

    return nullptr;
}

const SymbolInfo *DwarfAnalyzer::find_symbol_by_name(const std::string &name) const
{
    auto it = symbol_name_index_.find(name);
    if (it != symbol_name_index_.end())
        return &symbols_[it->second];
    return nullptr;
}

std::optional<FieldInfo> DwarfAnalyzer::resolve_field_at_offset(
    const std::string &type_name, uint64_t byte_offset) const
{
    const TypeInfo *type = find_type_by_name(type_name);
    if (!type)
        return std::nullopt;
    return resolve_field_at_offset(type->die_offset, byte_offset);
}

std::optional<FieldInfo> DwarfAnalyzer::resolve_field_at_offset(
    uint64_t type_die_offset, uint64_t byte_offset) const
{
    const TypeInfo *type = find_type_by_offset(type_die_offset);
    if (!type)
        return std::nullopt;

    const FieldInfo *best = nullptr;
    uint64_t best_distance = UINT64_MAX;

    for (const auto &field : type->fields) {
        if (byte_offset == field.byte_offset) {
            if (!best || field.byte_size > best->byte_size) {
                best = &field;
                best_distance = 0;
            }
        }

        if (field.byte_size > 0 &&
            byte_offset >= field.byte_offset &&
            byte_offset < field.byte_offset + field.byte_size) {
            uint64_t dist = byte_offset - field.byte_offset;
            if (dist < best_distance) {
                best_distance = dist;
                best = &field;
            }
        }
    }

    if (best)
        return *best;
    return std::nullopt;
}

std::string DwarfAnalyzer::type_layout_to_string(const std::string &type_name) const
{
    const TypeInfo *type = find_type_by_name(type_name);
    if (!type)
        return "type not found: " + type_name;

    std::ostringstream oss;
    oss << "struct " << type->name << " (size=" << type->byte_size << ", align="
        << type->alignment << ")\n";
    oss << "  Offset  Size  Type            Name\n";
    oss << "  ------  ----  ----            ----\n";

    for (const auto &f : type->fields) {
        oss << "  " << std::setw(6) << f.byte_offset
            << "  " << std::setw(4) << f.byte_size
            << "  " << std::setw(15) << (f.type_name.empty() ? "?" : f.type_name)
            << "  " << f.name;
        if (f.is_bitfield)
            oss << " (bitfield: bit_offset=" << f.bit_offset
                << ", bit_size=" << f.bit_size << ")";
        if (f.is_pointer)
            oss << " *";
        if (f.is_array)
            oss << "[" << f.array_element_count << "]";
        oss << "\n";
    }

    uint64_t total = 0;
    for (const auto &f : type->fields)
        total = std::max(total, f.byte_offset + f.byte_size);

    if (total < type->byte_size) {
        oss << "  " << std::setw(6) << total
            << "  " << std::setw(4) << (type->byte_size - total)
            << "  " << std::setw(15) << "<padding>"
            << "  <tail padding>\n";
    }

    return oss.str();
}

int64_t DwarfAnalyzer::unwind_frame(uint64_t pc, uint64_t *regs, int reg_count) const
{
    (void)regs;
    (void)reg_count;

    const FDERecord *fde = nullptr;
    for (const auto &f : fde_records_) {
        if (pc >= f.initial_location && pc < f.initial_location + f.address_range) {
            fde = &f;
            break;
        }
    }
    if (!fde)
        return -1;

    return 0;
}

}
