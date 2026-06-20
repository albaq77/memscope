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
#include <utility>

namespace memscope {

DwarfAnalyzer::DwarfAnalyzer()
    : loaded_(false)
    , elf_fd_(-1)
    , elf_mmap_()
    , elf_ptr_(nullptr)
    , dwarf_ptr_(nullptr)
{
}

DwarfAnalyzer::~DwarfAnalyzer() = default;

int DwarfAnalyzer::load_binary(const std::string &path)
{
    binary_path_ = path;

    elf_version(EV_CURRENT);

    ScopedFd fd(open(path.c_str(), O_RDONLY));
    if (!fd.valid()) {
        fprintf(stderr, "cannot open %s: %s\n", path.c_str(), strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd.get(), &st) < 0) {
        fprintf(stderr, "cannot stat %s: %s\n", path.c_str(), strerror(errno));
        return -1;
    }
    size_t file_size = st.st_size;

    ScopedMmap mmap_guard(
        mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd.get(), 0),
        file_size
    );
    if (!mmap_guard.valid()) {
        fprintf(stderr, "cannot mmap %s: %s\n", path.c_str(), strerror(errno));
        return -1;
    }

    ScopedElf elf_guard(elf_begin(fd.get(), ELF_C_READ_MMAP, nullptr));
    if (!elf_guard.valid()) {
        fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
        return -1;
    }

    if (elf_kind(elf_guard.get()) != ELF_K_ELF) {
        fprintf(stderr, "%s is not an ELF file\n", path.c_str());
        return -1;
    }

    ScopedDwarf dwarf_guard(dwarf_begin_elf(elf_guard.get(), DWARF_C_READ, nullptr));
    if (!dwarf_guard.valid()) {
        fprintf(stderr, "no DWARF info in %s, falling back to symbol table\n", path.c_str());
    }

    elf_fd_ = std::move(fd);
    elf_mmap_ = std::move(mmap_guard);
    elf_ptr_ = std::move(elf_guard);
    dwarf_ptr_ = std::move(dwarf_guard);

    int rc = 0;
    rc |= parse_symbol_table();
    rc |= parse_dwarf_info();
    parse_dwarf_frames();

    std::sort(symbols_.begin(), symbols_.end(),
              [](const SymbolInfo &a, const SymbolInfo &b) {
                  if (a.address != b.address)
                      return a.address < b.address;
                  return a.type_name.empty() && !b.type_name.empty();
              });

    symbol_addr_index_.clear();
    for (size_t i = 0; i < symbols_.size(); i++)
        symbol_addr_index_[symbols_[i].address] = i;

    loaded_ = true;
    return rc;
}

int DwarfAnalyzer::parse_symbol_table()
{
    Elf *elf = elf_ptr_.get();
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
                  if (a.address != b.address)
                      return a.address < b.address;
                  return a.type_name.empty() && !b.type_name.empty();
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
    Dwarf *dbg = dwarf_ptr_.get();
    if (!dbg)
        return 0;

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
    case DW_TAG_pointer_type:
    case DW_TAG_array_type:
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
    int dwarf_tag_val = dwarf_tag(die);

    // 匿名数组/指针类型允许 name 为空(用 die_offset 作 key)
    bool allow_anonymous = (dwarf_tag_val == DW_TAG_array_type ||
                            dwarf_tag_val == DW_TAG_pointer_type);
    if (!name && !allow_anonymous)
        return;

    TypeInfo info = {};
    info.die_offset = dwarf_dieoffset(die);
    if (name)
        info.name = name;
    info.tag = map_tag(dwarf_tag_val);

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

    // 数组类型:解析元素类型 + 元素数 + 元素大小
    if (dwarf_tag_val == DW_TAG_array_type) {
        Dwarf_Attribute elem_attr;
        if (dwarf_attr(die, DW_AT_type, &elem_attr)) {
            Dwarf_Die elem_die;
            if (dwarf_formref_die(&elem_attr, &elem_die)) {
                info.element_type_offset = dwarf_dieoffset(&elem_die);
                const char *en = dwarf_diename(&elem_die);
                if (en) info.element_type_name = en;
                Dwarf_Word es = 0;
                if (dwarf_aggregate_size(&elem_die, &es) == 0 && es > 0)
                    info.element_byte_size = es;
            }
        }
        // 遍历 subrange 获取 element_count
        Dwarf_Die sub_child;
        if (dwarf_child(die, &sub_child) == 0) {
            do {
                if (dwarf_tag(&sub_child) == DW_TAG_subrange_type) {
                    Dwarf_Attribute ca;
                    if (dwarf_attr(&sub_child, DW_AT_upper_bound, &ca)) {
                        Dwarf_Word ub;
                        if (dwarf_formudata(&ca, &ub) == 0) {
                            info.element_count = ub + 1;
                            break;
                        }
                    }
                    if (dwarf_attr(&sub_child, DW_AT_count, &ca)) {
                        Dwarf_Word cnt;
                        if (dwarf_formudata(&ca, &cnt) == 0) {
                            info.element_count = cnt;
                            break;
                        }
                    }
                }
            } while (dwarf_siblingof(&sub_child, &sub_child) == 0);
        }
    }

    // 指针类型:解析目标类型
    if (dwarf_tag_val == DW_TAG_pointer_type) {
        Dwarf_Attribute tgt_attr;
        if (dwarf_attr(die, DW_AT_type, &tgt_attr)) {
            Dwarf_Die tgt_die;
            if (dwarf_formref_die(&tgt_attr, &tgt_die)) {
                info.pointer_target_type_offset = dwarf_dieoffset(&tgt_die);
                const char *tn = dwarf_diename(&tgt_die);
                if (tn) info.pointer_target_type_name = tn;
            }
        }
    }

    // typedef:解析底层类型
    if (dwarf_tag_val == DW_TAG_typedef) {
        Dwarf_Attribute ut_attr;
        if (dwarf_attr(die, DW_AT_type, &ut_attr)) {
            Dwarf_Die ut_die;
            if (dwarf_formref_die(&ut_attr, &ut_die)) {
                info.underlying_type_offset = dwarf_dieoffset(&ut_die);
                const char *un = dwarf_diename(&ut_die);
                if (un) info.underlying_type_name = un;
            }
        }
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
    if (!info.name.empty())
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
            field.type_die_offset = dwarf_dieoffset(&type_die);
            const char *type_name = dwarf_diename(&type_die);
            if (type_name)
                field.type_name = type_name;

            int type_tag = dwarf_tag(&type_die);
            field.is_pointer = (type_tag == DW_TAG_pointer_type);
            field.is_array = (type_tag == DW_TAG_array_type);

            // 数组字段:解析元素类型 + 元素数 + 元素大小
            if (field.is_array) {
                Dwarf_Attribute elem_attr;
                if (dwarf_attr(&type_die, DW_AT_type, &elem_attr)) {
                    Dwarf_Die elem_die;
                    if (dwarf_formref_die(&elem_attr, &elem_die)) {
                        field.array_element_type_offset = dwarf_dieoffset(&elem_die);
                        const char *en = dwarf_diename(&elem_die);
                        if (en) field.array_element_type_name = en;
                        Dwarf_Word es = 0;
                        if (dwarf_aggregate_size(&elem_die, &es) == 0 && es > 0)
                            field.array_element_byte_size = es;
                    }
                }
                // 解析 subrange 获取 element_count
                Dwarf_Die sub_child;
                if (dwarf_child(&type_die, &sub_child) == 0) {
                    do {
                        if (dwarf_tag(&sub_child) == DW_TAG_subrange_type) {
                            Dwarf_Attribute ca;
                            if (dwarf_attr(&sub_child, DW_AT_upper_bound, &ca)) {
                                Dwarf_Word ub;
                                if (dwarf_formudata(&ca, &ub) == 0) {
                                    field.array_element_count = ub + 1;
                                    break;
                                }
                            }
                            if (dwarf_attr(&sub_child, DW_AT_count, &ca)) {
                                Dwarf_Word cnt;
                                if (dwarf_formudata(&ca, &cnt) == 0) {
                                    field.array_element_count = cnt;
                                    break;
                                }
                            }
                        }
                    } while (dwarf_siblingof(&sub_child, &sub_child) == 0);
                }
            }

            // 指针字段:解析目标类型
            if (field.is_pointer) {
                Dwarf_Attribute tgt_attr;
                if (dwarf_attr(&type_die, DW_AT_type, &tgt_attr)) {
                    Dwarf_Die tgt_die;
                    if (dwarf_formref_die(&tgt_attr, &tgt_die)) {
                        field.pointer_target_type_offset = dwarf_dieoffset(&tgt_die);
                        const char *tn = dwarf_diename(&tgt_die);
                        if (tn) field.pointer_target_type_name = tn;
                    }
                }
            }

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
    info.die_offset = dwarf_dieoffset(die);

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

    Dwarf_Die child;
    if (dwarf_child(die, &child) == 0) {
        do {
            int child_tag = dwarf_tag(&child);
            if (child_tag == DW_TAG_variable) {
                Dwarf_Attribute var_type_attr;
                if (dwarf_attr(&child, DW_AT_type, &var_type_attr)) {
                    LocalVariableInfo var_info = {};
                    var_info.is_pointer = false;
                    var_info.type_die_offset = 0;
                    var_info.pointer_target_type_offset = 0;

                    const char *var_name = dwarf_diename(&child);
                    if (var_name)
                        var_info.name = var_name;

                    Dwarf_Die type_die;
                    if (dwarf_formref_die(&var_type_attr, &type_die)) {
                        var_info.type_die_offset = dwarf_dieoffset(&type_die);
                        const char *type_name = dwarf_diename(&type_die);
                        if (type_name)
                            var_info.type_name = type_name;

                        int type_tag = dwarf_tag(&type_die);
                        if (type_tag == DW_TAG_pointer_type) {
                            var_info.is_pointer = true;
                            Dwarf_Attribute ptr_target_attr;
                            if (dwarf_attr(&type_die, DW_AT_type, &ptr_target_attr)) {
                                Dwarf_Die target_type_die;
                                if (dwarf_formref_die(&ptr_target_attr, &target_type_die)) {
                                    var_info.pointer_target_type_offset = dwarf_dieoffset(&target_type_die);
                                    const char *target_name = dwarf_diename(&target_type_die);
                                    if (target_name)
                                        var_info.pointer_target_type_name = target_name;

                                    Dwarf_Die deepest_die = target_type_die;
                                    for (int depth = 0; depth < 16; depth++) {
                                        int dtag = dwarf_tag(&deepest_die);
                                        if (dtag != DW_TAG_pointer_type &&
                                            dtag != DW_TAG_typedef &&
                                            dtag != DW_TAG_const_type &&
                                            dtag != DW_TAG_volatile_type &&
                                            dtag != DW_TAG_restrict_type)
                                            break;
                                        Dwarf_Attribute dta;
                                        if (!dwarf_attr(&deepest_die, DW_AT_type, &dta))
                                            break;
                                        Dwarf_Die next_die;
                                        if (!dwarf_formref_die(&dta, &next_die))
                                            break;
                                        deepest_die = next_die;
                                    }

                                    const char *deepest_name = dwarf_diename(&deepest_die);
                                    if (deepest_name && var_info.pointer_target_type_name.empty())
                                        var_info.pointer_target_type_name = deepest_name;
                                }
                            }
                        } else if (type_tag == DW_TAG_array_type) {
                            Dwarf_Attribute elem_attr;
                            if (dwarf_attr(&type_die, DW_AT_type, &elem_attr)) {
                                Dwarf_Die elem_type_die;
                                if (dwarf_formref_die(&elem_attr, &elem_type_die)) {
                                    int elem_tag = dwarf_tag(&elem_type_die);
                                    if (elem_tag == DW_TAG_pointer_type) {
                                        var_info.is_pointer = true;
                                        Dwarf_Attribute ptr_target_attr;
                                        if (dwarf_attr(&elem_type_die, DW_AT_type, &ptr_target_attr)) {
                                            Dwarf_Die target_type_die;
                                            if (dwarf_formref_die(&ptr_target_attr, &target_type_die)) {
                                                var_info.pointer_target_type_offset = dwarf_dieoffset(&target_type_die);
                                                const char *target_name = dwarf_diename(&target_type_die);
                                                if (target_name)
                                                    var_info.pointer_target_type_name = target_name;

                                                Dwarf_Die deepest_die = target_type_die;
                                                for (int depth = 0; depth < 16; depth++) {
                                                    int dtag = dwarf_tag(&deepest_die);
                                                    if (dtag != DW_TAG_pointer_type &&
                                                        dtag != DW_TAG_typedef &&
                                                        dtag != DW_TAG_const_type &&
                                                        dtag != DW_TAG_volatile_type &&
                                                        dtag != DW_TAG_restrict_type)
                                                        break;
                                                    Dwarf_Attribute dta;
                                                    if (!dwarf_attr(&deepest_die, DW_AT_type, &dta))
                                                        break;
                                                    Dwarf_Die next_die;
                                                    if (!dwarf_formref_die(&dta, &next_die))
                                                        break;
                                                    deepest_die = next_die;
                                                }

                                                const char *deepest_name = dwarf_diename(&deepest_die);
                                                if (deepest_name && var_info.pointer_target_type_name.empty())
                                                    var_info.pointer_target_type_name = deepest_name;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (!var_info.name.empty())
                        info.local_variables.push_back(var_info);
                }
            }
        } while (dwarf_siblingof(&child, &child) == 0);
    }

    subprograms_.push_back(info);
    subprogram_name_index_[info.name] = subprograms_.size() - 1;
    if (!info.linkage_name.empty())
        subprogram_name_index_[info.linkage_name] = subprograms_.size() - 1;
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

            if (sym.type_name.empty()) {
                Dwarf_Die deepest_die = type_die;
                for (int depth = 0; depth < 16; depth++) {
                    int dtag = dwarf_tag(&deepest_die);
                    if (dtag != DW_TAG_pointer_type &&
                        dtag != DW_TAG_typedef &&
                        dtag != DW_TAG_const_type &&
                        dtag != DW_TAG_volatile_type &&
                        dtag != DW_TAG_restrict_type)
                        break;
                    Dwarf_Attribute dta;
                    if (!dwarf_attr(&deepest_die, DW_AT_type, &dta))
                        break;
                    Dwarf_Die next_die;
                    if (!dwarf_formref_die(&dta, &next_die))
                        break;
                    deepest_die = next_die;
                    const char *dn = dwarf_diename(&deepest_die);
                    if (dn) {
                        sym.type_name = dn;
                        break;
                    }
                }
            }

            Dwarf_Word type_size = 0;
            if (dwarf_aggregate_size(&type_die, &type_size) == 0 && type_size > 0)
                sym.size = type_size;
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
    Dwarf *dbg = dwarf_ptr_.get();
    if (!dbg)
        return 0;

    Dwarf_CFI *cfi = dwarf_getcfi(dbg);
    if (!cfi)
        return 0;

    for (const auto &sp : subprograms_) {
        if (sp.low_pc == 0)
            continue;

        uint64_t start = sp.low_pc;
        uint64_t end = sp.high_pc_is_offset ? sp.low_pc + sp.high_pc : sp.high_pc;
        if (end <= start)
            continue;

        Dwarf_Frame *frame = nullptr;
        if (dwarf_cfi_addrframe(cfi, start, &frame) != 0)
            continue;

        FDERecord rec = {};
        rec.fde_offset = 0;
        rec.cie_pointer = 0;
        rec.initial_location = start;
        rec.address_range = end - start;
        rec.cie = nullptr;

        Dwarf_Op *cfa_ops = nullptr;
        size_t cfa_nops = 0;
        if (dwarf_frame_cfa(frame, &cfa_ops, &cfa_nops) == 0 && cfa_ops) {
            (void)cfa_ops;
            (void)cfa_nops;
        }

        fde_records_.push_back(rec);
        free(frame);
    }

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

std::optional<std::pair<std::string, uint32_t>> DwarfAnalyzer::resolve_source_line(uint64_t pc) const
{
    Dwarf *dbg = dwarf_ptr_.get();
    if (!dbg)
        return std::nullopt;

    Dwarf_Off off = 0;
    Dwarf_Off next_off;
    size_t    cu_hdr_size;

    while (dwarf_nextcu(dbg, off, &next_off, &cu_hdr_size, nullptr, nullptr, nullptr) == 0) {
        Dwarf_Die cudie;
        if (dwarf_offdie(dbg, off + cu_hdr_size, &cudie) == nullptr) {
            off = next_off;
            continue;
        }

        if (dwarf_haspc(&cudie, pc) != 1) {
            off = next_off;
            continue;
        }

        Dwarf_Lines *lines = nullptr;
        size_t nlines = 0;
        if (dwarf_getsrclines(&cudie, &lines, &nlines) != 0) {
            off = next_off;
            continue;
        }

        Dwarf_Line *line = dwarf_getsrc_die(&cudie, pc);
        if (!line) {
            off = next_off;
            continue;
        }

        const char *src = dwarf_linesrc(line, nullptr, nullptr);
        if (!src) {
            off = next_off;
            continue;
        }

        int lineno_val = 0;
        dwarf_lineno(line, &lineno_val);
        return std::make_pair(std::string(src), static_cast<uint32_t>(lineno_val));
    }

    return std::nullopt;
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

    if (type->fields.empty() && type->tag == TypeInfo::TAG_TYPEDEF) {
        Dwarf_Off off = 0, next_off;
        size_t cu_hdr_size;
        Dwarf *dbg = dwarf_ptr_.get();
        if (dbg) {
            while (dwarf_nextcu(dbg, off, &next_off, &cu_hdr_size, nullptr, nullptr, nullptr) == 0) {
                Dwarf_Die cudie;
                if (dwarf_offdie(dbg, off + cu_hdr_size, &cudie) != nullptr) {
                    Dwarf_Die tdie;
                    if (dwarf_offdie(dbg, type->die_offset, &tdie) != nullptr) {
                        Dwarf_Die cur = tdie;
                        for (int depth = 0; depth < 16; depth++) {
                            if (dwarf_tag(&cur) != DW_TAG_typedef)
                                break;
                            Dwarf_Attribute ta;
                            if (!dwarf_attr(&cur, DW_AT_type, &ta))
                                break;
                            Dwarf_Die next;
                            if (!dwarf_formref_die(&ta, &next))
                                break;
                            cur = next;
                        }
                        const TypeInfo *resolved = find_type_by_offset(dwarf_dieoffset(&cur));
                        if (resolved && !resolved->fields.empty())
                            return resolve_field_at_offset(resolved->die_offset, byte_offset);
                    }
                }
                off = next_off;
            }
        }
    }
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

std::optional<DwarfAnalyzer::ResolvedFieldPath> DwarfAnalyzer::resolve_field_path_recursive(
    uint64_t type_die_offset, uint64_t byte_offset, int depth) const
{
    if (depth > 16)
        return std::nullopt;

    const TypeInfo *type = find_type_by_offset(type_die_offset);
    if (!type)
        return std::nullopt;

    ResolvedFieldPath rp = {};
    rp.byte_offset = byte_offset;
    rp.byte_size = type->byte_size;
    rp.field_type_name = type->name;

    // typedef 穿透
    if (type->tag == TypeInfo::TAG_TYPEDEF && type->underlying_type_offset) {
        auto inner = resolve_field_path_recursive(type->underlying_type_offset, byte_offset, depth + 1);
        if (inner) {
            rp.var_path = inner->var_path;
            rp.type_path = type->name;
            if (!inner->type_path.empty())
                rp.type_path += "." + inner->type_path;
            rp.byte_size = inner->byte_size;
            rp.field_type_name = inner->field_type_name;
            return rp;
        }
        rp.type_path = type->name;
        return rp;
    }

    // 数组:计算 elem_index + elem_offset
    if (type->tag == TypeInfo::TAG_ARRAY && type->element_byte_size > 0) {
        uint64_t idx = byte_offset / type->element_byte_size;
        uint64_t sub = byte_offset % type->element_byte_size;
        rp.var_path = "[" + std::to_string(idx) + "]";
        rp.type_path = type->name + "[" + std::to_string(idx) + "]";
        rp.byte_size = type->element_byte_size;
        rp.field_type_name = type->element_type_name;
        if (sub > 0 && type->element_type_offset) {
            auto inner = resolve_field_path_recursive(type->element_type_offset, sub, depth + 1);
            if (inner) {
                rp.var_path += "." + inner->var_path;
                rp.type_path += "." + inner->type_path;
                rp.byte_size = inner->byte_size;
                rp.field_type_name = inner->field_type_name;
            }
        }
        return rp;
    }

    // struct/union:找最匹配字段并递归
    if (type->tag == TypeInfo::TAG_STRUCT || type->tag == TypeInfo::TAG_UNION) {
        const FieldInfo *best = nullptr;
        uint64_t best_distance = UINT64_MAX;
        for (const auto &f : type->fields) {
            if (byte_offset == f.byte_offset) {
                if (!best || f.byte_size > best->byte_size) {
                    best = &f;
                    best_distance = 0;
                }
            }
            if (f.byte_size > 0 &&
                byte_offset >= f.byte_offset &&
                byte_offset < f.byte_offset + f.byte_size) {
                uint64_t dist = byte_offset - f.byte_offset;
                if (dist < best_distance) {
                    best_distance = dist;
                    best = &f;
                }
            }
        }
        if (!best) {
            rp.type_path = type->name;
            return rp;
        }
        rp.var_path = best->name;
        rp.type_path = type->name + "." + best->name;
        rp.byte_offset = best->byte_offset;
        rp.byte_size = best->byte_size;
        rp.field_type_name = best->type_name;
        // 递归嵌套结构体
        uint64_t sub = byte_offset - best->byte_offset;
        if (sub > 0 && best->type_die_offset) {
            auto inner = resolve_field_path_recursive(best->type_die_offset, sub, depth + 1);
            if (inner) {
                if (!inner->var_path.empty())
                    rp.var_path += "." + inner->var_path;
                if (!inner->type_path.empty())
                    rp.type_path += "." + inner->type_path;
                rp.byte_size = inner->byte_size;
                rp.field_type_name = inner->field_type_name;
            }
        }
        return rp;
    }

    // 标量/指针/base_type
    rp.type_path = type->name;
    return rp;
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
    Dwarf *dbg = dwarf_ptr_.get();
    if (!dbg)
        return -1;

    Dwarf_CFI *cfi = dwarf_getcfi(dbg);
    if (!cfi)
        return -1;

    Dwarf_Frame *frame = nullptr;
    if (dwarf_cfi_addrframe(cfi, pc, &frame) != 0)
        return -1;

    Dwarf_Op *cfa_ops = nullptr;
    size_t cfa_nops = 0;
    if (dwarf_frame_cfa(frame, &cfa_ops, &cfa_nops) != 0) {
        free(frame);
        return -1;
    }

    if (reg_count >= 1 && cfa_nops > 0)
        regs[0] = cfa_ops[0].number;

    free(frame);
    return 0;
}

const SubprogramInfo *DwarfAnalyzer::find_subprogram_by_name(const std::string &name) const
{
    auto it = subprogram_name_index_.find(name);
    if (it != subprogram_name_index_.end())
        return &subprograms_[it->second];
    return nullptr;
}

std::vector<StackVariableInfo> DwarfAnalyzer::find_stack_variables(uint64_t pc) const
{
    std::vector<StackVariableInfo> result;

    Dwarf *dbg = dwarf_ptr_.get();
    if (!dbg)
        return result;

    const SubprogramInfo *subprog = nullptr;
    for (const auto &sp : subprograms_) {
        if (sp.high_pc_is_offset) {
            if (pc >= sp.low_pc && pc < sp.low_pc + sp.high_pc) {
                subprog = &sp;
                break;
            }
        } else {
            if (pc >= sp.low_pc && pc < sp.high_pc) {
                subprog = &sp;
                break;
            }
        }
    }

    if (!subprog)
        return result;

    Dwarf_Die die;
    if (!dwarf_offdie(dbg, subprog->die_offset, &die))
        return result;

    Dwarf_Die child;
    if (dwarf_child(&die, &child) != 0)
        return result;

    do {
        if (dwarf_tag(&child) != DW_TAG_variable)
            continue;

        const char *var_name = dwarf_diename(&child);
        if (!var_name)
            continue;

        Dwarf_Attribute loc_attr;
        if (!dwarf_attr(&child, DW_AT_location, &loc_attr))
            continue;

        Dwarf_Op *ops = nullptr;
        size_t ops_len = 0;
        if (dwarf_getlocation(&loc_attr, &ops, &ops_len) != 0 || ops_len == 0)
            continue;

        int64_t stack_offset = 0;
        bool found_offset = false;

        for (size_t i = 0; i < ops_len; i++) {
            if (ops[i].atom == DW_OP_fbreg) {
                stack_offset = ops[i].number + ops[i].offset;
                found_offset = true;
                break;
            }
            if (ops[i].atom >= DW_OP_breg0 && ops[i].atom <= DW_OP_breg31) {
                stack_offset = ops[i].number + ops[i].offset;
                found_offset = true;
                break;
            }
        }

        if (!found_offset)
            continue;

        StackVariableInfo var_info = {};
        var_info.name = var_name;
        var_info.stack_offset = stack_offset;

        Dwarf_Attribute type_attr;
        if (dwarf_attr(&child, DW_AT_type, &type_attr)) {
            Dwarf_Die type_die;
            if (dwarf_formref_die(&type_attr, &type_die)) {
                var_info.type_die_offset = dwarf_dieoffset(&type_die);
                const char *type_name = dwarf_diename(&type_die);
                if (type_name)
                    var_info.type_name = type_name;

                int type_tag = dwarf_tag(&type_die);
                var_info.is_pointer = (type_tag == DW_TAG_pointer_type);

                // 指针:解析目标类型
                if (var_info.is_pointer) {
                    Dwarf_Attribute tgt_attr;
                    if (dwarf_attr(&type_die, DW_AT_type, &tgt_attr)) {
                        Dwarf_Die tgt_die;
                        if (dwarf_formref_die(&tgt_attr, &tgt_die)) {
                            var_info.pointer_target_type_offset = dwarf_dieoffset(&tgt_die);
                            const char *tn = dwarf_diename(&tgt_die);
                            if (tn) var_info.pointer_target_type_name = tn;
                        }
                    }
                }

                Dwarf_Word type_size = 0;
                if (dwarf_aggregate_size(&type_die, &type_size) == 0 && type_size > 0)
                    var_info.byte_size = type_size;
            }
        }

        result.push_back(var_info);
    } while (dwarf_siblingof(&child, &child) == 0);

    return result;
}

std::vector<std::string> DwarfAnalyzer::find_pointer_target_types_at_pc(uint64_t pc) const
{
    std::vector<std::string> results;

    for (const auto &sp : subprograms_) {
        bool in_range = false;
        if (sp.high_pc_is_offset) {
            if (pc >= sp.low_pc && pc < sp.low_pc + sp.high_pc)
                in_range = true;
        } else {
            if (pc >= sp.low_pc && pc < sp.high_pc)
                in_range = true;
        }

        if (!in_range)
            continue;

        for (const auto &var : sp.local_variables) {
            if (var.is_pointer && !var.pointer_target_type_name.empty()) {
                results.push_back(var.pointer_target_type_name);
            }
        }
        break;
    }

    std::sort(results.begin(), results.end());
    results.erase(std::unique(results.begin(), results.end()), results.end());

    return results;
}

}
