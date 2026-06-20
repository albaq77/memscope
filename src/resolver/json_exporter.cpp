#include "json_exporter.h"
#include <cstdio>
#include <unordered_map>

namespace memscope {

std::string JsonExporter::die_offset_hex(uint64_t off)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%lx", off);
    return buf;
}

std::string JsonExporter::addr_hex(uint64_t addr)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%lx", addr);
    return buf;
}

const char *JsonExporter::tag_to_string(TypeInfo::Tag tag)
{
    switch (tag) {
    case TypeInfo::TAG_STRUCT:    return "struct";
    case TypeInfo::TAG_UNION:     return "union";
    case TypeInfo::TAG_ENUM:      return "enum";
    case TypeInfo::TAG_TYPEDEF:   return "typedef";
    case TypeInfo::TAG_BASE_TYPE: return "base_type";
    case TypeInfo::TAG_POINTER:   return "pointer";
    case TypeInfo::TAG_ARRAY:     return "array";
    case TypeInfo::TAG_FUNCTION:  return "function";
    default:                      return "unknown";
    }
}

const char *JsonExporter::binding_to_string(SymbolInfo::Binding b)
{
    switch (b) {
    case SymbolInfo::BIND_GLOBAL: return "GLOBAL";
    case SymbolInfo::BIND_LOCAL:  return "LOCAL";
    case SymbolInfo::BIND_WEAK:   return "WEAK";
    default:                      return "UNKNOWN";
    }
}

uint64_t JsonExporter::lookup_builtin_size(const std::string &type_name)
{
    static const std::unordered_map<std::string, uint64_t> builtin_sizes = {
        {"char", 1}, {"signed char", 1}, {"unsigned char", 1},
        {"short", 2}, {"short int", 2}, {"unsigned short", 2},
        {"int", 4}, {"signed int", 4}, {"unsigned int", 4},
        {"long", 8}, {"long int", 8}, {"unsigned long", 8},
        {"long long", 8}, {"long long int", 8}, {"unsigned long long", 8},
        {"float", 4}, {"double", 8}, {"long double", 16},
        {"_Bool", 1}, {"bool", 1},
    };
    auto it = builtin_sizes.find(type_name);
    if (it != builtin_sizes.end())
        return it->second;
    return 0;
}

void JsonExporter::emit_field_entry(JsonWriter &w, const FieldInfo &f) const
{
    w.begin_object();
    w.key("name"); w.value_string(f.name);
    w.key("byte_offset"); w.value_uint(f.byte_offset);
    w.key("byte_size"); w.value_uint(f.byte_size);
    w.key("bit_offset"); w.value_uint(f.bit_offset);
    w.key("bit_size"); w.value_uint(f.bit_size);
    w.key("is_bitfield"); w.value_bool(f.is_bitfield);
    w.key("type_name"); w.value_string(f.type_name);
    w.key("is_pointer"); w.value_bool(f.is_pointer);
    w.key("is_array"); w.value_bool(f.is_array);

    w.key("type_ref");
    if (f.type_die_offset) w.value_string(die_offset_hex(f.type_die_offset));
    else w.value_null();

    if (f.is_array) {
        w.key("array_element_type_name"); w.value_string(f.array_element_type_name);
        w.key("array_element_type_ref");
        if (f.array_element_type_offset) w.value_string(die_offset_hex(f.array_element_type_offset));
        else w.value_null();
        w.key("array_element_count"); w.value_uint(f.array_element_count);
        w.key("array_element_byte_size"); w.value_uint(f.array_element_byte_size);
    }

    if (f.is_pointer) {
        w.key("pointer_target_type_name"); w.value_string(f.pointer_target_type_name);
        w.key("pointer_target_type_ref");
        if (f.pointer_target_type_offset) w.value_string(die_offset_hex(f.pointer_target_type_offset));
        else w.value_null();
    }

    w.end_object();
}

void JsonExporter::emit_type_entry(JsonWriter &w, const TypeInfo &t) const
{
    w.begin_object();
    w.key("name"); w.value_string(t.name);
    w.key("tag"); w.value_string(tag_to_string(t.tag));
    w.key("byte_size"); w.value_uint(t.byte_size);
    w.key("alignment"); w.value_uint(t.alignment);
    w.key("die_offset"); w.value_string(die_offset_hex(t.die_offset));

    if (!t.source_file.empty()) {
        w.key("source_file"); w.value_string(t.source_file);
        w.key("source_line"); w.value_uint(t.source_line);
    }

    // 数组
    if (t.tag == TypeInfo::TAG_ARRAY) {
        w.key("element_type_ref");
        if (t.element_type_offset) w.value_string(die_offset_hex(t.element_type_offset));
        else w.value_null();
        w.key("element_type_name"); w.value_string(t.element_type_name);
        w.key("element_count"); w.value_uint(t.element_count);
        w.key("element_byte_size"); w.value_uint(t.element_byte_size);
    }

    // 指针
    if (t.tag == TypeInfo::TAG_POINTER) {
        w.key("pointer_target_type_ref");
        if (t.pointer_target_type_offset) w.value_string(die_offset_hex(t.pointer_target_type_offset));
        else w.value_null();
        w.key("pointer_target_type_name"); w.value_string(t.pointer_target_type_name);
    }

    // typedef
    if (t.tag == TypeInfo::TAG_TYPEDEF) {
        w.key("underlying_type_ref");
        if (t.underlying_type_offset) w.value_string(die_offset_hex(t.underlying_type_offset));
        else w.value_null();
        w.key("underlying_type_name"); w.value_string(t.underlying_type_name);
    }

    // struct/union fields
    if (t.tag == TypeInfo::TAG_STRUCT || t.tag == TypeInfo::TAG_UNION) {
        w.key("fields");
        w.begin_array();
        for (const auto &f : t.fields) {
            emit_field_entry(w, f);
        }
        w.end_array();
    }

    w.end_object();
}

void JsonExporter::emit_types(JsonWriter &w) const
{
    w.key("types");
    w.begin_object();
    const auto &types = resolver_.analyzer().get_all_types();
    for (const auto &t : types) {
        w.key(die_offset_hex(t.die_offset));
        emit_type_entry(w, t);
    }
    w.end_object();
}

void JsonExporter::emit_globals(JsonWriter &w) const
{
    w.key("globals");
    w.begin_array();
    const auto &symbols = resolver_.analyzer().get_all_symbols();
    for (const auto &s : symbols) {
        if (s.sym_type != SymbolInfo::SYM_OBJECT)
            continue;
        if (s.address == 0)
            continue;
        w.begin_object();
        w.key("name"); w.value_string(s.name);  // 变量名
        w.key("address"); w.value_string(addr_hex(s.address));
        w.key("size"); w.value_uint(s.size);
        w.key("type_name"); w.value_string(s.type_name);
        w.key("type_ref");
        if (s.type_die_offset) w.value_string(die_offset_hex(s.type_die_offset));
        else w.value_null();
        w.key("binding"); w.value_string(binding_to_string(s.binding));
        w.end_object();
    }
    w.end_array();
}

void JsonExporter::emit_locals(JsonWriter &w) const
{
    w.key("locals");
    w.begin_object();
    const auto &subprogs = resolver_.analyzer().get_subprograms();
    for (const auto &sp : subprogs) {
        if (sp.name.empty() || sp.low_pc == 0)
            continue;
        auto stack_vars = resolver_.analyzer().find_stack_variables(sp.low_pc);
        if (stack_vars.empty())
            continue;

        w.key(sp.name);
        w.begin_object();
        w.key("low_pc"); w.value_string(addr_hex(sp.low_pc));
        if (sp.high_pc) {
            uint64_t high = sp.high_pc_is_offset ? sp.low_pc + sp.high_pc : sp.high_pc;
            w.key("high_pc"); w.value_string(addr_hex(high));
        }
        if (!sp.source_file.empty()) {
            w.key("source_file"); w.value_string(sp.source_file);
            w.key("source_line"); w.value_uint(sp.source_line);
        }
        w.key("variables");
        w.begin_array();
        for (const auto &v : stack_vars) {
            w.begin_object();
            w.key("name"); w.value_string(v.name);  // 变量名
            w.key("type_name"); w.value_string(v.type_name);
            w.key("type_ref");
            if (v.type_die_offset) w.value_string(die_offset_hex(v.type_die_offset));
            else w.value_null();
            w.key("stack_offset"); w.value_int(v.stack_offset);
            w.key("byte_size"); w.value_uint(v.byte_size);
            w.key("is_pointer"); w.value_bool(v.is_pointer);
            if (v.is_pointer) {
                w.key("pointer_target_type_name"); w.value_string(v.pointer_target_type_name);
                w.key("pointer_target_type_ref");
                if (v.pointer_target_type_offset) w.value_string(die_offset_hex(v.pointer_target_type_offset));
                else w.value_null();
            }
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
    w.end_object();
}

void JsonExporter::emit_allocs(JsonWriter &w) const
{
    w.key("allocs");
    w.begin_array();
    for (const auto &alloc : allocs_) {
        w.begin_object();
        w.key("addr"); w.value_string(addr_hex(alloc.addr));
        w.key("size"); w.value_uint(alloc.size);
        w.key("pid"); w.value_uint(alloc.pid);
        w.key("tid"); w.value_uint(alloc.tid);
        w.key("live"); w.value_bool(alloc.live != 0);
        w.key("stack_id"); w.value_int(alloc.stack_id);
        w.key("stack_depth"); w.value_int(alloc.stack_depth);

        w.key("stack_pcs");
        w.begin_array();
        for (uint64_t pc : alloc.stack_pcs) {
            w.value_string(addr_hex(pc));
        }
        w.end_array();

        w.key("timestamp_alloc"); w.value_uint(alloc.timestamp);

        // 类型推断(不展开数组,只记录元数据)
        auto tr = resolver_.infer_type_combined_v2_public(
            alloc.stack_id, alloc.size, alloc.stack_pcs);

        w.key("inferred_type"); w.value_string(tr.type_name);
        w.key("inferred_method"); w.value_string(tr.method);
        w.key("confidence"); w.value_double(tr.confidence);
        w.key("element_count"); w.value_uint(tr.alloc_count);
        w.key("note"); w.value_string(tr.note);

        // 查找 type_ref
        const TypeInfo *ti = nullptr;
        if (!tr.type_name.empty())
            ti = resolver_.analyzer().find_type_by_name(tr.type_name);
        w.key("inferred_type_ref");
        if (ti) w.value_string(die_offset_hex(ti->die_offset));
        else w.value_null();

        // element_byte_size
        uint64_t elem_size = 0;
        if (ti && ti->byte_size > 0) {
            elem_size = ti->byte_size;
        } else if (!tr.type_name.empty()) {
            elem_size = lookup_builtin_size(tr.type_name);
        }
        w.key("element_byte_size"); w.value_uint(elem_size);

        w.end_object();
    }
    w.end_array();
}

std::string JsonExporter::build_json() const
{
    JsonWriter w;
    w.begin_object();

    w.key("version"); w.value_string("1.0");
    w.key("binary"); w.value_string(resolver_.binary_path());
    w.key("aslr_offset"); w.value_int(resolver_.aslr_offset());

    // binary_ranges
    w.key("binary_ranges");
    w.begin_array();
    for (const auto &r : resolver_.binary_ranges()) {
        w.begin_object();
        w.key("start"); w.value_string(addr_hex(r.start));
        w.key("end"); w.value_string(addr_hex(r.end));
        w.key("path"); w.value_string(r.path);
        w.end_object();
    }
    w.end_array();

    emit_types(w);
    emit_globals(w);
    emit_locals(w);
    emit_allocs(w);

    w.end_object();
    return w.str();
}

}  // namespace memscope
