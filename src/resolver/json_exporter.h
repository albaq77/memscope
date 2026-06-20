#ifndef MEMSCOPE_JSON_EXPORTER_H
#define MEMSCOPE_JSON_EXPORTER_H

#include <string>
#include <vector>
#include "address_resolver.h"
#include "json_writer.h"

namespace memscope {

// 把 DwarfAnalyzer + AddressResolver 的数据导出为 JSON 字典。
// 核心策略:引用式布局,不展开数组,每个类型/变量/alloc 只出现一次。
// 下游 Python 拿到地址后按需递归遍历类型树得到 变量名.字段.字段... 路径。
class JsonExporter {
public:
    JsonExporter(const AddressResolver &resolver, const std::vector<AllocInfo> &allocs)
        : resolver_(resolver), allocs_(allocs) {}

    std::string build_json() const;

    // 工具函数,供 cmd_lookup 等使用
    static std::string die_offset_hex(uint64_t off);
    static std::string addr_hex(uint64_t addr);

private:
    const AddressResolver &resolver_;
    const std::vector<AllocInfo> &allocs_;

    void emit_types(JsonWriter &w) const;
    void emit_globals(JsonWriter &w) const;
    void emit_locals(JsonWriter &w) const;
    void emit_allocs(JsonWriter &w) const;
    void emit_type_entry(JsonWriter &w, const TypeInfo &t) const;
    void emit_field_entry(JsonWriter &w, const FieldInfo &f) const;

    static uint64_t lookup_builtin_size(const std::string &type_name);
    static const char *tag_to_string(TypeInfo::Tag tag);
    static const char *binding_to_string(SymbolInfo::Binding b);
};

}  // namespace memscope

#endif
