#ifndef MEMSCOPE_JSON_WRITER_H
#define MEMSCOPE_JSON_WRITER_H

#include <string>
#include <vector>
#include <cstdint>
#include <sstream>

namespace memscope {

// 最小 JSON writer:用 ostringstream + 栈跟踪 array/object 状态,
// 自动处理逗号和字符串转义。零依赖。
class JsonWriter {
public:
    JsonWriter() = default;

    void begin_object();
    void end_object();
    void begin_array();
    void end_array();

    void key(const std::string &k);

    void value_string(const std::string &v);
    void value_uint(uint64_t v);
    void value_int(int64_t v);
    void value_double(double v);
    void value_bool(bool v);
    void value_null();

    // 直接写入预格式化 JSON 片段(调用方负责合法性)
    void raw(const std::string &json_fragment);

    std::string str() const { return oss_.str(); }

private:
    std::ostringstream oss_;
    // 栈:true=array,false=object
    std::vector<bool> container_is_array_;
    // 栈:当前容器是否已写入第一个元素
    std::vector<bool> first_in_container_;
    // 上一次调用是否是 key()(用于 object 中交替 key/value
    bool last_was_key_ = false;

    void comma_if_needed();
    static std::string escape(const std::string &s);
};

}  // namespace memscope

#endif
