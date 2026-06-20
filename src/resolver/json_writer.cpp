#include "json_writer.h"
#include <cstdio>

namespace memscope {

std::string JsonWriter::escape(const std::string &s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if ((unsigned char)c < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

void JsonWriter::comma_if_needed()
{
    if (container_is_array_.empty()) return;  // 顶层
    if (last_was_key_) return;  // object 中刚写了 key,接下来是 value,不加逗号
    if (!first_in_container_.back()) {
        oss_ << ",";
    }
}

void JsonWriter::begin_object()
{
    comma_if_needed();
    oss_ << "{";
    container_is_array_.push_back(false);
    first_in_container_.push_back(true);
    last_was_key_ = false;
}

void JsonWriter::end_object()
{
    oss_ << "}";
    if (!container_is_array_.empty()) {
        container_is_array_.pop_back();
        first_in_container_.pop_back();
        if (!first_in_container_.empty())
            first_in_container_.back() = false;
    }
    last_was_key_ = false;
}

void JsonWriter::begin_array()
{
    comma_if_needed();
    oss_ << "[";
    container_is_array_.push_back(true);
    first_in_container_.push_back(true);
    last_was_key_ = false;
}

void JsonWriter::end_array()
{
    oss_ << "]";
    if (!container_is_array_.empty()) {
        container_is_array_.pop_back();
        first_in_container_.pop_back();
        if (!first_in_container_.empty())
            first_in_container_.back() = false;
    }
    last_was_key_ = false;
}

void JsonWriter::key(const std::string &k)
{
    comma_if_needed();
    oss_ << "\"" << escape(k) << "\":";
    // 标记下一个是 value,不需要逗号
    last_was_key_ = true;
    if (!first_in_container_.empty())
        first_in_container_.back() = false;
}

void JsonWriter::value_string(const std::string &v)
{
    comma_if_needed();
    oss_ << "\"" << escape(v) << "\"";
    last_was_key_ = false;
    if (!first_in_container_.empty())
        first_in_container_.back() = false;
}

void JsonWriter::value_uint(uint64_t v)
{
    comma_if_needed();
    oss_ << v;
    last_was_key_ = false;
    if (!first_in_container_.empty())
        first_in_container_.back() = false;
}

void JsonWriter::value_int(int64_t v)
{
    comma_if_needed();
    oss_ << v;
    last_was_key_ = false;
    if (!first_in_container_.empty())
        first_in_container_.back() = false;
}

void JsonWriter::value_double(double v)
{
    comma_if_needed();
    char buf[64];
    snprintf(buf, sizeof(buf), "%.6g", v);
    oss_ << buf;
    last_was_key_ = false;
    if (!first_in_container_.empty())
        first_in_container_.back() = false;
}

void JsonWriter::value_bool(bool v)
{
    comma_if_needed();
    oss_ << (v ? "true" : "false");
    last_was_key_ = false;
    if (!first_in_container_.empty())
        first_in_container_.back() = false;
}

void JsonWriter::value_null()
{
    comma_if_needed();
    oss_ << "null";
    last_was_key_ = false;
    if (!first_in_container_.empty())
        first_in_container_.back() = false;
}

void JsonWriter::raw(const std::string &json_fragment)
{
    comma_if_needed();
    oss_ << json_fragment;
    last_was_key_ = false;
    if (!first_in_container_.empty())
        first_in_container_.back() = false;
}

}  // namespace memscope
