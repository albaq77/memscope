#ifndef SOURCE_CODE_ANALYZER_H
#define SOURCE_CODE_ANALYZER_H

#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include <cstdint>

namespace memscope {

struct TypeExtractionResult {
    std::string type_name;
    std::string source_line;
    std::string method;
    float confidence;
    std::string note;
};

class SourceCodeAnalyzer {
public:
    SourceCodeAnalyzer();
    ~SourceCodeAnalyzer();

    int load_binary(const std::string &path);

    std::optional<std::pair<std::string, uint32_t>> get_source_location(uint64_t pc) const;

    std::optional<std::string> get_source_line(const std::string &file, uint32_t line) const;

    TypeExtractionResult extract_type_from_source(uint64_t pc) const;

    void set_binary_path(const std::string &path) { binary_path_ = path; }

private:
    std::string execute_addr2line(uint64_t pc) const;
    std::string read_source_file(const std::string &file) const;
    std::vector<std::string> extract_malloc_types(const std::string &line) const;
    std::vector<std::string> extract_calloc_types(const std::string &line) const;
    std::vector<std::string> extract_realloc_types(const std::string &line) const;

    std::string binary_path_;
    std::unordered_map<std::string, std::string> source_cache_;

    bool use_dwarf_;
    void *dwarf_handle_;
};

}

#endif
