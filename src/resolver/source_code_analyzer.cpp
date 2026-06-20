#include "source_code_analyzer.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <cstdio>
#include <array>
#include <cstring>
#include <cstdint>

namespace memscope {

SourceCodeAnalyzer::SourceCodeAnalyzer()
    : use_dwarf_(false)
    , dwarf_handle_(nullptr)
{
}

SourceCodeAnalyzer::~SourceCodeAnalyzer()
{
}

int SourceCodeAnalyzer::load_binary(const std::string &path)
{
    binary_path_ = path;
    return 0;
}

std::optional<std::pair<std::string, uint32_t>> SourceCodeAnalyzer::get_source_location(uint64_t pc) const
{
    std::string result = execute_addr2line(pc);
    if (result.empty())
        return std::nullopt;

    size_t colon_pos = result.rfind(':');
    if (colon_pos == std::string::npos)
        return std::nullopt;

    std::string file = result.substr(0, colon_pos);
    std::string line_str = result.substr(colon_pos + 1);

    if (file == "??" || line_str == "?")
        return std::nullopt;

    try {
        uint32_t line = std::stoul(line_str);
        return std::make_pair(file, line);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::string> SourceCodeAnalyzer::get_source_line(const std::string &file, uint32_t line) const
{
    std::string content = read_source_file(file);
    if (content.empty())
        return std::nullopt;

    std::istringstream iss(content);
    std::string result;
    uint32_t current_line = 1;

    while (std::getline(iss, result)) {
        if (current_line == line)
            return result;
        current_line++;
    }

    return std::nullopt;
}

static std::string try_resolve_source_path(const std::string &file)
{
    if (file.empty() || file == "??")
        return "";

    std::ifstream direct(file);
    if (direct.is_open())
        return file;

    std::string basename = file;
    size_t slash = basename.find_last_of('/');
    if (slash != std::string::npos)
        basename = basename.substr(slash + 1);

    const char *search_dirs_env = std::getenv("MEMSCOPE_SOURCE_PATH");
    std::vector<std::string> search_dirs;
    if (search_dirs_env && search_dirs_env[0]) {
        std::istringstream iss(search_dirs_env);
        std::string dir;
        while (std::getline(iss, dir, ':')) {
            if (!dir.empty())
                search_dirs.push_back(dir);
        }
    }

    search_dirs.push_back(".");
    search_dirs.push_back("tests");
    search_dirs.push_back("tests/kmeans");

    for (const auto &dir : search_dirs) {
        std::string candidate = dir + "/" + basename;
        std::ifstream test(candidate);
        if (test.is_open())
            return candidate;
    }

    return "";
}

TypeExtractionResult SourceCodeAnalyzer::extract_type_from_source(uint64_t pc) const
{
    TypeExtractionResult result = {};
    result.confidence = 0.0f;

    auto location = get_source_location(pc);
    if (!location)
        return result;

    std::string resolved = try_resolve_source_path(location->first);
    if (resolved.empty())
        return result;

    auto source_line = get_source_line(resolved, location->second);
    if (!source_line)
        return result;

    result.source_line = *source_line;

    std::vector<std::string> types;

    auto malloc_types = extract_malloc_types(*source_line);
    types.insert(types.end(), malloc_types.begin(), malloc_types.end());

    auto calloc_types = extract_calloc_types(*source_line);
    types.insert(types.end(), calloc_types.begin(), calloc_types.end());

    auto realloc_types = extract_realloc_types(*source_line);
    types.insert(types.end(), realloc_types.begin(), realloc_types.end());

    if (types.empty()) {
        result.method = "no_type_found";
        result.note = "No type pattern matched in source line";
        return result;
    }

    if (types.size() == 1) {
        result.type_name = types[0];
        result.method = "source_text";
        result.confidence = 0.90f;
        result.note = "Extracted from source: " + *source_line;
        return result;
    }

    if (types.size() > 1) {
        result.type_name = types[0];
        result.method = "source_text";
        result.confidence = 0.75f;
        result.note = "Extracted from source (multiple candidates): " + *source_line;
        return result;
    }
}

std::string SourceCodeAnalyzer::execute_addr2line(uint64_t pc) const
{
    if (binary_path_.empty())
        return "";

    std::array<char, 512> buffer;
    std::string result;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "addr2line -e %s 0x%lx 2>/dev/null",
             binary_path_.c_str(), pc);

    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return "";

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }

    pclose(pipe);

    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();

    return result;
}

std::string SourceCodeAnalyzer::read_source_file(const std::string &file) const
{
    auto it = source_cache_.find(file);
    if (it != source_cache_.end())
        return it->second;

    std::ifstream ifs(file);
    if (!ifs.is_open())
        return "";

    std::stringstream ss;
    ss << ifs.rdbuf();
    std::string content = ss.str();

    const_cast<SourceCodeAnalyzer*>(this)->source_cache_[file] = content;

    return content;
}

std::vector<std::string> SourceCodeAnalyzer::extract_malloc_types(const std::string &line) const
{
    std::vector<std::string> results;

    std::regex patterns[] = {
        std::regex(R"(=\s*\(\s*([^*\s]+)\s*\*\s*\)\s*malloc\s*\()"),
        std::regex(R"(=\s*\(\s*struct\s+([^*\s]+)\s*\*\s*\)\s*malloc\s*\()"),
        std::regex(R"(=\s*\(\s*([^*\s]+)\s*\*\s*\*\s*\)\s*malloc\s*\()"),
        std::regex(R"(([^*\s]+)\s*\*\s+(\w+)\s*=\s*malloc\s*\()"),
        std::regex(R"(struct\s+([^*\s]+)\s*\*\s+(\w+)\s*=\s*malloc\s*\()"),
        std::regex(R"(malloc\s*\(\s*sizeof\s*\(\s*([^)]+)\s*\)\s*\))"),
        std::regex(R"(malloc\s*\(\s*sizeof\s*\(\s*struct\s+([^)]+)\s*\)\s*\))"),
        std::regex(R"(malloc\s*\([^)]*\*\s*sizeof\s*\(\s*([^)]+)\s*\)\s*\))"),
        std::regex(R"(malloc\s*\([^)]*\*\s*sizeof\s*\(\s*struct\s+([^)]+)\s*\)\s*\))"),
        std::regex(R"(malloc\s*\(\s*\([^)]+\)\s*\*\s*sizeof\s*\(\s*([^)]+)\s*\)\s*\))"),
        std::regex(R"(malloc\s*\(\s*\([^)]+\)\s*\*\s*sizeof\s*\(\s*struct\s+([^)]+)\s*\)\s*\))"),
        std::regex(R"(malloc\s*\(\s*sizeof\s*\(\s*([^)]+)\s*\)\s*\*[^)]*\))"),
        std::regex(R"(malloc\s*\(\s*sizeof\s*\(\s*struct\s+([^)]+)\s*\)\s*\*[^)]*\))"),
        std::regex(R"(malloc\s*\(\s*\([^)]+\)\s*\*\s*sizeof\s*\(\s*([^)]+)\s*\)\s*\*[^)]*\))"),
    };

    for (const auto &pattern : patterns) {
        std::smatch match;
        if (std::regex_search(line, match, pattern)) {
            std::string type = match[1].str();

            type.erase(0, type.find_first_not_of(" \t\n\r"));
            type.erase(type.find_last_not_of(" \t\n\r") + 1);

            if (!type.empty() && type != "void") {
                results.push_back(type);
            }
        }
    }

    std::sort(results.begin(), results.end());
    results.erase(std::unique(results.begin(), results.end()), results.end());

    return results;
}

std::vector<std::string> SourceCodeAnalyzer::extract_calloc_types(const std::string &line) const
{
    std::vector<std::string> results;

    std::regex patterns[] = {
        std::regex(R"(=\s*\(\s*([^*\s]+)\s*\*\s*\)\s*calloc\s*\()"),
        std::regex(R"(=\s*\(\s*struct\s+([^*\s]+)\s*\*\s*\)\s*calloc\s*\()"),
        std::regex(R"(=\s*\(\s*([^*\s]+)\s*\*\s*\*\s*\)\s*calloc\s*\()"),
        std::regex(R"(([^*\s]+)\s*\*\s+(\w+)\s*=\s*calloc\s*\()"),
        std::regex(R"(struct\s+([^*\s]+)\s*\*\s+(\w+)\s*=\s*calloc\s*\()"),
        std::regex(R"(calloc\s*\([^,]+,\s*sizeof\s*\(\s*([^)]+)\s*\)\s*\))"),
        std::regex(R"(calloc\s*\([^,]+,\s*sizeof\s*\(\s*struct\s+([^)]+)\s*\)\s*\))"),
        std::regex(R"(calloc\s*\(\s*sizeof\s*\(\s*([^)]+)\s*\)\s*,[^)]*\))"),
        std::regex(R"(calloc\s*\(\s*sizeof\s*\(\s*struct\s+([^)]+)\s*\)\s*,[^)]*\))"),
    };

    for (const auto &pattern : patterns) {
        std::smatch match;
        if (std::regex_search(line, match, pattern)) {
            std::string type = match[1].str();

            type.erase(0, type.find_first_not_of(" \t\n\r"));
            type.erase(type.find_last_not_of(" \t\n\r") + 1);

            if (!type.empty() && type != "void") {
                results.push_back(type);
            }
        }
    }

    std::sort(results.begin(), results.end());
    results.erase(std::unique(results.begin(), results.end()), results.end());

    return results;
}

std::vector<std::string> SourceCodeAnalyzer::extract_realloc_types(const std::string &line) const
{
    std::vector<std::string> results;

    std::regex patterns[] = {
        std::regex(R"(=\s*\(\s*([^*\s]+)\s*\*\s*\)\s*realloc\s*\()"),
        std::regex(R"(=\s*\(\s*struct\s+([^*\s]+)\s*\*\s*\)\s*realloc\s*\()"),
        std::regex(R"(=\s*\(\s*([^*\s]+)\s*\*\s*\*\s*\)\s*realloc\s*\()"),
        std::regex(R"(([^*\s]+)\s*\*\s+(\w+)\s*=\s*realloc\s*\()"),
        std::regex(R"(struct\s+([^*\s]+)\s*\*\s+(\w+)\s*=\s*realloc\s*\()"),
        std::regex(R"(realloc\s*\([^,]+,\s*[^)]*sizeof\s*\(\s*([^)]+)\s*\)\s*\))"),
        std::regex(R"(realloc\s*\([^,]+,\s*[^)]*sizeof\s*\(\s*struct\s+([^)]+)\s*\)\s*\))"),
        std::regex(R"(realloc\s*\([^,]+,\s*sizeof\s*\(\s*([^)]+)\s*\)\s*\*[^)]*\))"),
        std::regex(R"(realloc\s*\([^,]+,\s*sizeof\s*\(\s*struct\s+([^)]+)\s*\)\s*\*[^)]*\))"),
    };

    for (const auto &pattern : patterns) {
        std::smatch match;
        if (std::regex_search(line, match, pattern)) {
            std::string type = match[1].str();

            type.erase(0, type.find_first_not_of(" \t\n\r"));
            type.erase(type.find_last_not_of(" \t\n\r") + 1);

            if (!type.empty() && type != "void") {
                results.push_back(type);
            }
        }
    }

    std::sort(results.begin(), results.end());
    results.erase(std::unique(results.begin(), results.end()), results.end());

    return results;
}

}
