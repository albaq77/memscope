#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>

#include "../dwarf/dwarf_analyzer.h"
#include "../resolver/address_resolver.h"

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "MemScope - eBPF + DWARF Address-to-Field Resolver\n"
        "\n"
        "Usage:\n"
        "  %s lookup  -b <binary> -f <csv> -a <addr> [-a <addr> ...]\n"
        "  %s batch   -b <binary> -f <csv> [-o <output>]\n"
        "  %s resolve -b <binary> -a <addr> [-p <pid>] [-f <csv>]\n"
        "  %s layout  -b <binary> -t <type>\n"
        "  %s types   -b <binary> [-n <name>]\n"
        "  %s symbols -b <binary> [-n <name>]\n"
        "\n"
        "Commands:\n"
        "  lookup    Lookup addresses: auto-classify region + resolve field\n"
        "  batch     Batch resolve all addresses in CSV\n"
        "  resolve   Resolve single address (verbose)\n"
        "  layout    Print struct layout\n"
        "  types     List/search types\n"
        "  symbols   List/search symbols\n"
        "\n"
        "Options:\n"
        "  -b <path>   Binary file path\n"
        "  -a <addr>   Address (hex: 0x...), can specify multiple\n"
        "  -t <type>   Type name\n"
        "  -p <pid>    Process PID\n"
        "  -f <csv>    Allocation CSV from collector\n"
        "  -o <file>   Output file for batch results\n"
        "  -n <name>   Search filter\n"
        "  -h          Show this help\n",
        prog, prog, prog, prog, prog, prog);
}

static uint64_t parse_addr(const char *s)
{
    uint64_t addr = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        sscanf(s + 2, "%lx", &addr);
    else
        sscanf(s, "%lu", &addr);
    return addr;
}

static std::vector<memscope::AllocInfo> load_csv(const std::string &csv_path)
{
    std::vector<memscope::AllocInfo> allocs;
    std::ifstream ifs(csv_path);
    std::string line;
    std::getline(ifs, line);

    while (std::getline(ifs, line)) {
        memscope::AllocInfo info = {};
        char live_str[8] = {};
        long stack_id_val = 0;
        int stack_depth_val = 0;

        int parsed = sscanf(line.c_str(), "0x%lx,%lu,%u,%u,%7[^,],%lu,%lu,%ld,%d",
                   &info.addr, &info.size, &info.pid, &info.tid,
                   live_str, &info.timestamp, &info.timestamp,
                   &stack_id_val, &stack_depth_val);

        if (parsed >= 5) {
            info.live = (strcmp(live_str, "1") == 0);
            info.stack_id = stack_id_val;
            info.stack_depth = stack_depth_val;

            if (parsed >= 9) {
                size_t pos = 0;
                int comma_count = 0;
                for (size_t i = 0; i < line.size(); i++) {
                    if (line[i] == ',') {
                        comma_count++;
                        if (comma_count == 9) {
                            pos = i + 1;
                            break;
                        }
                    }
                }
                if (pos > 0 && pos < line.size()) {
                    std::string pcs_str = line.substr(pos);
                    if (!pcs_str.empty()) {
                        std::istringstream iss(pcs_str);
                        std::string token;
                        while (std::getline(iss, token, ';')) {
                            uint64_t pc = 0;
                            if (sscanf(token.c_str(), "0x%lx", &pc) == 1 && pc != 0) {
                                info.stack_pcs.push_back(pc);
                            }
                        }
                    }
                }
            }

            allocs.push_back(info);
        }
    }
    return allocs;
}

static int cmd_lookup(memscope::AddressResolver &resolver, const std::string &csv_path,
                       const std::vector<uint64_t> &addrs)
{
    if (!csv_path.empty()) {
        auto allocs = load_csv(csv_path);
        resolver.set_alloc_table(allocs);
    }

    printf("%-18s  %-6s  %-20s  %-30s  %s\n",
           "ADDRESS", "REGION", "TYPE", "FIELD", "OFFSET");
    printf("%-18s  %-6s  %-20s  %-30s  %s\n",
           "------------------", "------", "--------------------", "------------------------------", "------");

    for (uint64_t addr : addrs) {
        auto result = resolver.resolve(addr, 0);
        if (!result) {
            printf("0x%016lx  %-6s  %-20s  %-30s  %s\n",
                   addr, "??????", "", "", "");
            continue;
        }

        const char *cls = result->addr_class == memscope::ResolvedAddress::ADDR_GLOBAL ? "GLOBAL" :
                          result->addr_class == memscope::ResolvedAddress::ADDR_HEAP   ? "HEAP"   :
                          result->addr_class == memscope::ResolvedAddress::ADDR_STACK  ? "STACK"  : "??????";

        if (result->fields.empty()) {
            printf("0x%016lx  %-6s  %-20s  %-30s  %s\n",
                   addr, cls,
                   result->type_name.empty() ? "" : result->type_name.c_str(),
                   "", "");
        } else {
            for (const auto &f : result->fields) {
                char field_desc[256];
                snprintf(field_desc, sizeof(field_desc), "%s.%s",
                         f.type_name.c_str(), f.field_name.c_str());

                char offset_desc[64];
                if (f.field_byte_size > 0) {
                    snprintf(offset_desc, sizeof(offset_desc), "+%lu [%luB %s]",
                             f.field_byte_offset, f.field_byte_size,
                             f.field_type_name.empty() ? "?" : f.field_type_name.c_str());
                } else {
                    snprintf(offset_desc, sizeof(offset_desc), "+%lu", f.field_byte_offset);
                }

                printf("0x%016lx  %-6s  %-20s  %-30s  %s\n",
                       addr, cls,
                       result->type_name.empty() ? "" : result->type_name.c_str(),
                       field_desc, offset_desc);
            }
        }
    }

    return 0;
}

static int cmd_batch(memscope::AddressResolver &resolver, const std::string &csv_path,
                      const std::string &output_path)
{
    auto allocs = load_csv(csv_path);
    resolver.set_alloc_table(allocs);
    resolver.set_debug_log("memscope_debug.log");

    FILE *out = stdout;
    if (!output_path.empty()) {
        out = fopen(output_path.c_str(), "w");
        if (!out) {
            fprintf(stderr, "cannot open output: %s\n", output_path.c_str());
            return 1;
        }
    }

    fprintf(out, "address,size,region,type,field,offset,size_bytes,field_type,infer_method,confidence\n");

    size_t matched = 0;
    size_t total = allocs.size();
    const auto &analyzer = resolver.analyzer();

    for (const auto &alloc : allocs) {
        auto result = resolver.resolve(alloc.addr, alloc.pid);
        if (!result) {
            fprintf(out, "0x%lx,%lu,UNKNOWN,,,,,,,,\n", alloc.addr, alloc.size);
            continue;
        }

        const char *cls = result->addr_class == memscope::ResolvedAddress::ADDR_GLOBAL ? "GLOBAL" :
                          result->addr_class == memscope::ResolvedAddress::ADDR_HEAP   ? "HEAP"   :
                          result->addr_class == memscope::ResolvedAddress::ADDR_STACK  ? "STACK"  : "UNKNOWN";

        std::string infer_method;
        std::string confidence;
        if (result->addr_class == memscope::ResolvedAddress::ADDR_HEAP) {
            size_t paren = result->allocation_callsite.find('(');
            size_t end = result->allocation_callsite.find(')', paren);
            if (paren != std::string::npos && end != std::string::npos) {
                infer_method = result->allocation_callsite.substr(0, paren - 1);
                confidence = result->allocation_callsite.substr(paren + 1, end - paren - 1);
            } else {
                infer_method = result->allocation_callsite;
            }
        }

        if (result->type_name.empty()) {
            fprintf(out, "0x%lx,%lu,%s,,,,,,%s,%s\n",
                    alloc.addr, alloc.size, cls,
                    infer_method.c_str(), confidence.c_str());
            continue;
        }

        matched++;

        if (result->fields.empty()) {
            const memscope::TypeInfo *type_info = analyzer.find_type_by_name(result->type_name);
            if (!type_info || type_info->fields.empty()) {
                fprintf(out, "0x%lx,%lu,%s,%s,,,,,%s,%s\n",
                        alloc.addr, alloc.size, cls,
                        result->type_name.c_str(),
                        infer_method.c_str(), confidence.c_str());
                continue;
            }

            for (const auto &f : type_info->fields) {
                fprintf(out, "0x%lx,%lu,%s,%s,%s.%s,%lu,%lu,%s,%s,%s\n",
                        alloc.addr + f.byte_offset, alloc.size, cls,
                        result->type_name.c_str(),
                        result->type_name.c_str(), f.name.c_str(),
                        f.byte_offset, f.byte_size,
                        f.type_name.empty() ? "" : f.type_name.c_str(),
                        infer_method.c_str(), confidence.c_str());
            }
        } else {
            for (const auto &f : result->fields) {
                fprintf(out, "0x%lx,%lu,%s,%s,%s,%lu,%lu,%s,%s,%s\n",
                        f.resolved_address, alloc.size, cls,
                        result->type_name.c_str(),
                        f.full_path.c_str(),
                        f.field_byte_offset, f.field_byte_size,
                        f.field_type_name.empty() ? "" : f.field_type_name.c_str(),
                        infer_method.c_str(), confidence.c_str());
            }
        }
    }

    fprintf(stderr, "\nBatch resolve: %zu/%zu matched a known type\n", matched, total);

    if (out != stdout)
        fclose(out);

    return 0;
}

static int cmd_resolve(memscope::AddressResolver &resolver, uint64_t addr,
                        uint32_t pid, const std::string &csv_path)
{
    if (!csv_path.empty()) {
        auto allocs = load_csv(csv_path);
        resolver.set_alloc_table(allocs);
    }

    auto result = resolver.resolve(addr, pid);
    if (result) {
        printf("%s\n", resolver.resolved_to_string(*result).c_str());
    } else {
        printf("Could not resolve address 0x%lx\n", addr);
    }

    return 0;
}

static int cmd_layout(memscope::DwarfAnalyzer &analyzer, const std::string &type_name)
{
    if (type_name.empty()) {
        fprintf(stderr, "type name required for layout command\n");
        return 1;
    }
    printf("%s\n", analyzer.type_layout_to_string(type_name).c_str());
    return 0;
}

static int cmd_symbols(memscope::DwarfAnalyzer &analyzer, const std::string &filter)
{
    const auto &syms = analyzer.get_all_symbols();
    int count = 0;
    for (const auto &s : syms) {
        if (!filter.empty() && s.name.find(filter) == std::string::npos)
            continue;
        printf("0x%-16lx %-8lu %-8s %-12s %s%s\n",
               s.address, s.size,
               s.binding == memscope::SymbolInfo::BIND_GLOBAL ? "GLOBAL" :
               s.binding == memscope::SymbolInfo::BIND_LOCAL  ? "LOCAL"  : "WEAK",
               s.sym_type == memscope::SymbolInfo::SYM_FUNC   ? "FUNC"   :
               s.sym_type == memscope::SymbolInfo::SYM_OBJECT ? "OBJECT" : "OTHER",
               s.name.c_str(),
               s.type_name.empty() ? "" : (" [" + s.type_name + "]").c_str());
        count++;
    }
    printf("\nTotal: %d symbols\n", count);
    return 0;
}

static int cmd_types(memscope::DwarfAnalyzer &analyzer, const std::string &filter)
{
    const auto &types = analyzer.get_all_types();
    int count = 0;
    for (const auto &t : types) {
        if (!filter.empty() && t.name.find(filter) == std::string::npos)
            continue;
        const char *tag_str = t.tag == memscope::TypeInfo::TAG_STRUCT ? "struct" :
                              t.tag == memscope::TypeInfo::TAG_UNION  ? "union"  :
                              t.tag == memscope::TypeInfo::TAG_ENUM   ? "enum"   :
                              t.tag == memscope::TypeInfo::TAG_TYPEDEF ? "typedef" :
                              t.tag == memscope::TypeInfo::TAG_BASE_TYPE ? "base"  :
                              "other";
        printf("%-8s %-40s size=%-6lu fields=%-4zu\n",
               tag_str, t.name.c_str(), t.byte_size, t.fields.size());
        count++;
    }
    printf("\nTotal: %d types\n", count);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];
    argc--;
    argv++;

    std::string binary_path;
    std::vector<uint64_t> addrs;
    std::string type_name;
    std::string filter;
    uint32_t pid = 0;
    std::string csv_path;
    std::string output_path;

    int opt;
    while ((opt = getopt(argc, argv, "b:a:t:l:p:f:o:n:h")) != -1) {
        switch (opt) {
        case 'b': binary_path = optarg; break;
        case 'a': addrs.push_back(parse_addr(optarg)); break;
        case 't': type_name = optarg; break;
        case 'l': type_name = optarg; break;
        case 'p': pid = (uint32_t)atoi(optarg); break;
        case 'f': csv_path = optarg; break;
        case 'o': output_path = optarg; break;
        case 'n': filter = optarg; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    if (binary_path.empty()) {
        fprintf(stderr, "binary path is required (-b)\n");
        return 1;
    }

    memscope::DwarfAnalyzer analyzer;
    if (analyzer.load_binary(binary_path) != 0) {
        fprintf(stderr, "failed to load binary: %s\n", binary_path.c_str());
        return 1;
    }

    fprintf(stderr, "Loaded: %s (%zu types, %zu symbols)\n",
            binary_path.c_str(),
            analyzer.get_all_types().size(),
            analyzer.get_all_symbols().size());

    if (cmd == "lookup") {
        if (addrs.empty()) {
            fprintf(stderr, "lookup requires at least one -a <addr>\n");
            return 1;
        }
        memscope::AddressResolver resolver;
        resolver.load_binary(binary_path);
        return cmd_lookup(resolver, csv_path, addrs);
    } else if (cmd == "batch") {
        if (csv_path.empty()) {
            fprintf(stderr, "batch requires -f <csv>\n");
            return 1;
        }
        memscope::AddressResolver resolver;
        resolver.load_binary(binary_path);
        return cmd_batch(resolver, csv_path, output_path);
    } else if (cmd == "resolve") {
        if (addrs.empty()) {
            fprintf(stderr, "resolve requires -a <addr>\n");
            return 1;
        }
        memscope::AddressResolver resolver;
        resolver.load_binary(binary_path);
        return cmd_resolve(resolver, addrs[0], pid, csv_path);
    } else if (cmd == "layout") {
        return cmd_layout(analyzer, type_name);
    } else if (cmd == "symbols") {
        return cmd_symbols(analyzer, filter);
    } else if (cmd == "types") {
        return cmd_types(analyzer, filter);
    } else {
        fprintf(stderr, "unknown command: %s\n", cmd.c_str());
        print_usage(argv[0]);
        return 1;
    }
}
