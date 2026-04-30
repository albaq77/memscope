#include "collector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig)
{
    g_running = 0;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  -p, --pid PID        Target process PID to trace (0 = all)\n"
        "  -b, --binary PATH    Path to target binary for symbol resolution\n"
        "  -B, --bpf PATH       Path to BPF object file\n"
        "  -o, --output FILE    Output file for allocation data\n"
        "  -d, --duration SEC   Trace duration in seconds (0 = infinite)\n"
        "  -v, --verbose        Verbose output\n"
        "  -h, --help           Show this help\n",
        prog);
}

int main(int argc, char **argv)
{
    uint32_t target_pid = 0;
    const char *binary_path = NULL;
    const char *bpf_obj_path = NULL;
    const char *output_path = NULL;
    int duration = 0;
    int verbose = 0;

    static struct option long_opts[] = {
        {"pid",      required_argument, NULL, 'p'},
        {"binary",   required_argument, NULL, 'b'},
        {"bpf",      required_argument, NULL, 'B'},
        {"output",   required_argument, NULL, 'o'},
        {"duration", required_argument, NULL, 'd'},
        {"verbose",  no_argument,       NULL, 'v'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:b:B:o:d:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': target_pid = (uint32_t)atoi(optarg); break;
        case 'b': binary_path = optarg; break;
        case 'B': bpf_obj_path = optarg; break;
        case 'o': output_path = optarg; break;
        case 'd': duration = atoi(optarg); break;
        case 'v': verbose = 1; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    if (!binary_path && target_pid) {
        char proc_path[64];
        char exe_path[512];
        snprintf(proc_path, sizeof(proc_path), "/proc/%u/exe", target_pid);
        ssize_t len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = '\0';
            binary_path = exe_path;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *bpf_obj = bpf_obj_path ? bpf_obj_path : "memscope.bpf.o";

    struct collector_ctx *ctx = collector_init(bpf_obj, target_pid, binary_path);
    if (!ctx) {
        fprintf(stderr, "failed to initialize collector\n");
        return 1;
    }

    if (collector_start(ctx)) {
        fprintf(stderr, "failed to start collector\n");
        collector_destroy(ctx);
        return 1;
    }

    printf("MemScope collector started (pid=%u, binary=%s)\n",
           target_pid, binary_path ? binary_path : "none");
    printf("Press Ctrl-C to stop...\n\n");

    time_t start = time(NULL);
    while (g_running) {
        collector_poll(ctx, 100);

        if (duration > 0 && (time(NULL) - start) >= duration)
            break;

        if (target_pid > 0) {
            char proc_path[64];
            snprintf(proc_path, sizeof(proc_path), "/proc/%u/status", target_pid);
            if (access(proc_path, F_OK) != 0) {
                fprintf(stderr, "Target process %u exited, stopping...\n", target_pid);
                break;
            }
        }
    }

    printf("\nStopping collector...\n");
    collector_stop(ctx);
    collector_dump_allocs(ctx);

    if (output_path) {
        FILE *fp = fopen(output_path, "w");
        if (fp) {
            fprintf(fp, "address,size,pid,tid,live,timestamp_alloc,timestamp_free\n");
            for (size_t i = 0; i < ctx->table.count; i++) {
                struct alloc_record *r = &ctx->table.records[i];
                fprintf(fp, "0x%lx,%lu,%u,%u,%s,%lu,%lu\n",
                        r->addr, r->size, r->pid, r->tid,
                        r->live ? "1" : "0",
                        r->timestamp_alloc, r->timestamp_free);
            }
            fclose(fp);
            printf("Allocation data written to %s\n", output_path);
        } else {
            fprintf(stderr, "failed to open output file: %s\n", output_path);
        }
    }

    collector_destroy(ctx);
    return 0;
}
