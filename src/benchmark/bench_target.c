#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define NUM_STRUCTURES 100
#define NUM_ITERATIONS 10

struct Point {
    double x;
    double y;
    double z;
    int    label;
    double weight;
};

struct Node {
    struct Node *left;
    struct Node *right;
    int          value;
    double       score;
    char         name[32];
};

struct Buffer {
    size_t capacity;
    size_t length;
    char  *data;
    int    flags;
    int    refcount;
};

struct Packet {
    unsigned int src_port;
    unsigned int dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    char         payload[64];
    unsigned int checksum;
};

static void bench_point_alloc(void)
{
    struct Point *points[NUM_STRUCTURES];
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        for (int j = 0; j < NUM_STRUCTURES; j++) {
            points[j] = (struct Point *)malloc(sizeof(struct Point));
            if (!points[j]) {
                perror("malloc");
                return;
            }
            points[j]->x = (double)j * 0.1;
            points[j]->y = (double)j * 0.2;
            points[j]->z = (double)j * 0.3;
            points[j]->label = j % 10;
            points[j]->weight = (double)(j % 100) / 100.0;
        }
        for (int j = 0; j < NUM_STRUCTURES; j++) {
            free(points[j]);
        }
    }
}

static struct Node *create_tree(int depth)
{
    if (depth <= 0)
        return NULL;

    struct Node *node = (struct Node *)malloc(sizeof(struct Node));
    if (!node)
        return NULL;

    node->value = depth;
    node->score = (double)depth * 1.5;
    snprintf(node->name, sizeof(node->name), "node_d%d", depth);
    node->left = create_tree(depth - 1);
    node->right = create_tree(depth - 1);
    return node;
}

static void destroy_tree(struct Node *node)
{
    if (!node)
        return;
    destroy_tree(node->left);
    destroy_tree(node->right);
    free(node);
}

static void bench_tree_alloc(void)
{
    for (int i = 0; i < 5; i++) {
        struct Node *root = create_tree(8);
        destroy_tree(root);
    }
}

static void bench_buffer_alloc(void)
{
    struct Buffer *bufs[100];
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        for (int j = 0; j < 100; j++) {
            bufs[j] = (struct Buffer *)malloc(sizeof(struct Buffer));
            if (!bufs[j]) {
                perror("malloc");
                return;
            }
            bufs[j]->capacity = 4096;
            bufs[j]->length = 0;
            bufs[j]->data = (char *)malloc(bufs[j]->capacity);
            bufs[j]->flags = j % 4;
            bufs[j]->refcount = 1;
        }
        for (int j = 0; j < 100; j++) {
            free(bufs[j]->data);
            free(bufs[j]);
        }
    }
}

static void bench_packet_alloc(void)
{
    struct Packet *pkts[100];
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        for (int j = 0; j < 100; j++) {
            pkts[j] = (struct Packet *)malloc(sizeof(struct Packet));
            if (!pkts[j]) {
                perror("malloc");
                return;
            }
            pkts[j]->src_port = j;
            pkts[j]->dst_port = j + 1;
            pkts[j]->seq_num = i * 100 + j;
            pkts[j]->ack_num = pkts[j]->seq_num + 1;
            memset(pkts[j]->payload, 0xAA, sizeof(pkts[j]->payload));
            pkts[j]->checksum = j % 65536;
        }
        for (int j = 0; j < 100; j++) {
            free(pkts[j]);
        }
    }
}

static void bench_mixed_alloc(void)
{
    void *ptrs[200];
    size_t sizes[] = {
        sizeof(struct Point),
        sizeof(struct Node),
        sizeof(struct Buffer),
        sizeof(struct Packet),
        16, 32, 64, 128, 256, 512, 1024
    };
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 200; j++) {
            size_t sz = sizes[j % num_sizes];
            ptrs[j] = malloc(sz);
            if (!ptrs[j]) {
                perror("malloc");
                return;
            }
            memset(ptrs[j], 0, sz);
        }
        for (int j = 0; j < 200; j++) {
            free(ptrs[j]);
        }
    }
}

static void access_pattern_sequential(void)
{
    struct Point *points = (struct Point *)malloc(NUM_STRUCTURES * sizeof(struct Point));
    if (!points)
        return;

    for (int i = 0; i < NUM_STRUCTURES; i++) {
        points[i].x = (double)i;
        points[i].y = (double)i * 2;
        points[i].z = (double)i * 3;
        points[i].label = i;
        points[i].weight = (double)i / 10.0;
    }

    volatile double sum = 0;
    for (int i = 0; i < NUM_STRUCTURES; i++) {
        sum += points[i].x + points[i].y + points[i].z;
    }

    free(points);
}

static void access_pattern_random(void)
{
    struct Node *nodes = (struct Node *)malloc(NUM_STRUCTURES * sizeof(struct Node));
    if (!nodes)
        return;

    srand(42);
    for (int i = 0; i < NUM_STRUCTURES; i++) {
        nodes[i].value = i;
        nodes[i].score = (double)i;
        nodes[i].left = (i * 2 + 1 < NUM_STRUCTURES) ? &nodes[i * 2 + 1] : NULL;
        nodes[i].right = (i * 2 + 2 < NUM_STRUCTURES) ? &nodes[i * 2 + 2] : NULL;
    }

    volatile int total = 0;
    for (int i = 0; i < 1000; i++) {
        int idx = rand() % NUM_STRUCTURES;
        total += nodes[idx].value;
    }

    free(nodes);
}

int main(int argc, char **argv)
{
    int bench_id = -1;
    if (argc > 1)
        bench_id = atoi(argv[1]);

    printf("MemScope Benchmark Target (PID=%d)\n", getpid());
    printf("====================================\n\n");

    struct timespec ts_start, ts_end;

    if (bench_id == -1 || bench_id == 1) {
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        bench_point_alloc();
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        printf("[%-30s] %.4f seconds\n", "Point allocation",
               (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9);
    }
    if (bench_id == -1 || bench_id == 2) {
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        bench_tree_alloc();
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        printf("[%-30s] %.4f seconds\n", "Tree allocation",
               (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9);
    }
    if (bench_id == -1 || bench_id == 3) {
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        bench_buffer_alloc();
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        printf("[%-30s] %.4f seconds\n", "Buffer allocation",
               (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9);
    }
    if (bench_id == -1 || bench_id == 4) {
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        bench_packet_alloc();
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        printf("[%-30s] %.4f seconds\n", "Packet allocation",
               (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9);
    }
    if (bench_id == -1 || bench_id == 5) {
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        bench_mixed_alloc();
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        printf("[%-30s] %.4f seconds\n", "Mixed allocation",
               (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9);
    }
    if (bench_id == -1 || bench_id == 6) {
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        access_pattern_sequential();
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        printf("[%-30s] %.4f seconds\n", "Sequential access",
               (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9);
    }
    if (bench_id == -1 || bench_id == 7) {
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        access_pattern_random();
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        printf("[%-30s] %.4f seconds\n", "Random access",
               (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9);
    }

    printf("\nBenchmark complete.\n");
    return 0;
}
