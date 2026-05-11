#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define NUM_STRUCTURES 10000
#define NUM_ITERATIONS 1000

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

struct Vec3 {
    float x;
    float y;
    float z;
};

struct Color {
    float r;
    float g;
    float b;
};

struct Coord {
    double lat;
    double lon;
};

struct Triple {
    int a;
    int b;
    int c;
};

struct Counter {
    long value;
    long step;
};

struct Pair {
    int first;
    int second;
};

struct global_point_s {
    struct Point *p;
    int count;
};

static struct Point g_point = {1.0, 2.0, 3.0, 0, 1.5};
static struct Node  g_node  = {NULL, NULL, 42, 3.14, "global_node"};
static struct Buffer g_buf  = {4096, 0, NULL, 0, 1};
static struct Packet g_pkt  = {80, 443, 1, 0, {0}, 0xFFFF};
static struct Vec3   g_vec  = {1.0f, 2.0f, 3.0f};
static struct Color  g_clr  = {0.5f, 0.25f, 0.75f};
static struct Coord  g_coord = {39.9, 116.4};
static struct Triple g_triple = {1, 2, 3};
static struct Counter g_counter = {0, 1};
static struct Pair   g_pair = {10, 20};
static struct global_point_s g_point_mgr = {NULL, 0};
static int g_int_array[16] = {0};

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

static void bench_ambiguous_size_alloc(void)
{
    struct Vec3 *vec = (struct Vec3 *)malloc(sizeof(struct Vec3));
    struct Color *clr = (struct Color *)malloc(sizeof(struct Color));

    if (vec) {
        vec->x = 1.0f;
        vec->y = 2.0f;
        vec->z = 3.0f;
    }
    if (clr) {
        clr->r = 0.5f;
        clr->g = 0.25f;
        clr->b = 0.75f;
    }

    printf("  Vec3 (size=%zu): {%.1f, %.1f, %.1f}\n", sizeof(struct Vec3),
           vec ? vec->x : 0, vec ? vec->y : 0, vec ? vec->z : 0);
    printf("  Color (size=%zu): {%.2f, %.2f, %.2f}\n", sizeof(struct Color),
           clr ? clr->r : 0, clr ? clr->g : 0, clr ? clr->b : 0);
    printf("  -> Same size! Callsite inference should distinguish them.\n");

    free(vec);
    free(clr);

    struct Coord *coord = (struct Coord *)malloc(sizeof(struct Coord));
    struct Triple *triple = (struct Triple *)malloc(sizeof(struct Triple));

    if (coord) {
        coord->lat = 39.9;
        coord->lon = 116.4;
    }
    if (triple) {
        triple->a = 1;
        triple->b = 2;
        triple->c = 3;
    }

    printf("  Coord (size=%zu): {%.1f, %.1f}\n", sizeof(struct Coord),
           coord ? coord->lat : 0, coord ? coord->lon : 0);
    printf("  Triple (size=%zu): {%d, %d, %d}\n", sizeof(struct Triple),
           triple ? triple->a : 0, triple ? triple->b : 0, triple ? triple->c : 0);

    free(coord);
    free(triple);

    struct Counter *counter = (struct Counter *)malloc(sizeof(struct Counter));
    struct Pair *pair = (struct Pair *)malloc(sizeof(struct Pair));

    if (counter) {
        counter->value = 100;
        counter->step = 1;
    }
    if (pair) {
        pair->first = 10;
        pair->second = 20;
    }

    printf("  Counter (size=%zu): {%ld, %ld}\n", sizeof(struct Counter),
           counter ? counter->value : 0, counter ? counter->step : 0);
    printf("  Pair (size=%zu): {%d, %d}\n", sizeof(struct Pair),
           pair ? pair->first : 0, pair ? pair->second : 0);

    free(counter);
    free(pair);
}

static void bench_global_access(void)
{
    printf("  g_point: {x=%.1f, y=%.1f, z=%.1f, label=%d, weight=%.1f}\n",
           g_point.x, g_point.y, g_point.z, g_point.label, g_point.weight);
    printf("  g_node: {value=%d, score=%.2f, name='%s'}\n",
           g_node.value, g_node.score, g_node.name);
    printf("  g_buf: {capacity=%zu, length=%zu, flags=%d, refcount=%d}\n",
           g_buf.capacity, g_buf.length, g_buf.flags, g_buf.refcount);
    printf("  g_vec: {x=%.1f, y=%.1f, z=%.1f}\n", g_vec.x, g_vec.y, g_vec.z);
    printf("  g_clr: {r=%.2f, g=%.2f, b=%.2f}\n", g_clr.r, g_clr.g, g_clr.b);
    printf("  g_coord: {lat=%.1f, lon=%.1f}\n", g_coord.lat, g_coord.lon);
    printf("  g_triple: {a=%d, b=%d, c=%d}\n", g_triple.a, g_triple.b, g_triple.c);
    printf("  g_counter: {value=%ld, step=%ld}\n", g_counter.value, g_counter.step);
    printf("  g_pair: {first=%d, second=%d}\n", g_pair.first, g_pair.second);

    g_point_mgr.p = (struct Point *)malloc(sizeof(struct Point));
    g_point_mgr.count = 1;
    if (g_point_mgr.p) {
        g_point_mgr.p->x = 10.0;
        g_point_mgr.p->y = 20.0;
        g_point_mgr.p->z = 30.0;
        g_point_mgr.p->label = 99;
        g_point_mgr.p->weight = 5.5;
    }
    printf("  g_point_mgr.p: {x=%.1f, y=%.1f, z=%.1f}\n",
           g_point_mgr.p ? g_point_mgr.p->x : 0,
           g_point_mgr.p ? g_point_mgr.p->y : 0,
           g_point_mgr.p ? g_point_mgr.p->z : 0);

    for (int i = 0; i < 16; i++)
        g_int_array[i] = i * i;
    volatile int sum = 0;
    for (int i = 0; i < 16; i++)
        sum += g_int_array[i];
    printf("  g_int_array sum = %d\n", sum);
}

static void bench_stack_variables(void)
{
    struct Point  local_point  = {100.0, 200.0, 300.0, 1, 99.9};
    struct Node   local_node   = {NULL, NULL, 7, 2.71, "stack_node"};
    struct Vec3   local_vec    = {4.0f, 5.0f, 6.0f};
    struct Color  local_color  = {1.0f, 0.5f, 0.0f};
    struct Coord  local_coord  = {31.2, 121.5};
    struct Triple local_triple = {10, 20, 30};
    struct Counter local_counter = {50, 5};
    struct Pair   local_pair   = {100, 200};
    int local_int = 42;
    double local_double = 3.14159;

    printf("  local_point: {x=%.1f, y=%.1f, z=%.1f}\n",
           local_point.x, local_point.y, local_point.z);
    printf("  local_node: {value=%d, score=%.2f, name='%s'}\n",
           local_node.value, local_node.score, local_node.name);
    printf("  local_vec: {x=%.1f, y=%.1f, z=%.1f}\n",
           local_vec.x, local_vec.y, local_vec.z);
    printf("  local_color: {r=%.2f, g=%.2f, b=%.2f}\n",
           local_color.r, local_color.g, local_color.b);
    printf("  local_coord: {lat=%.1f, lon=%.1f}\n",
           local_coord.lat, local_coord.lon);
    printf("  local_triple: {a=%d, b=%d, c=%d}\n",
           local_triple.a, local_triple.b, local_triple.c);
    printf("  local_counter: {value=%ld, step=%ld}\n",
           local_counter.value, local_counter.step);
    printf("  local_pair: {first=%d, second=%d}\n",
           local_pair.first, local_pair.second);
    printf("  local_int = %d, local_double = %.5f\n", local_int, local_double);

    volatile double sink = local_point.x + local_node.score +
                           local_vec.x + local_color.r +
                           local_coord.lat + local_triple.a +
                           local_counter.value + local_pair.first +
                           local_int + local_double;
    (void)sink;
}

static void bench_multi_struct_alloc(void)
{
    struct Point *p1 = (struct Point *)malloc(sizeof(struct Point));
    struct Point *p2 = (struct Point *)malloc(sizeof(struct Point));
    struct Point *p3 = (struct Point *)malloc(sizeof(struct Point));
    struct Node  *n1 = (struct Node *)malloc(sizeof(struct Node));
    struct Node  *n2 = (struct Node *)malloc(sizeof(struct Node));
    struct Buffer *b1 = (struct Buffer *)malloc(sizeof(struct Buffer));
    struct Packet *pkt = (struct Packet *)malloc(sizeof(struct Packet));

    if (p1) { p1->x = 1.0; p1->y = 2.0; p1->z = 3.0; p1->label = 1; p1->weight = 1.0; }
    if (p2) { p2->x = 4.0; p2->y = 5.0; p2->z = 6.0; p2->label = 2; p2->weight = 2.0; }
    if (p3) { p3->x = 7.0; p3->y = 8.0; p3->z = 9.0; p3->label = 3; p3->weight = 3.0; }
    if (n1) { n1->left = NULL; n1->right = n2; n1->value = 10; n1->score = 1.5; snprintf(n1->name, 32, "n1"); }
    if (n2) { n2->left = NULL; n2->right = NULL; n2->value = 20; n2->score = 2.5; snprintf(n2->name, 32, "n2"); }
    if (b1) { b1->capacity = 1024; b1->length = 0; b1->data = NULL; b1->flags = 0; b1->refcount = 1; }
    if (pkt) { pkt->src_port = 8080; pkt->dst_port = 80; pkt->seq_num = 1; pkt->ack_num = 0; pkt->checksum = 0; }

    printf("  Allocated: 3 Points, 2 Nodes, 1 Buffer, 1 Packet in one function\n");
    printf("  Callsite inference should find all pointer types in this scope\n");

    free(p1);
    free(p2);
    free(p3);
    free(n1);
    free(n2);
    free(b1);
    free(pkt);
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
    if (bench_id == -1 || bench_id == 8) {
        printf("[%-30s]\n", "Ambiguous size allocation");
        bench_ambiguous_size_alloc();
    }
    if (bench_id == -1 || bench_id == 9) {
        printf("[%-30s]\n", "Global variable access");
        bench_global_access();
    }
    if (bench_id == -1 || bench_id == 10) {
        printf("[%-30s]\n", "Stack variable access");
        bench_stack_variables();
    }
    if (bench_id == -1 || bench_id == 11) {
        printf("[%-30s]\n", "Multi-struct allocation");
        bench_multi_struct_alloc();
    }

    printf("\nBenchmark complete.\n");
    return 0;
}
