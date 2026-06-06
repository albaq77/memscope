#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

struct Point {
    double x;
    double y;
    double z;
    int label;
    double weight;
};

struct Node {
    struct Node *left;
    struct Node *right;
    int value;
    double score;
    char name[32];
};

struct Buffer {
    size_t capacity;
    size_t length;
    char *data;
    int flags;
    int refcount;
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

struct Counter {
    long value;
    long step;
};

struct Pair {
    int first;
    int second;
};

struct Matrix4x4 {
    double m[4][4];
};

struct Student {
    int id;
    char name[64];
    double gpa;
    int age;
    char major[32];
};

struct LinkedList {
    struct LinkedList *next;
    int data;
    double priority;
};

struct HashMapEntry {
    uint64_t key;
    uint64_t value;
    struct HashMapEntry *chain;
};

struct SensorReading {
    uint64_t timestamp;
    double temperature;
    double humidity;
    double pressure;
    int sensor_id;
    int status;
};

struct PacketHeader {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t flags;
    uint16_t window_size;
};

struct Task {
    int task_id;
    int priority;
    void (*callback)(void *);
    char description[48];
    double cpu_time;
    int status;
};

struct Config {
    int max_connections;
    int timeout_ms;
    double threshold;
    char log_path[128];
    int verbose;
    int retry_count;
    double backoff_factor;
};

struct Vertex {
    float x;
    float y;
    float z;
    float nx;
    float ny;
    float nz;
    float u;
    float v;
};

struct Edge {
    int from;
    int to;
    double weight;
    int flags;
};

struct Token {
    int type;
    int line;
    int column;
    char text[32];
};

struct Rectangle {
    double x;
    double y;
    double width;
    double height;
};

struct Circle {
    double center_x;
    double center_y;
    double radius;
};

struct Triangle {
    double x1, y1;
    double x2, y2;
    double x3, y3;
};

struct GlobalState {
    int initialized;
    int total_allocs;
    double total_bytes;
    struct Point origin;
    struct Counter counter;
};

struct GlobalState g_state = {
    .initialized = 1,
    .total_allocs = 0,
    .total_bytes = 0.0,
    .origin = {0.0, 0.0, 0.0, 0, 1.0},
    .counter = {0, 1}
};

struct Matrix4x4 g_identity = {
    .m = {
        {1.0, 0.0, 0.0, 0.0},
        {0.0, 1.0, 0.0, 0.0},
        {0.0, 0.0, 1.0, 0.0},
        {0.0, 0.0, 0.0, 1.0}
    }
};

struct PacketHeader g_default_packet = {
    .src_addr = 0x7f000001,
    .dst_addr = 0x7f000001,
    .src_port = 8080,
    .dst_port = 9090,
    .seq_num = 1,
    .ack_num = 0,
    .flags = 0x02,
    .window_size = 65535
};

struct SensorReading g_last_reading = {0};

struct Config g_app_config = {
    .max_connections = 100,
    .timeout_ms = 5000,
    .threshold = 0.85,
    .log_path = "/var/log/memscope.log",
    .verbose = 1,
    .retry_count = 3,
    .backoff_factor = 1.5
};

int g_global_int = 42;
double g_global_double = 3.14159265358979;
char g_global_str[64] = "MemScope Global String";

void test_basic_single_alloc() {
    printf("=== Test 1: Basic Single Object Allocation ===\n");

    struct Point *point = (struct Point*)malloc(sizeof(struct Point));
    struct Node *node = (struct Node*)malloc(sizeof(struct Node));
    struct Buffer *buffer = (struct Buffer*)malloc(sizeof(struct Buffer));
    struct Student *student = (struct Student*)malloc(sizeof(struct Student));
    struct Task *task = (struct Task*)malloc(sizeof(struct Task));

    if (point) {
        point->x = 1.0; point->y = 2.0; point->z = 3.0;
        point->label = 1; point->weight = 1.5;
        printf("  Point @ %p, %zu bytes\n", (void*)point, sizeof(struct Point));
    }
    if (node) {
        node->left = NULL; node->right = NULL;
        node->value = 42; node->score = 3.14;
        strcpy(node->name, "root");
        printf("  Node @ %p, %zu bytes\n", (void*)node, sizeof(struct Node));
    }
    if (buffer) {
        buffer->capacity = 1024; buffer->length = 0;
        buffer->data = NULL; buffer->flags = 0; buffer->refcount = 1;
        printf("  Buffer @ %p, %zu bytes\n", (void*)buffer, sizeof(struct Buffer));
    }
    if (student) {
        student->id = 2024001; strcpy(student->name, "Alice");
        student->gpa = 3.85; student->age = 21;
        strcpy(student->major, "Computer Science");
        printf("  Student @ %p, %zu bytes\n", (void*)student, sizeof(struct Student));
    }
    if (task) {
        task->task_id = 1; task->priority = 10;
        task->callback = NULL; strcpy(task->description, "Initialize");
        task->cpu_time = 0.01; task->status = 0;
        printf("  Task @ %p, %zu bytes\n", (void*)task, sizeof(struct Task));
    }

    free(point);
    free(node);
    free(buffer);
    free(student);
    free(task);
    printf("\n");
}

void test_array_allocations() {
    printf("=== Test 2: Array Allocations (n * sizeof) ===\n");

    struct Point *points = (struct Point*)malloc(5 * sizeof(struct Point));
    struct Node *nodes = (struct Node*)malloc(3 * sizeof(struct Node));
    struct SensorReading *readings = (struct SensorReading*)malloc(10 * sizeof(struct SensorReading));
    struct Edge *edges = (struct Edge*)malloc(20 * sizeof(struct Edge));
    struct Token *tokens = (struct Token*)malloc(100 * sizeof(struct Token));

    if (points) {
        for (int i = 0; i < 5; i++) {
            points[i].x = i * 1.0; points[i].y = i * 2.0; points[i].z = i * 3.0;
            points[i].label = i; points[i].weight = i * 0.5;
        }
        printf("  Points[5] @ %p, 5*%zu = %zu bytes\n", (void*)points, sizeof(struct Point), 5 * sizeof(struct Point));
    }
    if (nodes) {
        for (int i = 0; i < 3; i++) {
            nodes[i].left = NULL; nodes[i].right = NULL;
            nodes[i].value = i; nodes[i].score = i * 1.5;
        }
        printf("  Nodes[3] @ %p, 3*%zu = %zu bytes\n", (void*)nodes, sizeof(struct Node), 3 * sizeof(struct Node));
    }
    if (readings) {
        for (int i = 0; i < 10; i++) {
            readings[i].timestamp = 1000 + i;
            readings[i].temperature = 20.0 + i * 0.5;
            readings[i].humidity = 50.0 + i;
            readings[i].pressure = 1013.25;
            readings[i].sensor_id = i % 4;
            readings[i].status = 0;
        }
        printf("  SensorReading[10] @ %p, 10*%zu = %zu bytes\n",
               (void*)readings, sizeof(struct SensorReading), 10 * sizeof(struct SensorReading));
    }
    if (edges) {
        for (int i = 0; i < 20; i++) {
            edges[i].from = i; edges[i].to = (i + 1) % 20;
            edges[i].weight = i * 0.1; edges[i].flags = 0;
        }
        printf("  Edge[20] @ %p, 20*%zu = %zu bytes\n", (void*)edges, sizeof(struct Edge), 20 * sizeof(struct Edge));
    }
    if (tokens) {
        for (int i = 0; i < 100; i++) {
            tokens[i].type = i % 10; tokens[i].line = i / 10 + 1;
            tokens[i].column = i % 10 + 1; strcpy(tokens[i].text, "tok");
        }
        printf("  Token[100] @ %p, 100*%zu = %zu bytes\n", (void*)tokens, sizeof(struct Token), 100 * sizeof(struct Token));
    }

    free(points);
    free(nodes);
    free(readings);
    free(edges);
    free(tokens);
    printf("\n");
}

void test_calloc_allocations() {
    printf("=== Test 3: Calloc Allocations ===\n");

    struct Vec3 *vectors = (struct Vec3*)calloc(8, sizeof(struct Vec3));
    struct Color *colors = (struct Color*)calloc(12, sizeof(struct Color));
    struct Counter *counters = (struct Counter*)calloc(4, sizeof(struct Counter));
    struct HashMapEntry *entries = (struct HashMapEntry*)calloc(16, sizeof(struct HashMapEntry));
    struct Vertex *vertices = (struct Vertex*)calloc(6, sizeof(struct Vertex));

    if (vectors) {
        for (int i = 0; i < 8; i++) {
            vectors[i].x = 1.0f; vectors[i].y = 2.0f; vectors[i].z = 3.0f;
        }
        printf("  Vec3[8] (calloc) @ %p, 8*%zu = %zu bytes\n", (void*)vectors, sizeof(struct Vec3), 8 * sizeof(struct Vec3));
    }
    if (colors) {
        for (int i = 0; i < 12; i++) {
            colors[i].r = 0.5f; colors[i].g = 0.25f; colors[i].b = 0.75f;
        }
        printf("  Color[12] (calloc) @ %p, 12*%zu = %zu bytes\n", (void*)colors, sizeof(struct Color), 12 * sizeof(struct Color));
    }
    if (counters) {
        for (int i = 0; i < 4; i++) {
            counters[i].value = i * 100; counters[i].step = i + 1;
        }
        printf("  Counter[4] (calloc) @ %p, 4*%zu = %zu bytes\n", (void*)counters, sizeof(struct Counter), 4 * sizeof(struct Counter));
    }
    if (entries) {
        for (int i = 0; i < 16; i++) {
            entries[i].key = i; entries[i].value = i * i; entries[i].chain = NULL;
        }
        printf("  HashMapEntry[16] (calloc) @ %p, 16*%zu = %zu bytes\n",
               (void*)entries, sizeof(struct HashMapEntry), 16 * sizeof(struct HashMapEntry));
    }
    if (vertices) {
        for (int i = 0; i < 6; i++) {
            vertices[i].x = (float)i; vertices[i].y = 0.0f; vertices[i].z = 0.0f;
            vertices[i].nx = 0.0f; vertices[i].ny = 1.0f; vertices[i].nz = 0.0f;
            vertices[i].u = (float)i / 6.0f; vertices[i].v = 0.0f;
        }
        printf("  Vertex[6] (calloc) @ %p, 6*%zu = %zu bytes\n", (void*)vertices, sizeof(struct Vertex), 6 * sizeof(struct Vertex));
    }

    free(vectors);
    free(colors);
    free(counters);
    free(entries);
    free(vertices);
    printf("\n");
}

void test_realloc_grow() {
    printf("=== Test 4: Realloc (Growing) ===\n");

    struct Pair *pairs = (struct Pair*)malloc(sizeof(struct Pair));
    if (pairs) {
        pairs->first = 10; pairs->second = 20;
        printf("  Pair (initial) @ %p, %zu bytes\n", (void*)pairs, sizeof(struct Pair));

        pairs = (struct Pair*)realloc(pairs, 10 * sizeof(struct Pair));
        if (pairs) {
            for (int i = 1; i < 10; i++) {
                pairs[i].first = i * 10; pairs[i].second = i * 20;
            }
            printf("  Pair[10] (realloc) @ %p, 10*%zu = %zu bytes\n",
                   (void*)pairs, sizeof(struct Pair), 10 * sizeof(struct Pair));
        }
    }

    struct SensorReading *readings = (struct SensorReading*)malloc(2 * sizeof(struct SensorReading));
    if (readings) {
        for (int i = 0; i < 2; i++) {
            readings[i].timestamp = i; readings[i].temperature = 20.0;
            readings[i].sensor_id = i;
        }
        printf("  SensorReading[2] (initial) @ %p, 2*%zu = %zu bytes\n",
               (void*)readings, sizeof(struct SensorReading), 2 * sizeof(struct SensorReading));

        readings = (struct SensorReading*)realloc(readings, 50 * sizeof(struct SensorReading));
        if (readings) {
            for (int i = 2; i < 50; i++) {
                readings[i].timestamp = i; readings[i].temperature = 20.0 + i * 0.1;
                readings[i].sensor_id = i % 8;
            }
            printf("  SensorReading[50] (realloc) @ %p, 50*%zu = %zu bytes\n",
                   (void*)readings, sizeof(struct SensorReading), 50 * sizeof(struct SensorReading));
        }
    }

    free(pairs);
    free(readings);
    printf("\n");
}

void test_same_size_disambiguation() {
    printf("=== Test 5: Same-Size Type Disambiguation ===\n");

    struct Vec3 *vec = (struct Vec3*)malloc(sizeof(struct Vec3));
    struct Color *color = (struct Color*)malloc(sizeof(struct Color));

    struct Counter *counter = (struct Counter*)malloc(sizeof(struct Counter));
    struct Pair *pair = (struct Pair*)malloc(sizeof(struct Pair));

    struct Rectangle *rect = (struct Rectangle*)malloc(sizeof(struct Rectangle));
    struct Circle *circ = (struct Circle*)malloc(sizeof(struct Circle));

    printf("  Vec3 (%zuB) vs Color (%zuB) — same size, different types\n", sizeof(struct Vec3), sizeof(struct Color));
    printf("  Counter (%zuB) vs Pair (%zuB) — same size, different types\n", sizeof(struct Counter), sizeof(struct Pair));
    printf("  Rectangle (%zuB) vs Circle (%zuB) — same size, different types\n", sizeof(struct Rectangle), sizeof(struct Circle));

    if (vec) { vec->x = 1.0f; vec->y = 2.0f; vec->z = 3.0f; }
    if (color) { color->r = 0.5f; color->g = 0.25f; color->b = 0.75f; }
    if (counter) { counter->value = 100; counter->step = 1; }
    if (pair) { pair->first = 1; pair->second = 2; }
    if (rect) { rect->x = 0.0; rect->y = 0.0; rect->width = 10.0; rect->height = 20.0; }
    if (circ) { circ->center_x = 5.0; circ->center_y = 5.0; circ->radius = 3.0; }

    free(vec); free(color); free(counter); free(pair); free(rect); free(circ);
    printf("\n");
}

void test_no_cast_allocations() {
    printf("=== Test 6: Allocations Without Cast ===\n");

    struct Point *p1 = malloc(sizeof(struct Point));
    struct Node *n1 = malloc(sizeof(struct Node));
    struct Buffer *b1 = malloc(sizeof(struct Buffer));
    struct Student *s1 = malloc(sizeof(struct Student));
    struct Config *c1 = malloc(sizeof(struct Config));

    if (p1) printf("  Point (no cast) @ %p, %zu bytes\n", (void*)p1, sizeof(struct Point));
    if (n1) printf("  Node (no cast) @ %p, %zu bytes\n", (void*)n1, sizeof(struct Node));
    if (b1) printf("  Buffer (no cast) @ %p, %zu bytes\n", (void*)b1, sizeof(struct Buffer));
    if (s1) printf("  Student (no cast) @ %p, %zu bytes\n", (void*)s1, sizeof(struct Student));
    if (c1) printf("  Config (no cast) @ %p, %zu bytes\n", (void*)c1, sizeof(struct Config));

    free(p1); free(n1); free(b1); free(s1); free(c1);
    printf("\n");
}

void test_variable_count_allocations() {
    printf("=== Test 7: Variable Count / Expression-Based Allocations ===\n");

    int n = 7;
    struct Point *points = (struct Point*)malloc(n * sizeof(struct Point));
    int num_edges = 2 * 10;
    struct Edge *edges = (struct Edge*)malloc(num_edges * sizeof(struct Edge));
    size_t buf_count = 3 + 2;
    struct Buffer *buffers = (struct Buffer*)malloc(buf_count * sizeof(struct Buffer));

    if (points) {
        for (int i = 0; i < n; i++) { points[i].x = i; points[i].y = i; points[i].z = i; }
        printf("  Point[%d] (variable n) @ %p, %d*%zu = %zu bytes\n", n, (void*)points, n, sizeof(struct Point), (size_t)(n * sizeof(struct Point)));
    }
    if (edges) {
        printf("  Edge[%d] (expression) @ %p, %d*%zu = %zu bytes\n", num_edges, (void*)edges, num_edges, sizeof(struct Edge), (size_t)(num_edges * sizeof(struct Edge)));
    }
    if (buffers) {
        printf("  Buffer[%zu] (expression) @ %p, %zu*%zu = %zu bytes\n", buf_count, (void*)buffers, buf_count, sizeof(struct Buffer), buf_count * sizeof(struct Buffer));
    }

    free(points); free(edges); free(buffers);
    printf("\n");
}

void test_linked_structures() {
    printf("=== Test 8: Linked / Nested Structures ===\n");

    struct LinkedList *head = (struct LinkedList*)malloc(sizeof(struct LinkedList));
    struct LinkedList *cur = NULL;
    if (head) {
        head->data = 0; head->priority = 1.0; head->next = NULL;
        cur = head;
        for (int i = 1; i < 5; i++) {
            struct LinkedList *node = (struct LinkedList*)malloc(sizeof(struct LinkedList));
            if (node) {
                node->data = i; node->priority = i * 1.0; node->next = NULL;
                cur->next = node; cur = node;
            }
        }
        printf("  LinkedList (5 nodes) @ %p, each %zu bytes\n", (void*)head, sizeof(struct LinkedList));
    }

    struct HashMapEntry *bucket = (struct HashMapEntry*)calloc(3, sizeof(struct HashMapEntry));
    if (bucket) {
        bucket[0].key = 1; bucket[0].value = 100; bucket[0].chain = &bucket[1];
        bucket[1].key = 2; bucket[1].value = 200; bucket[1].chain = &bucket[2];
        bucket[2].key = 3; bucket[2].value = 300; bucket[2].chain = NULL;
        printf("  HashMapEntry chain (3) @ %p, each %zu bytes\n", (void*)bucket, sizeof(struct HashMapEntry));
    }

    cur = head;
    while (cur) {
        struct LinkedList *next = cur->next;
        free(cur);
        cur = next;
    }
    free(bucket);
    printf("\n");
}

void test_large_array_allocation() {
    printf("=== Test 9: Large Array Allocations ===\n");

    struct Matrix4x4 *matrices = (struct Matrix4x4*)malloc(100 * sizeof(struct Matrix4x4));
    struct PacketHeader *packets = (struct PacketHeader*)malloc(1000 * sizeof(struct PacketHeader));
    struct Vertex *mesh = (struct Vertex*)malloc(500 * sizeof(struct Vertex));

    if (matrices) {
        for (int i = 0; i < 100; i++) {
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < 4; c++)
                    matrices[i].m[r][c] = (r == c) ? 1.0 : 0.0;
        }
        printf("  Matrix4x4[100] @ %p, 100*%zu = %zu bytes\n", (void*)matrices, sizeof(struct Matrix4x4), 100 * sizeof(struct Matrix4x4));
    }
    if (packets) {
        for (int i = 0; i < 1000; i++) {
            packets[i].src_addr = 0x0a000001 + i;
            packets[i].dst_addr = 0x0a000002;
            packets[i].src_port = 1024 + i;
            packets[i].dst_port = 80;
            packets[i].seq_num = i;
            packets[i].ack_num = 0;
            packets[i].flags = 0;
            packets[i].window_size = 65535;
        }
        printf("  PacketHeader[1000] @ %p, 1000*%zu = %zu bytes\n",
               (void*)packets, sizeof(struct PacketHeader), 1000 * sizeof(struct PacketHeader));
    }
    if (mesh) {
        for (int i = 0; i < 500; i++) {
            mesh[i].x = (float)i * 0.01f; mesh[i].y = 0.0f; mesh[i].z = 0.0f;
            mesh[i].nx = 0.0f; mesh[i].ny = 1.0f; mesh[i].nz = 0.0f;
            mesh[i].u = (float)i / 500.0f; mesh[i].v = 0.0f;
        }
        printf("  Vertex[500] @ %p, 500*%zu = %zu bytes\n", (void*)mesh, sizeof(struct Vertex), 500 * sizeof(struct Vertex));
    }

    free(matrices); free(packets); free(mesh);
    printf("\n");
}

void test_mixed_lifecycle() {
    printf("=== Test 10: Mixed Lifecycle (alloc/free interleaved) ===\n");

    struct Point *p1 = (struct Point*)malloc(sizeof(struct Point));
    struct Node *n1 = (struct Node*)malloc(sizeof(struct Node));
    if (p1) { p1->x = 1.0; p1->y = 2.0; p1->z = 3.0; p1->label = 0; p1->weight = 1.0; }
    if (n1) { n1->left = NULL; n1->right = NULL; n1->value = 1; n1->score = 0.0; strcpy(n1->name, "n1"); }

    free(p1);
    printf("  Point freed, Node still alive\n");

    struct Point *p2 = (struct Point*)malloc(sizeof(struct Point));
    if (p2) { p2->x = 10.0; p2->y = 20.0; p2->z = 30.0; p2->label = 1; p2->weight = 2.0; }
    printf("  New Point allocated (may reuse freed address)\n");

    struct Buffer *b1 = (struct Buffer*)malloc(sizeof(struct Buffer));
    if (b1) { b1->capacity = 2048; b1->length = 0; b1->data = NULL; b1->flags = 1; b1->refcount = 1; }

    free(n1);
    free(p2);
    free(b1);
    printf("\n");
}

void test_global_access() {
    printf("=== Test 11: Global Variable Access ===\n");

    printf("  g_state.initialized = %d\n", g_state.initialized);
    printf("  g_state.origin.x = %f\n", g_state.origin.x);
    printf("  g_state.counter.value = %ld\n", g_state.counter.value);
    printf("  g_identity.m[0][0] = %f\n", g_identity.m[0][0]);
    printf("  g_default_packet.src_port = %u\n", g_default_packet.src_port);
    printf("  g_app_config.max_connections = %d\n", g_app_config.max_connections);
    printf("  g_app_config.threshold = %f\n", g_app_config.threshold);
    printf("  g_global_int = %d\n", g_global_int);
    printf("  g_global_double = %.15g\n", g_global_double);
    printf("  g_global_str = \"%s\"\n", g_global_str);

    g_state.counter.value += g_state.counter.step;
    g_last_reading.timestamp = 1000;
    g_last_reading.temperature = 22.5;
    g_last_reading.humidity = 45.0;
    g_last_reading.pressure = 1013.25;
    g_last_reading.sensor_id = 1;
    g_last_reading.status = 0;

    printf("  Updated g_state.counter.value = %ld\n", g_state.counter.value);
    printf("  Updated g_last_reading.temperature = %f\n", g_last_reading.temperature);
    printf("\n");
}

void test_nested_field_access() {
    printf("=== Test 12: Nested Field Access (struct within struct) ===\n");

    struct GlobalState *state = (struct GlobalState*)malloc(sizeof(struct GlobalState));
    if (state) {
        state->initialized = 1;
        state->total_allocs = 100;
        state->total_bytes = 4096.0;
        state->origin.x = 0.0; state->origin.y = 0.0; state->origin.z = 0.0;
        state->origin.label = 0; state->origin.weight = 1.0;
        state->counter.value = 50; state->counter.step = 5;

        printf("  GlobalState @ %p, %zu bytes\n", (void*)state, sizeof(struct GlobalState));
        printf("    state->origin.x = %f (nested Point)\n", state->origin.x);
        printf("    state->counter.value = %ld (nested Counter)\n", state->counter.value);
    }

    free(state);
    printf("\n");
}

void test_multi_same_type_in_func() {
    printf("=== Test 13: Multiple Same-Type Pointers in One Function ===\n");

    struct Point *origin = (struct Point*)malloc(sizeof(struct Point));
    struct Point *dest = (struct Point*)malloc(sizeof(struct Point));
    struct Point *waypoint = (struct Point*)malloc(sizeof(struct Point));

    if (origin) { origin->x = 0.0; origin->y = 0.0; origin->z = 0.0; origin->label = 0; origin->weight = 0.0; }
    if (dest) { dest->x = 100.0; dest->y = 200.0; dest->z = 300.0; dest->label = 1; dest->weight = 1.0; }
    if (waypoint) { waypoint->x = 50.0; waypoint->y = 100.0; waypoint->z = 150.0; waypoint->label = 2; waypoint->weight = 0.5; }

    printf("  origin @ %p, dest @ %p, waypoint @ %p (all struct Point*)\n", (void*)origin, (void*)dest, (void*)waypoint);

    free(origin); free(dest); free(waypoint);
    printf("\n");
}

void test_untyped_alloc() {
    printf("=== Test 14: Untyped / Raw Byte Allocations ===\n");

    void *raw = malloc(256);
    char *raw_buf = (char*)malloc(1024);
    unsigned char *raw_uchar = (unsigned char*)malloc(512);

    printf("  void* raw @ %p, 256 bytes\n", raw);
    printf("  char* raw_buf @ %p, 1024 bytes\n", (void*)raw_buf);
    printf("  unsigned char* raw_uchar @ %p, 512 bytes\n", (void*)raw_uchar);

    free(raw); free(raw_buf); free(raw_uchar);
    printf("\n");
}

void test_persistent_allocations() {
    printf("=== Test 15: Persistent (Never Freed) Allocations ===\n");

    struct Config *cfg = (struct Config*)malloc(sizeof(struct Config));
    struct Student *record = (struct Student*)malloc(sizeof(struct Student));

    if (cfg) {
        *cfg = g_app_config;
        printf("  Config (persistent) @ %p, %zu bytes\n", (void*)cfg, sizeof(struct Config));
    }
    if (record) {
        record->id = 999; strcpy(record->name, "Persistent"); record->gpa = 4.0;
        record->age = 30; strcpy(record->major, "Physics");
        printf("  Student (persistent) @ %p, %zu bytes\n", (void*)record, sizeof(struct Student));
    }

    printf("  (These allocations are intentionally NOT freed for leak detection testing)\n");
    printf("\n");
}

struct ThreadArg {
    int thread_id;
    int alloc_count;
    struct Point **results;
};

void *thread_func(void *arg) {
    struct ThreadArg *ta = (struct ThreadArg*)arg;
    ta->results = (struct Point**)malloc(ta->alloc_count * sizeof(struct Point*));

    for (int i = 0; i < ta->alloc_count; i++) {
        ta->results[i] = (struct Point*)malloc(sizeof(struct Point));
        if (ta->results[i]) {
            ta->results[i]->x = ta->thread_id * 100.0 + i;
            ta->results[i]->y = ta->thread_id * 200.0 + i;
            ta->results[i]->z = ta->thread_id * 300.0 + i;
            ta->results[i]->label = ta->thread_id;
            ta->results[i]->weight = i * 0.1;
        }
    }

    printf("  Thread %d: allocated %d Points\n", ta->thread_id, ta->alloc_count);

    for (int i = 0; i < ta->alloc_count; i++) {
        free(ta->results[i]);
    }
    free(ta->results);

    return NULL;
}

void test_multithread_allocations() {
    printf("=== Test 16: Multi-Threaded Allocations ===\n");

    pthread_t threads[4];
    struct ThreadArg args[4];

    for (int i = 0; i < 4; i++) {
        args[i].thread_id = i;
        args[i].alloc_count = 5;
        args[i].results = NULL;
        pthread_create(&threads[i], NULL, thread_func, &args[i]);
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("  All threads completed\n\n");
}

void test_size_ambiguous_pairs() {
    printf("=== Test 17: Size-Ambiguous Pairs (stress test for typename matching) ===\n");

    struct Vec3 *v1 = (struct Vec3*)malloc(sizeof(struct Vec3));
    struct Color *c1 = (struct Color*)malloc(sizeof(struct Color));
    struct Vec3 *v2 = (struct Vec3*)malloc(sizeof(struct Vec3));
    struct Color *c2 = (struct Color*)malloc(sizeof(struct Color));

    struct Counter *cnt1 = (struct Counter*)malloc(sizeof(struct Counter));
    struct Pair *pr1 = (struct Pair*)malloc(sizeof(struct Pair));
    struct Counter *cnt2 = (struct Counter*)malloc(sizeof(struct Counter));
    struct Pair *pr2 = (struct Pair*)malloc(sizeof(struct Pair));

    struct Rectangle *r1 = (struct Rectangle*)malloc(sizeof(struct Rectangle));
    struct Circle *ci1 = (struct Circle*)malloc(sizeof(struct Circle));

    struct Triangle *t1 = (struct Triangle*)malloc(sizeof(struct Triangle));

    printf("  Vec3 (%zuB) x2, Color (%zuB) x2 — interleaved same-size\n", sizeof(struct Vec3), sizeof(struct Color));
    printf("  Counter (%zuB) x2, Pair (%zuB) x2 — interleaved same-size\n", sizeof(struct Counter), sizeof(struct Pair));
    printf("  Rectangle (%zuB), Circle (%zuB), Triangle (%zuB)\n",
           sizeof(struct Rectangle), sizeof(struct Circle), sizeof(struct Triangle));

    free(v1); free(c1); free(v2); free(c2);
    free(cnt1); free(pr1); free(cnt2); free(pr2);
    free(r1); free(ci1); free(t1);
    printf("\n");
}

void test_array_of_same_size_types() {
    printf("=== Test 18: Arrays of Same-Size Types ===\n");

    struct Vec3 *vecs = (struct Vec3*)malloc(10 * sizeof(struct Vec3));
    struct Color *cols = (struct Color*)malloc(10 * sizeof(struct Color));

    if (vecs) {
        for (int i = 0; i < 10; i++) { vecs[i].x = 1.0f; vecs[i].y = 0.0f; vecs[i].z = 0.0f; }
        printf("  Vec3[10] @ %p, 10*%zu = %zu bytes\n", (void*)vecs, sizeof(struct Vec3), 10 * sizeof(struct Vec3));
    }
    if (cols) {
        for (int i = 0; i < 10; i++) { cols[i].r = 1.0f; cols[i].g = 0.0f; cols[i].b = 0.0f; }
        printf("  Color[10] @ %p, 10*%zu = %zu bytes\n", (void*)cols, sizeof(struct Color), 10 * sizeof(struct Color));
    }

    printf("  Both arrays have same total size (%zu vs %zu) — typename must distinguish\n",
           10 * sizeof(struct Vec3), 10 * sizeof(struct Color));

    free(vecs); free(cols);
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("MemScope V2 Benchmark — Comprehensive Type Inference Test\n");
    printf("==========================================================\n");
    printf("PID: %d\n\n", getpid());

    int iterations = 1;
    if (argc > 2) {
        iterations = atoi(argv[2]);
    }

    if (argc > 1) {
        int test_num = atoi(argv[1]);
        for (int i = 0; i < iterations; i++) {
            switch (test_num) {
                case 1:  test_basic_single_alloc(); break;
                case 2:  test_array_allocations(); break;
                case 3:  test_calloc_allocations(); break;
                case 4:  test_realloc_grow(); break;
                case 5:  test_same_size_disambiguation(); break;
                case 6:  test_no_cast_allocations(); break;
                case 7:  test_variable_count_allocations(); break;
                case 8:  test_linked_structures(); break;
                case 9:  test_large_array_allocation(); break;
                case 10: test_mixed_lifecycle(); break;
                case 11: test_global_access(); break;
                case 12: test_nested_field_access(); break;
                case 13: test_multi_same_type_in_func(); break;
                case 14: test_untyped_alloc(); break;
                case 15: test_persistent_allocations(); break;
                case 16: test_multithread_allocations(); break;
                case 17: test_size_ambiguous_pairs(); break;
                case 18: test_array_of_same_size_types(); break;
                default:
                    printf("Unknown test number: %d\n", test_num);
                    return 1;
            }
        }
    } else {
        test_basic_single_alloc();
        test_array_allocations();
        test_calloc_allocations();
        test_realloc_grow();
        test_same_size_disambiguation();
        test_no_cast_allocations();
        test_variable_count_allocations();
        test_linked_structures();
        test_large_array_allocation();
        test_mixed_lifecycle();
        test_global_access();
        test_nested_field_access();
        test_multi_same_type_in_func();
        test_untyped_alloc();
        test_persistent_allocations();
        test_multithread_allocations();
        test_size_ambiguous_pairs();
        test_array_of_same_size_types();
    }

    printf("V2 Benchmark complete.\n");
    return 0;
}
