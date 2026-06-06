#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

void test_basic_allocations() {
    printf("=== Test 1: Basic Allocations ===\n");
    
    struct Point *point = (struct Point*)malloc(sizeof(struct Point));
    struct Node *node = (struct Node*)malloc(sizeof(struct Node));
    struct Buffer *buffer = (struct Buffer*)malloc(sizeof(struct Buffer));
    
    if (point) {
        point->x = 1.0;
        point->y = 2.0;
        point->z = 3.0;
        point->label = 1;
        point->weight = 1.5;
        printf("Point allocated: %zu bytes\n", sizeof(struct Point));
    }
    
    if (node) {
        node->left = NULL;
        node->right = NULL;
        node->value = 42;
        node->score = 3.14;
        printf("Node allocated: %zu bytes\n", sizeof(struct Node));
    }
    
    if (buffer) {
        buffer->capacity = 1024;
        buffer->length = 0;
        buffer->data = NULL;
        buffer->flags = 0;
        buffer->refcount = 1;
        printf("Buffer allocated: %zu bytes\n", sizeof(struct Buffer));
    }
    
    free(point);
    free(node);
    free(buffer);
    printf("\n");
    usleep(1000);
}

void test_array_allocations() {
    printf("=== Test 2: Array Allocations ===\n");
    
    struct Point *points = (struct Point*)malloc(5 * sizeof(struct Point));
    struct Node *nodes = (struct Node*)malloc(3 * sizeof(struct Node));
    struct Buffer *buffers = (struct Buffer*)malloc(10 * sizeof(struct Buffer));
    
    if (points) {
        for (int i = 0; i < 5; i++) {
            points[i].x = i * 1.0;
            points[i].y = i * 2.0;
            points[i].z = i * 3.0;
        }
        printf("Points array: 5 * %zu = %zu bytes\n", sizeof(struct Point), 5 * sizeof(struct Point));
    }
    
    if (nodes) {
        for (int i = 0; i < 3; i++) {
            nodes[i].value = i;
            nodes[i].score = i * 1.5;
        }
        printf("Nodes array: 3 * %zu = %zu bytes\n", sizeof(struct Node), 3 * sizeof(struct Node));
    }
    
    if (buffers) {
        printf("Buffers array: 10 * %zu = %zu bytes\n", sizeof(struct Buffer), 10 * sizeof(struct Buffer));
    }
    
    free(points);
    free(nodes);
    free(buffers);
    printf("\n");
}

void test_calloc_allocations() {
    printf("=== Test 3: Calloc Allocations ===\n");
    
    struct Vec3 *vectors = (struct Vec3*)calloc(4, sizeof(struct Vec3));
    struct Color *colors = (struct Color*)calloc(6, sizeof(struct Color));
    struct Counter *counters = (struct Counter*)calloc(2, sizeof(struct Counter));
    
    if (vectors) {
        for (int i = 0; i < 4; i++) {
            vectors[i].x = 1.0f;
            vectors[i].y = 2.0f;
            vectors[i].z = 3.0f;
        }
        printf("Vec3 array (calloc): 4 * %zu = %zu bytes\n", sizeof(struct Vec3), 4 * sizeof(struct Vec3));
    }
    
    if (colors) {
        for (int i = 0; i < 6; i++) {
            colors[i].r = 0.5f;
            colors[i].g = 0.25f;
            colors[i].b = 0.75f;
        }
        printf("Color array (calloc): 6 * %zu = %zu bytes\n", sizeof(struct Color), 6 * sizeof(struct Color));
    }
    
    if (counters) {
        counters[0].value = 100;
        counters[0].step = 1;
        counters[1].value = 200;
        counters[1].step = 2;
        printf("Counter array (calloc): 2 * %zu = %zu bytes\n", sizeof(struct Counter), 2 * sizeof(struct Counter));
    }
    
    free(vectors);
    free(colors);
    free(counters);
    printf("\n");
}

void test_realloc_allocations() {
    printf("=== Test 4: Realloc Allocations ===\n");
    
    struct Pair *pairs = (struct Pair*)malloc(sizeof(struct Pair));
    if (pairs) {
        pairs->first = 10;
        pairs->second = 20;
        printf("Initial Pair: %zu bytes\n", sizeof(struct Pair));
        
        pairs = (struct Pair*)realloc(pairs, 5 * sizeof(struct Pair));
        if (pairs) {
            for (int i = 1; i < 5; i++) {
                pairs[i].first = i * 10;
                pairs[i].second = i * 20;
            }
            printf("Reallocated Pair array: 5 * %zu = %zu bytes\n", sizeof(struct Pair), 5 * sizeof(struct Pair));
        }
    }
    
    struct Vec3 *vec = (struct Vec3*)malloc(sizeof(struct Vec3));
    if (vec) {
        vec->x = 1.0f;
        vec->y = 2.0f;
        vec->z = 3.0f;
        printf("Initial Vec3: %zu bytes\n", sizeof(struct Vec3));
        
        vec = (struct Vec3*)realloc(vec, 3 * sizeof(struct Vec3));
        if (vec) {
            vec[1].x = 4.0f;
            vec[1].y = 5.0f;
            vec[1].z = 6.0f;
            vec[2].x = 7.0f;
            vec[2].y = 8.0f;
            vec[2].z = 9.0f;
            printf("Reallocated Vec3 array: 3 * %zu = %zu bytes\n", sizeof(struct Vec3), 3 * sizeof(struct Vec3));
        }
    }
    
    free(pairs);
    free(vec);
    printf("\n");
}

void test_same_size_types() {
    printf("=== Test 5: Same Size Types (Type Inference Challenge) ===\n");
    
    struct Vec3 *vec = (struct Vec3*)malloc(sizeof(struct Vec3));
    struct Color *color = (struct Color*)malloc(sizeof(struct Color));
    
    struct Counter *counter = (struct Counter*)malloc(sizeof(struct Counter));
    struct Pair *pair = (struct Pair*)malloc(sizeof(struct Pair));
    
    if (vec && color) {
        printf("Vec3 size: %zu bytes\n", sizeof(struct Vec3));
        printf("Color size: %zu bytes\n", sizeof(struct Color));
        printf("Both are 12 bytes - should be distinguished by source text analysis\n");
    }
    
    if (counter && pair) {
        printf("Counter size: %zu bytes\n", sizeof(struct Counter));
        printf("Pair size: %zu bytes\n", sizeof(struct Pair));
        printf("Both are 8 bytes - should be distinguished by source text analysis\n");
    }
    
    free(vec);
    free(color);
    free(counter);
    free(pair);
    printf("\n");
}

void test_no_cast_allocations() {
    printf("=== Test 6: Allocations Without Cast ===\n");
    
    struct Point *p1 = malloc(sizeof(struct Point));
    struct Node *n1 = malloc(sizeof(struct Node));
    struct Buffer *b1 = malloc(sizeof(struct Buffer));
    
    if (p1) {
        printf("Point (no cast): %zu bytes\n", sizeof(struct Point));
    }
    if (n1) {
        printf("Node (no cast): %zu bytes\n", sizeof(struct Node));
    }
    if (b1) {
        printf("Buffer (no cast): %zu bytes\n", sizeof(struct Buffer));
    }
    
    free(p1);
    free(n1);
    free(b1);
    printf("\n");
}

void test_complex_expressions() {
    printf("=== Test 7: Complex Expressions ===\n");
    
    int count = 5;
    struct Point *points = (struct Point*)malloc(count * sizeof(struct Point));
    
    if (points) {
        printf("Points (variable count): %d * %zu = %zu bytes\n", 
               count, sizeof(struct Point), count * sizeof(struct Point));
    }
    
    struct Node *nodes = (struct Node*)malloc((2 + 3) * sizeof(struct Node));
    if (nodes) {
        printf("Nodes (expression): (2+3) * %zu = %zu bytes\n", 
               sizeof(struct Node), (2 + 3) * sizeof(struct Node));
    }
    
    free(points);
    free(nodes);
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("MemScope Simple Benchmark\n");
    printf("=========================\n");
    printf("PID: %d\n\n", getpid());
    
    int iterations = 1;
    if (argc > 2) {
        iterations = atoi(argv[2]);
    }
    
    if (argc > 1) {
        int test_num = atoi(argv[1]);
        for (int i = 0; i < iterations; i++) {
            switch (test_num) {
                case 1: test_basic_allocations(); break;
                case 2: test_array_allocations(); break;
                case 3: test_calloc_allocations(); break;
                case 4: test_realloc_allocations(); break;
                case 5: test_same_size_types(); break;
                case 6: test_no_cast_allocations(); break;
                case 7: test_complex_expressions(); break;
                default:
                    printf("Unknown test number: %d\n", test_num);
                    return 1;
            }
        }
    } else {
        test_basic_allocations();
        test_array_allocations();
        test_calloc_allocations();
        test_realloc_allocations();
        test_same_size_types();
        test_no_cast_allocations();
        test_complex_expressions();
    }
    
    printf("Benchmark complete.\n");
    return 0;
}
