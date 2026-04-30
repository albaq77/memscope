#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define NUM_ALLOCS 1000
#define NUM_SIZES 5

static size_t test_sizes[NUM_SIZES] = {16, 64, 256, 1024, 4096};

int main(void)
{
    void *ptrs[NUM_ALLOCS];
    int   sizes_idx[NUM_ALLOCS];

    printf("Allocation tracking test (PID=%d)\n", getpid());

    for (int round = 0; round < 10; round++) {
        for (int i = 0; i < NUM_ALLOCS; i++) {
            sizes_idx[i] = i % NUM_SIZES;
            ptrs[i] = malloc(test_sizes[sizes_idx[i]]);
            if (!ptrs[i]) {
                fprintf(stderr, "malloc failed at i=%d\n", i);
                return 1;
            }
            memset(ptrs[i], 0xAA, test_sizes[sizes_idx[i]]);
        }

        for (int i = 0; i < NUM_ALLOCS; i++) {
            free(ptrs[i]);
        }
    }

    void *leaked = malloc(128);
    (void)leaked;

    printf("Allocation tracking test complete.\n");
    printf("Intentionally leaked 128 bytes at %p\n", leaked);
    return 0;
}
