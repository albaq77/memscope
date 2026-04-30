#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ComplexType {
    char     tag;
    int      id;
    double   values[4];
    char     name[32];
    void    *next;
    unsigned flags;
};

struct Container {
    struct ComplexType items[8];
    int                count;
    int                capacity;
    long               total_size;
};

int main(void)
{
    struct Container *c = (struct Container *)malloc(sizeof(struct Container));
    if (!c) return 1;

    c->count = 0;
    c->capacity = 8;
    c->total_size = 0;

    for (int i = 0; i < 4; i++) {
        c->items[i].tag = 'A' + i;
        c->items[i].id = i * 100;
        for (int j = 0; j < 4; j++)
            c->items[i].values[j] = (double)(i * 4 + j) * 0.5;
        snprintf(c->items[i].name, sizeof(c->items[i].name), "item_%d", i);
        c->items[i].next = (i < 3) ? &c->items[i + 1] : NULL;
        c->items[i].flags = (unsigned)i;
        c->count++;
    }

    printf("Container at %p (size=%zu)\n", (void *)c, sizeof(struct Container));
    printf("ComplexType size=%zu\n", sizeof(struct ComplexType));

    printf("\nField resolution test addresses:\n");
    printf("  Container.count at offset %zu: addr=%p\n",
           offsetof(struct Container, count), (void *)&c->count);
    printf("  Container.items[2].values[3] at offset %zu: addr=%p\n",
           ((char *)&c->items[2].values[3] - (char *)c),
           (void *)&c->items[2].values[3]);
    printf("  Container.items[0].name at offset %zu: addr=%p\n",
           ((char *)&c->items[0].name - (char *)c),
           (void *)&c->items[0].name);

    volatile double val = c->items[2].values[3];
    (void)val;

    free(c);
    printf("\nField resolution test complete.\n");
    return 0;
}
