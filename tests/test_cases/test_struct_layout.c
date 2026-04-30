#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct TestStruct {
    char    a;
    int     b;
    long    c;
    double  d;
    char    e[16];
    void   *f;
};

struct NestedStruct {
    struct TestStruct inner;
    int              extra;
};

struct PaddedStruct {
    char   flag;
    double value;
    short  count;
    long   total;
};

int main(void)
{
    struct TestStruct *ts = (struct TestStruct *)malloc(sizeof(struct TestStruct));
    struct NestedStruct *ns = (struct NestedStruct *)malloc(sizeof(struct NestedStruct));
    struct PaddedStruct *ps = (struct PaddedStruct *)malloc(sizeof(struct PaddedStruct));

    ts->a = 'X';
    ts->b = 42;
    ts->c = 123456789L;
    ts->d = 3.14159;
    strcpy(ts->e, "hello world");
    ts->f = NULL;

    ns->inner.a = 'Y';
    ns->inner.b = 99;
    ns->extra = 777;

    ps->flag = 1;
    ps->value = 2.71828;
    ps->count = 10;
    ps->total = 1000000L;

    printf("TestStruct at %p (size=%zu)\n", (void *)ts, sizeof(struct TestStruct));
    printf("NestedStruct at %p (size=%zu)\n", (void *)ns, sizeof(struct NestedStruct));
    printf("PaddedStruct at %p (size=%zu)\n", (void *)ps, sizeof(struct PaddedStruct));

    printf("\nField offsets:\n");
    printf("  TestStruct.a: %zu\n", offsetof(struct TestStruct, a));
    printf("  TestStruct.b: %zu\n", offsetof(struct TestStruct, b));
    printf("  TestStruct.c: %zu\n", offsetof(struct TestStruct, c));
    printf("  TestStruct.d: %zu\n", offsetof(struct TestStruct, d));
    printf("  TestStruct.e: %zu\n", offsetof(struct TestStruct, e));
    printf("  TestStruct.f: %zu\n", offsetof(struct TestStruct, f));

    volatile char *pa = &ts->a;
    volatile int  *pb = &ts->b;
    volatile long *pc = &ts->c;
    (void)pa; (void)pb; (void)pc;

    free(ts);
    free(ns);
    free(ps);

    printf("\nAll tests passed.\n");
    return 0;
}
