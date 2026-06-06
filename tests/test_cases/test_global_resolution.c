#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

struct Inner {
    int a;
    double b;
    char c;
};

struct Outer {
    int id;
    struct Inner inner;
    double values[4];
    char name[32];
};

struct Flat {
    uint64_t x;
    uint64_t y;
    uint64_t z;
};

struct Mixed {
    float f;
    int i;
    short s;
    char pad[2];
    double d;
};

struct PtrHolder {
    int *p_int;
    double *p_double;
    void *p_void;
};

struct Large {
    double matrix[4][4];
    int flags[8];
    char buffer[128];
};

int g_simple_int = 42;
double g_simple_double = 3.14159265358979;
char g_simple_char = 'X';

struct Inner g_inner = { .a = 10, .b = 2.71828, .c = 'I' };

struct Outer g_outer = {
    .id = 1,
    .inner = { .a = 20, .b = 1.41421, .c = 'O' },
    .values = { 1.0, 2.0, 3.0, 4.0 },
    .name = "OuterGlobal"
};

struct Flat g_flat = { .x = 100, .y = 200, .z = 300 };

struct Mixed g_mixed = { .f = 1.5f, .i = 99, .s = 16, .pad = {0, 0}, .d = 6.626e-34 };

struct PtrHolder g_ptr_holder = { .p_int = NULL, .p_double = NULL, .p_void = NULL };

struct Large g_large = {0};

int g_int_array[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
double g_double_array[4] = { 0.1, 0.2, 0.3, 0.4 };

static int g_static_int = -1;
static struct Inner g_static_inner = { .a = 30, .b = 0.57721, .c = 'S' };

#define PRINT_ADDR(label, ptr) printf("ADDR:%s=%p\n", label, (void*)(ptr))

int main(int argc, char **argv)
{
    printf("=== Global Resolution Test ===\n\n");

    PRINT_ADDR("g_simple_int",    &g_simple_int);
    PRINT_ADDR("g_simple_double", &g_simple_double);
    PRINT_ADDR("g_simple_char",   &g_simple_char);

    PRINT_ADDR("g_inner",         &g_inner);
    PRINT_ADDR("g_inner.a",       &g_inner.a);
    PRINT_ADDR("g_inner.b",       &g_inner.b);
    PRINT_ADDR("g_inner.c",       &g_inner.c);

    PRINT_ADDR("g_outer",         &g_outer);
    PRINT_ADDR("g_outer.id",      &g_outer.id);
    PRINT_ADDR("g_outer.inner",   &g_outer.inner);
    PRINT_ADDR("g_outer.inner.a", &g_outer.inner.a);
    PRINT_ADDR("g_outer.inner.b", &g_outer.inner.b);
    PRINT_ADDR("g_outer.inner.c", &g_outer.inner.c);
    PRINT_ADDR("g_outer.values",  &g_outer.values);
    PRINT_ADDR("g_outer.values[0]", &g_outer.values[0]);
    PRINT_ADDR("g_outer.values[3]", &g_outer.values[3]);
    PRINT_ADDR("g_outer.name",    &g_outer.name);

    PRINT_ADDR("g_flat",          &g_flat);
    PRINT_ADDR("g_flat.x",        &g_flat.x);
    PRINT_ADDR("g_flat.y",        &g_flat.y);
    PRINT_ADDR("g_flat.z",        &g_flat.z);

    PRINT_ADDR("g_mixed",         &g_mixed);
    PRINT_ADDR("g_mixed.f",       &g_mixed.f);
    PRINT_ADDR("g_mixed.i",       &g_mixed.i);
    PRINT_ADDR("g_mixed.s",       &g_mixed.s);
    PRINT_ADDR("g_mixed.d",       &g_mixed.d);

    PRINT_ADDR("g_ptr_holder",    &g_ptr_holder);
    PRINT_ADDR("g_ptr_holder.p_int",    &g_ptr_holder.p_int);
    PRINT_ADDR("g_ptr_holder.p_double", &g_ptr_holder.p_double);
    PRINT_ADDR("g_ptr_holder.p_void",   &g_ptr_holder.p_void);

    PRINT_ADDR("g_large",         &g_large);

    PRINT_ADDR("g_int_array",     &g_int_array);
    PRINT_ADDR("g_double_array",  &g_double_array);

    PRINT_ADDR("g_static_int",    &g_static_int);
    PRINT_ADDR("g_static_inner",  &g_static_inner);
    PRINT_ADDR("g_static_inner.a",&g_static_inner.a);
    PRINT_ADDR("g_static_inner.b",&g_static_inner.b);
    PRINT_ADDR("g_static_inner.c",&g_static_inner.c);

    printf("\n");
    printf("g_simple_int    = %d\n", g_simple_int);
    printf("g_simple_double = %.15g\n", g_simple_double);
    printf("g_simple_char   = '%c'\n", g_simple_char);
    printf("g_inner: .a=%d .b=%.5f .c='%c'\n", g_inner.a, g_inner.b, g_inner.c);
    printf("g_outer: .id=%d .inner.a=%d .inner.b=%.5f .inner.c='%c' .values[0]=%.1f .values[3]=%.1f .name=\"%s\"\n",
           g_outer.id, g_outer.inner.a, g_outer.inner.b, g_outer.inner.c,
           g_outer.values[0], g_outer.values[3], g_outer.name);
    printf("g_flat: .x=%lu .y=%lu .z=%lu\n", g_flat.x, g_flat.y, g_flat.z);
    printf("g_mixed: .f=%.1f .i=%d .s=%d .d=%.3e\n", g_mixed.f, g_mixed.i, g_mixed.s, g_mixed.d);
    printf("g_static_int = %d\n", g_static_int);
    printf("g_static_inner: .a=%d .b=%.5f .c='%c'\n",
           g_static_inner.a, g_static_inner.b, g_static_inner.c);

    printf("\n=== Test Complete ===\n");
    return 0;
}
