#include "np_allocator.h"

#include <nn/allocator.h>

#include <stdlib.h>


static void* calloc_impl(size_t n , size_t size) {
    return calloc(n, size);
}

static void free_impl(void* ptr) {
    free(ptr);
}

static struct nn_allocator allocator = {
    .calloc = calloc_impl,
    .free = free_impl
};

void* np_calloc(size_t n, size_t size) {
    return allocator.calloc(n, size);
}

void np_free(void* ptr) {
    allocator.free(ptr);
}

struct nn_allocator* np_allocator_get() {
    return &allocator;
}

void np_allocator_set(struct nn_allocator* a) {
    allocator = *a;
}
