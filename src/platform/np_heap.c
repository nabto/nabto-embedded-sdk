#include "np_heap.h"

#include <nn/allocator.h>

#include <stdlib.h>


static struct nn_allocator allocator = {
    .calloc = calloc,
    .free = free
};

void* np_calloc(size_t n, size_t size) {
    return allocator.calloc(n, size);
}

void np_free(void* ptr) {
    allocator.free(ptr);
}

struct nn_allocator* np_get_default_allocator() {
    return &allocator;
}

void np_set_default_allocator(struct nn_allocator* a) {
    allocator = *a;
}
