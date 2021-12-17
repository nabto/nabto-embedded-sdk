#include "np_heap.h"

#include <stdlib.h>

void* np_calloc(size_t n, size_t size) {
    return calloc(n, size);
}

void np_free(void* ptr) {
    free(ptr);
}
