#include "custom_allocator.h"

#include "3rdparty/tinyalloc/tinyalloc/tinyalloc.h"

void* custom_calloc(size_t n, size_t size) {
    return ta_calloc(n, size);
}

void custom_free(void* ptr) {
    ta_free(ptr);
}
