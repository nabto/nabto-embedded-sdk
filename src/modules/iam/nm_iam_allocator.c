#include "nm_iam_allocator.h"

#include <stdlib.h>

void nm_iam_free(void* ptr)
{
    free(ptr);
}

void* nm_iam_calloc(size_t n, size_t size)
{
    return calloc(n, size);
}

static struct nn_allocator defaultAllocator = {
    .free = nm_iam_free,
    .calloc = nm_iam_calloc
};

struct nn_allocator* nm_iam_allocator_get(void)
{
    return &defaultAllocator;
}
