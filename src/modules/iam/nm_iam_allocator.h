#ifndef NM_IAM_ALLOCATOR_H_
#define NM_IAM_ALLOCATOR_H_

#include <stddef.h>

#include <nn/allocator.h>

struct nn_allocator* nm_iam_allocator_get();

void* nm_iam_calloc(size_t n, size_t size);
void nm_iam_free(void* ptr);


#endif
