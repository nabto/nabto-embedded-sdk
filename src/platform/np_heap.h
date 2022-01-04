#ifndef _NP_HEAP_H_
#define _NP_HEAP_H_

#include <nn/allocator.h>

#include <stddef.h>


// like calloc, allocate an area of n*size return a pointer to the first byte.
// or NULL if allocation failed.
void* np_calloc(size_t n, size_t size);

// free memory allocated by np_calloc.
void np_free(void* ptr);

void np_set_default_allocator(struct nn_allocator* allocator);

struct nn_allocator* np_get_default_allocator();

#endif
