#ifndef _NP_HEAP_H_
#define _NP_HEAP_H_

#include <nn/allocator.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// like calloc, allocate an area of n*size return a pointer to the first byte.
// or NULL if allocation failed.
void* np_calloc(size_t n, size_t size);

// free memory allocated by np_calloc.
void np_free(void* ptr);

/**
 * Set the allocator
 */
void np_allocator_set(struct nn_allocator* allocator);

/**
 * Get the allocator
 */
struct nn_allocator* np_allocator_get();


#ifdef __cplusplus
} //extern "C"
#endif


#endif
