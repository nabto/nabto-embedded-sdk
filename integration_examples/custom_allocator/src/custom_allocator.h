#ifndef _CUSTOM_ALLOCATOR_H_
#define _CUSTOM_ALLOCATOR_H_

#include <string.h>

void* custom_calloc(size_t n, size_t size);

void custom_free(void* ptr);

#endif
