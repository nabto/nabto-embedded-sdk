#ifndef _NP_VECTOR_H_
#define _NP_VECTOR_H_

#include <string.h>
#include <platform/np_error_code.h>

#include <platform/np_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*np_vector_element_free)(void* element);

struct np_vector {
    np_vector_element_free freeFunction; // function called on each element if deinitialized with elements.
    void** elements;
    size_t capacity;
    size_t used;
};

np_error_code np_vector_init(struct np_vector* vector, np_vector_element_free freeFunction);

void np_vector_deinit(struct np_vector* vector);

np_error_code np_vector_push_back(struct np_vector* vector, void* element);

bool np_vector_empty(struct np_vector* vector);
size_t np_vector_size(struct np_vector* vector);
void* np_vector_get(struct np_vector* vector, size_t index);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
