#include "np_vector.h"

#include "np_error_code.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

np_error_code np_vector_init(struct np_vector* vector, np_vector_element_free freeFunction)
{
    vector->freeFunction = freeFunction;
    vector->elements = malloc(1*sizeof(void*));
    if (vector->elements == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    vector->capacity = 1;
    vector->used = 0;
    return NABTO_EC_OK;
}


void np_vector_deinit(struct np_vector* vector)
{
    size_t i;
    for (i = 0; i < vector->used; i++) {
        if (vector->freeFunction != NULL) {
            vector->freeFunction(vector->elements[i]);
        }
    }
    free(vector->elements);
}

np_error_code np_vector_push_back(struct np_vector* vector, void* element)
{
    if (vector->used == vector->capacity) {
        size_t newCapacity = vector->capacity*2;
        void** newElements = malloc(newCapacity*sizeof(void*));
        if (newElements == NULL) {
            return NABTO_EC_OUT_OF_MEMORY;
        }
        memcpy(newElements, vector->elements, (vector->capacity * sizeof(void*)));
        free(vector->elements);
        vector->elements = newElements;
        vector->capacity = newCapacity;
    }
    vector->elements[vector->used] = element;
    vector->used += 1;
    return NABTO_EC_OK;
}

bool np_vector_empty(struct np_vector* vector)
{
    return vector->used == 0;
}

size_t np_vector_size(struct np_vector* vector)
{
    return vector->used;
}

void* np_vector_get(struct np_vector* vector, size_t index)
{
    if (index < vector->used) {
        return vector->elements[index];
    } else {
        return NULL;
    }
}

void np_vector_erase(struct np_vector* vector, size_t index)
{
    if (index < vector->used) {
        // eg. used = 2, remove index 1 aka last element,
        // used -= 1; used(1) - index(1) = 0
        vector->used -= 1;
        size_t after = vector->used - index;
        memmove(&vector->elements[index], &vector->elements[index+1], sizeof(void*)*after);
    }
}
