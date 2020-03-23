#include "np_vector.h"

#include "np_error_code.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

void np_vector_init(struct np_vector* vector, np_vector_element_free freeFunction)
{
    vector->freeFunction = freeFunction;
    vector->elements = NULL;
    vector->capacity = 0;
    vector->used = 0;
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
        if (newCapacity == 0) {
            newCapacity = 1;
        }
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

bool np_vector_empty(const struct np_vector* vector)
{
    return vector->used == 0;
}

size_t np_vector_size(const struct np_vector* vector)
{
    return vector->used;
}

void* np_vector_get(const struct np_vector* vector, size_t index)
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

void np_vector_clear(struct np_vector* vector)
{
    vector->used = 0;
    // TODO free elements if needed
}

void np_vector_front(const struct np_vector* vector, struct np_vector_iterator* iterator)
{
    iterator->v = vector;
    iterator->current = 0;
}

struct np_vector_iterator np_vector_front2(const struct np_vector* vector)
{
    struct np_vector_iterator iterator;
    iterator.v = vector;
    iterator.current = 0;
    return iterator;
}

void np_vector_next(struct np_vector_iterator* iterator)
{
    iterator->current += 1;
}

bool np_vector_end(const struct np_vector_iterator* iterator)
{
    return iterator->current >= iterator->v->used;
}

void* np_vector_get_element(const struct np_vector_iterator* iterator)
{
    return np_vector_get(iterator->v, iterator->current);
}
