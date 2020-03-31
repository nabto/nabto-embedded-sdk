#include "np_string_set.h"

#include <stdlib.h>
#include <string.h>

static void string_free(void* item)
{
    free(item);
}

void np_string_set_init(struct np_string_set* set)
{
    np_vector_init(&set->strings, &string_free);
}

void np_string_set_deinit(struct np_string_set* set)
{
    np_vector_deinit(&set->strings);
}

np_error_code np_string_set_add(struct np_string_set* set, const char* item)
{
    if (np_string_set_contains(set, item)) {
        return NABTO_EC_OK;
    }
    char* dup = strdup(item);
    return np_vector_push_back(&set->strings, dup);
}

bool np_string_set_contains(const struct np_string_set* set, const char* item)
{
    struct np_vector_iterator it;
    for (np_vector_front(&set->strings, &it);
         !np_vector_end(&it);
         np_vector_next(&it))
    {
        const char* e = np_vector_get_element(&it);
        if (strcmp(e,item) == 0) {
            return true;
        }
    }
    return false;
}

bool np_string_set_empty(struct np_string_set* set)
{
    return np_vector_empty(&set->strings);
}

size_t np_string_set_size(struct np_string_set* set)
{
    return np_vector_size(&set->strings);
}

void np_string_set_front(const struct np_string_set* set, struct np_string_set_iterator* it)
{
    np_vector_front(&set->strings, &it->it);
}

struct np_string_set_iterator np_string_set_front2(const struct np_string_set* set)
{
    struct np_string_set_iterator it;
    np_vector_front(&set->strings, &it.it);
    return it;
}

bool np_string_set_end(const struct np_string_set_iterator* it)
{
    return np_vector_end(&it->it);
}

void np_string_set_next(struct np_string_set_iterator* it)
{
    np_vector_next(&it->it);
}

const char* np_string_set_get_element(const struct np_string_set_iterator* it)
{
    const char* s = np_vector_get_element(&it->it);
    return s;
}
