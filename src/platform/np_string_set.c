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

bool np_string_set_contains(struct np_string_set* set, const char* item)
{
    struct np_vector_iterator it;
    for (np_vector_front(&set->strings, &it);
         np_vector_end(&it);
         np_vector_next(&it))
    {
        const char* e = np_vector_get_element(&it);
        if (strcmp(e,item) == 0) {
            return true;
        }
    }
    return false;
}
