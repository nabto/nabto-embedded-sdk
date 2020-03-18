#ifndef _NP_STRING_SET_H_
#define _NP_STRING_SET_H_

#include <platform/np_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_string_set {
    struct np_vector strings;
};

struct np_string_set_iterator {
    struct np_vector_iterator it;
};

void np_string_set_init(struct np_string_set* set);

void np_string_set_deinit(struct np_string_set* set);

np_error_code np_string_set_add(struct np_string_set* set, const char* item);

bool np_string_set_contains(const struct np_string_set* set, const char* item);

bool np_string_set_empty(struct np_string_set* set);

void np_string_set_front(const struct np_string_set* set, struct np_string_set_iterator* it);
struct np_string_set_iterator np_string_set_front2(const struct np_string_set* set);
bool np_string_set_end(const struct np_string_set_iterator* it);
void np_string_set_next(struct np_string_set_iterator* it);
const char* np_string_set_get_element(const struct np_string_set_iterator* it);

#define NP_STRING_SET_FOREACH(element, set) for(struct np_string_set_iterator it = np_string_set_front2(set); element = np_string_set_get_element(&it), !np_string_set_end(&it); np_string_set_next(&it))

#ifdef __cplusplus
} //extern "C"
#endif

#endif
