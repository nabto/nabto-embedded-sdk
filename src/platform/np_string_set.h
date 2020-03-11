#ifndef _NP_STRING_SET_H_
#define _NP_STRING_SET_H_

#include <platform/np_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_string_set {
    struct np_vector strings;
};

void np_string_set_init(struct np_string_set* set);

void np_string_set_deinit(struct np_string_set* set);

np_error_code np_string_set_add(struct np_string_set* set, const char* item);

bool np_string_set_contains(struct np_string_set* set, const char* item);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
