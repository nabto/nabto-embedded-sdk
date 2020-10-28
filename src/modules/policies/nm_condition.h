#ifndef _NM_CONDITION_H_
#define _NM_CONDITION_H_

#include <nn/string_set.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nn_string_map;

struct nm_condition* nm_condition_new(enum nm_condition_operator op);
struct nm_condition* nm_condition_new_with_key(enum nm_condition_operator op, const char* key);

void nm_condition_free(struct nm_condition* condition);

void nm_condition_init(struct nm_condition* c);

void nm_condition_deinit(struct nm_condition* c);

bool nm_condition_add_value(struct nm_condition* c, const char* value);

bool nm_condition_parse_bool(const char* value, bool* out);

bool nm_condition_parse_numeric(const char* value, double* out);

bool nm_condition_parse_operator(const char* operation, enum nm_condition_operator* op);

const char* nm_condition_operator_to_string(const enum nm_condition_operator op);

enum nm_condition_result nm_condition_numeric_operator(enum nm_condition_operator op, const char* lhs, const char* rhs);

enum nm_condition_result nm_condition_matches(const struct nm_condition* condition, const struct nn_string_map* attributes);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
