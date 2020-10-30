#ifndef _NM_CONDITION_H_
#define _NM_CONDITION_H_

#include "../nm_iam_configuration.h"
#include <nn/string_set.h>

#ifdef __cplusplus
extern "C" {
#endif

enum nm_condition_result {
    NM_CONDITION_RESULT_MATCH,
    NM_CONDITION_RESULT_NO_MATCH,
    NM_CONDITION_RESULT_ERROR
};

struct nn_string_map;

struct nm_iam_condition* nm_condition_new(enum nm_iam_condition_operator op);
struct nm_iam_condition* nm_condition_new_with_key(enum nm_iam_condition_operator op, const char* key);

void nm_condition_free(struct nm_iam_condition* condition);

void nm_condition_init(struct nm_iam_condition* c);

void nm_condition_deinit(struct nm_iam_condition* c);

bool nm_condition_add_value(struct nm_iam_condition* c, const char* value);

bool nm_condition_parse_bool(const char* value, bool* out);

bool nm_condition_parse_numeric(const char* value, double* out);

bool nm_condition_parse_operator(const char* operation, enum nm_iam_condition_operator* op);

const char* nm_condition_operator_to_string(const enum nm_iam_condition_operator op);

enum nm_condition_result nm_condition_numeric_operator(enum nm_iam_condition_operator op, const char* lhs, const char* rhs);

enum nm_condition_result nm_condition_matches(const struct nm_iam_condition* condition, const struct nn_string_map* attributes);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
