#ifndef _NM_CONDITION_H_
#define _NM_CONDITION_H_

#include <platform/np_vector.h>
#include <platform/np_string_set.h>
#include <platform/np_string_map.h>

#ifdef __cplusplus
extern "C" {
#endif

enum nm_condition_operator {
    NM_CONDITION_OPERATOR_STRING_EQUALS,
    NM_CONDITION_OPERATOR_STRING_NOT_EQUALS,
    NM_CONDITION_OPERATOR_NUMERIC_EQUALS,
    NM_CONDITION_OPERATOR_NUMERIC_NOT_EQUALS,
    NM_CONDITION_OPERATOR_NUMERIC_LESS_THAN,
    NM_CONDITION_OPERATOR_NUMERIC_LESS_THAN_EQUALS,
    NM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN,
    NM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN_EQUALS,
    NM_CONDITION_OPERATOR_BOOL
};

enum nm_condition_result {
    NM_CONDITION_RESULT_MATCH,
    NM_CONDITION_RESULT_NO_MATCH,
    NM_CONDITION_RESULT_ERROR
};

struct nm_condition {
    enum nm_condition_operator op;
    char* key;

    struct np_string_set values;
};

struct nm_condition* nm_condition_new();

void nm_condition_free(struct nm_condition* condition);

void nm_condition_init(struct nm_condition* c);

void nm_condition_deinit(struct nm_condition* c);

bool nm_condition_parse_bool(const char* value, bool* out);

bool nm_condition_parse_numeric(const char* value, double* out);

bool nm_condition_parse_operator(const char* operation, enum nm_condition_operator* op);

enum nm_condition_result nm_condition_numeric_operator(enum nm_condition_operator op, const char* lhs, const char* rhs);

enum nm_condition_result nm_condition_matches(struct nm_condition* condition, struct np_string_map* attributes);



#ifdef __cplusplus
} //extern "C"
#endif

#endif
