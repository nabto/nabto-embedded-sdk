#ifndef _NM_CONDITION_H_
#define _NM_CONDITION_H_

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

struct nm_condition {
    enum nm_condition_operator operator;
    char* key;
    struct np_vector values;
};

void nm_condition_init(struct nm_condition* c, enum nm_condition_operator operator, const char* key, struct np_vector* values);

void nm_condition_deinit(struct nm_condition* c);

#endif
