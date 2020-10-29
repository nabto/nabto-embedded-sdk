#include "nm_condition.h"

#include <nn/string_map.h>

#include <stdlib.h>
#include <string.h>

static enum nm_condition_result match(enum nm_iam_condition_operator op, const char* lhs, const char* rhs);
static bool resolve_value(const struct nn_string_map* attributes, const char* value, const char** out);

struct nm_iam_condition* nm_condition_new(enum nm_iam_condition_operator op)
{
    struct nm_iam_condition* c = calloc(1, sizeof(struct nm_iam_condition));
    if (c == NULL) {
        return NULL;
    }

    nm_condition_init(c);
    c->op = op;
    return c;
}

struct nm_iam_condition* nm_condition_new_with_key(enum nm_iam_condition_operator op, const char* key)
{
    struct nm_iam_condition* c = nm_condition_new(op);
    if (c == NULL) {
        return c;
    }
    c->key = strdup(key);
    return c;

}

void nm_condition_free(struct nm_iam_condition* condition)
{
    nm_condition_deinit(condition);
    free(condition);
}

void nm_condition_init(struct nm_iam_condition* condition)
{
    nn_llist_node_init(&condition->listNode);
    nn_string_set_init(&condition->values);
}

void nm_condition_deinit(struct nm_iam_condition* condition)
{
    nn_string_set_deinit(&condition->values);
    free(condition->key);
    condition->key = NULL;
}

bool nm_condition_add_value(struct nm_iam_condition* c, const char* value)
{
    return nn_string_set_insert(&c->values, value);
}

bool nm_condition_parse_bool(const char* value, bool* out)
{
    if (strcmp(value, "true") == 0) {
        *out = true;
        return true;
    } else if (strcmp(value, "false") == 0) {
        *out = false;
        return true;
    } else {
        return false;
    }
}

bool nm_condition_parse_numeric(const char* value, double* out)
{
    char* err;
    *out = strtod(value, &err);
    // err points to the character after last parsed part of the
    // value. if it points to the null termination the full value was
    // used to be parsed to the double.
    return (*err == 0);
}

static enum nm_condition_result status(bool s)
{
    if (s) {
        return NM_CONDITION_RESULT_MATCH;
    } else {
        return NM_CONDITION_RESULT_NO_MATCH;
    }
}

enum nm_condition_result nm_condition_numeric_operator(enum nm_iam_condition_operator op, const char* lhs, const char* rhs)
{
    double lhsDouble;
    double rhsDouble;
    if (nm_condition_parse_numeric(lhs, &lhsDouble) && nm_condition_parse_numeric(rhs, &rhsDouble)) {
        switch (op) {
            case NM_IAM_CONDITION_OPERATOR_NUMERIC_EQUALS:
                return status(lhsDouble == rhsDouble);
            case NM_IAM_CONDITION_OPERATOR_NUMERIC_NOT_EQUALS:
                return status(lhsDouble != rhsDouble);
            case NM_IAM_CONDITION_OPERATOR_NUMERIC_LESS_THAN:
                return status(lhsDouble < rhsDouble);
            case NM_IAM_CONDITION_OPERATOR_NUMERIC_LESS_THAN_EQUALS:
                return status(lhsDouble <= rhsDouble);
            case NM_IAM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN:
                return status(lhsDouble > rhsDouble);
            case NM_IAM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN_EQUALS:
                return status(lhsDouble >= rhsDouble);
            case NM_IAM_CONDITION_OPERATOR_STRING_EQUALS:
            case NM_IAM_CONDITION_OPERATOR_STRING_NOT_EQUALS:
            case NM_IAM_CONDITION_OPERATOR_BOOL:
                // We should never get here, this silences the compiler.
                return NM_CONDITION_RESULT_ERROR;
        }
    }
    return NM_CONDITION_RESULT_ERROR;
}

enum nm_condition_result nm_condition_matches(const struct nm_iam_condition* condition, const struct nn_string_map* attributes)
{
    struct nn_string_map_iterator it = nn_string_map_get(attributes, condition->key);
    if (nn_string_map_is_end(&it)) {
        return NM_CONDITION_RESULT_NO_MATCH;
    }

    const char* attributeValue = nn_string_map_value(&it);

    const char* v;
    NN_STRING_SET_FOREACH(v, &condition->values) {
        const char* resolvedValue;
        // If the value is a variable we try to resolve it to a string
        // else interpret it as a string.
        if (resolve_value(attributes, v, &resolvedValue)) {
            enum nm_condition_result r = match(condition->op, attributeValue, resolvedValue);
            if (r == NM_CONDITION_RESULT_ERROR ||
                r == NM_CONDITION_RESULT_MATCH)
            {
                return r;
            }
        }
    }
    return NM_CONDITION_RESULT_NO_MATCH;
}


bool nm_condition_parse_operator(const char* operation, enum nm_iam_condition_operator* op)
{
    if      (strcmp(operation, "StringEquals") == 0)             { *op = NM_IAM_CONDITION_OPERATOR_STRING_EQUALS; }
    else if (strcmp(operation, "StringNotEquals") == 0)          { *op = NM_IAM_CONDITION_OPERATOR_STRING_NOT_EQUALS; }
    else if (strcmp(operation, "NumericEquals") == 0)            { *op = NM_IAM_CONDITION_OPERATOR_NUMERIC_EQUALS; }
    else if (strcmp(operation, "NumericNotEquals") == 0)         { *op = NM_IAM_CONDITION_OPERATOR_NUMERIC_NOT_EQUALS; }
    else if (strcmp(operation, "NumericLessThan") == 0)          { *op = NM_IAM_CONDITION_OPERATOR_NUMERIC_LESS_THAN; }
    else if (strcmp(operation, "NumericLessThanEquals") == 0)    { *op = NM_IAM_CONDITION_OPERATOR_NUMERIC_LESS_THAN_EQUALS; }
    else if (strcmp(operation, "NumericGreaterThan") == 0)       { *op = NM_IAM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN; }
    else if (strcmp(operation, "NumericGreaterThanEquals") == 0) { *op = NM_IAM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN_EQUALS; }
    else if (strcmp(operation, "Bool") == 0)                     { *op = NM_IAM_CONDITION_OPERATOR_BOOL; }
    else {
        return false;
    }
    return true;
}

const char* nm_condition_operator_to_string(const enum nm_iam_condition_operator op)
{
    switch(op) {
        case NM_IAM_CONDITION_OPERATOR_STRING_EQUALS: return "StringEquals";
        case NM_IAM_CONDITION_OPERATOR_STRING_NOT_EQUALS: return "StringNotEquals";
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_EQUALS: return "NumericEquals";
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_NOT_EQUALS: return "NumericNotEquals";
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_LESS_THAN: return "NumericLessThan";
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_LESS_THAN_EQUALS: return "NumericLessThanEquals";
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN: return "NumericGreaterThan";
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN_EQUALS: return "NumericGreaterThanEquals";
        case NM_IAM_CONDITION_OPERATOR_BOOL: return "Bool";
    }
    return "";
}

/********************************
 * Local helper functions below *
 ********************************/

enum nm_condition_result bool_equals(const char* lhs, const char* rhs)
{
    bool lhsBool;
    bool rhsBool;
    if (nm_condition_parse_bool(lhs, &lhsBool) && nm_condition_parse_bool(rhs, &rhsBool)) {
        return status(lhsBool == rhsBool);
    }
    return NM_CONDITION_RESULT_ERROR;
}

enum nm_condition_result string_equals(const char* lhs, const char* rhs)
{
    return status(strcmp(lhs, rhs) == 0);
}
enum nm_condition_result string_not_equals(const char* lhs, const char* rhs)
{
    return status(strcmp(lhs, rhs) != 0);
}

static enum nm_condition_result match(enum nm_iam_condition_operator op, const char* lhs, const char* rhs)
{
    switch (op) {
        case NM_IAM_CONDITION_OPERATOR_STRING_EQUALS:
            return string_equals(lhs, rhs);
        case NM_IAM_CONDITION_OPERATOR_STRING_NOT_EQUALS:
            return string_not_equals(lhs, rhs);
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_EQUALS:
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_NOT_EQUALS:
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_LESS_THAN:
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_LESS_THAN_EQUALS:
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN:
        case NM_IAM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN_EQUALS:
            return nm_condition_numeric_operator(op, lhs, rhs);
        case NM_IAM_CONDITION_OPERATOR_BOOL:
            return bool_equals(lhs, rhs);
    }
    // we should never get here
    return NM_CONDITION_RESULT_ERROR;
}

bool resolve_value(const struct nn_string_map* attributes, const char* value, const char** out)
{
    size_t valueLength = strlen(value);
    if (valueLength < 3) {
        *out = value;
        return true;
    }
    // try to match ${variable}
    if (strncmp(value, "${", 2) == 0 &&
        strncmp(value+(valueLength-1), "}", 1) == 0)
    {
        const char* variable = value+2;
        size_t variableLength = valueLength - 3;
        struct nn_string_map_iterator it = nn_string_map_getn(attributes, variable, variableLength);
        if (!nn_string_map_is_end(&it)) {
            *out = nn_string_map_value(&it);
            return true;
        }
    } else {
        *out = value;
        return true;
    }

    return false;

}
