#include "nm_condition.h"

#include <platform/np_string_map.h>

#include <stdlib.h>

static enum nm_condition_result match(enum nm_condition_operator op, const char* lhs, const char* rhs);
static bool resolve_value(struct np_string_map* attributes, const char* value, const char** out);

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

enum nm_condition_result nm_condition_numeric_operator(enum nm_condition_operator op, const char* lhs, const char* rhs)
{
    double lhsDouble;
    double rhsDouble;
    if (nm_condition_parse_numeric(lhs, &lhsDouble) && nm_condition_parse_numeric(rhs, &rhsDouble)) {
        switch (op) {
            case NM_CONDITION_OPERATOR_NUMERIC_EQUALS:
                return status(lhsDouble == rhsDouble);
            case NM_CONDITION_OPERATOR_NUMERIC_NOT_EQUALS:
                return status(lhsDouble != rhsDouble);
            case NM_CONDITION_OPERATOR_NUMERIC_LESS_THAN:
                return status(lhsDouble < rhsDouble);
            case NM_CONDITION_OPERATOR_NUMERIC_LESS_THAN_EQUALS:
                return status(lhsDouble <= rhsDouble);
            case NM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN:
                return status(lhsDouble > rhsDouble);
            case NM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN_EQUALS:
                return status(lhsDouble >= rhsDouble);
            case NM_CONDITION_OPERATOR_STRING_EQUALS:
            case NM_CONDITION_OPERATOR_STRING_NOT_EQUALS:
            case NM_CONDITION_OPERATOR_BOOL:
                // We should never get here, this silences the compiler.
                return NM_CONDITION_RESULT_ERROR;
        }
    }
    return NM_CONDITION_RESULT_ERROR;
}

enum nm_condition_result nm_condition_matches(struct nm_condition* condition, struct np_string_map* attributes)
{
    struct np_string_map_item* item = np_string_map_get(attributes, condition->key);
    if (item == NULL) {
        return NM_CONDITION_RESULT_NO_MATCH;
    }

    const char* attribute = item->value;

    struct np_vector_iterator it;
    for (np_vector_front(&condition->values, &it);
         !np_vector_end(&it);
         np_vector_next(&it))
    {
        const char* v = np_vector_get_element(&it);
        const char* resolvedValue;
        // If the value is a variable we try to resolve it to a string
        // else interpret it as a string.
        if (resolve_value(attributes, v, &resolvedValue)) {
            enum nm_condition_result r = match(condition->op, attribute, resolvedValue);
            if (r == NM_CONDITION_RESULT_ERROR ||
                r == NM_CONDITION_RESULT_MATCH)
            {
                return r;
            }
        }
    }
    return NM_CONDITION_RESULT_NO_MATCH;
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
    return (strcmp(lhs, rhs) == 0);
}
enum nm_condition_result string_not_equals(const char* lhs, const char* rhs)
{
    return (strcmp(lhs, rhs) != 0);
}

static enum nm_condition_result match(enum nm_condition_operator op, const char* lhs, const char* rhs)
{
    switch (op) {
        case NM_CONDITION_OPERATOR_STRING_EQUALS:
            return string_equals(lhs, rhs);
        case NM_CONDITION_OPERATOR_STRING_NOT_EQUALS:
            return string_not_equals(lhs, rhs);
        case NM_CONDITION_OPERATOR_NUMERIC_EQUALS:
        case NM_CONDITION_OPERATOR_NUMERIC_NOT_EQUALS:
        case NM_CONDITION_OPERATOR_NUMERIC_LESS_THAN:
        case NM_CONDITION_OPERATOR_NUMERIC_LESS_THAN_EQUALS:
        case NM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN:
        case NM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN_EQUALS:
            return nm_condition_numeric_operator(op, lhs, rhs);
        case NM_CONDITION_OPERATOR_BOOL:
            return bool_equals(lhs, rhs);
    }
    // we should never get here
    return NM_CONDITION_RESULT_ERROR;
}

bool resolve_value(struct np_string_map* attributes, const char* value, const char** out)
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
        struct np_string_map_item* item = np_string_map_getn(attributes, variable, variableLength);
        if (item) {
            *out = item->value;
            return true;
        }
    } else {
        *out = value;
        return true;
    }

    return false;

}
