#include "nm_condition.h"

#include <stdlib.h>

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
