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
