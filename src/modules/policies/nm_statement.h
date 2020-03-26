#ifndef _NM_STATEMENT_H_
#define _NM_STATEMENT_H_

#include "nm_effect.h"
#include <platform/np_vector.h>
#include <nn/string_set.h>
#include <platform/np_string_map.h>

struct nm_statement {
    enum nm_effect effect;
    struct nn_string_set actions;
    struct np_vector conditions;
};

struct nm_statement* nm_statement_new();

void nm_statement_free(struct nm_statement* statement);

enum nm_effect nm_statement_eval(const struct nm_statement* statement, const char* action, const struct np_string_map* attributes);

np_error_code nm_statement_add_action(struct nm_statement* statement, const char* action);

#endif
