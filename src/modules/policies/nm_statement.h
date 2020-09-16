#ifndef _NM_STATEMENT_H_
#define _NM_STATEMENT_H_

#include "nm_effect.h"
#include <nn/vector.h>
#include <nn/string_set.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nn_string_map;
struct nm_condition;

struct nm_statement {
    enum nm_effect effect;
    struct nn_string_set actions;
    struct nn_vector conditions;
};

struct nm_statement* nm_statement_new(enum nm_effect effect);

void nm_statement_free(struct nm_statement* statement);

enum nm_effect nm_statement_eval(const struct nm_statement* statement, const char* action, const struct nn_string_map* attributes);

bool nm_statement_add_action(struct nm_statement* statement, const char* action);
bool nm_statement_add_condition(struct nm_statement* statement, struct nm_condition* condition);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
