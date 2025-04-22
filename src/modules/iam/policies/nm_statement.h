#ifndef NM_STATEMENT_H_
#define NM_STATEMENT_H_

#include "../nm_iam_configuration.h"

#include <nn/string_map.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_iam_statement* nm_statement_new(enum nm_iam_effect effect);

void nm_statement_free(struct nm_iam_statement* statement);

enum nm_iam_effect nm_statement_eval(const struct nm_iam_statement* statement, const char* action, const struct nn_string_map* attributes);

bool nm_statement_add_action(struct nm_iam_statement* statement, const char* action);
bool nm_statement_add_condition(struct nm_iam_statement* statement, struct nm_iam_condition* condition);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
