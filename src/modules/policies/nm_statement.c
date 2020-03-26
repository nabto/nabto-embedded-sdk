#include "nm_statement.h"
#include "nm_condition.h"

#include <nn/string_set.h>

#include <stdlib.h>



static enum nm_condition_result match_conditions(const struct nm_statement* statement, const struct np_string_map* attributes);

static void condition_free(void* condition);

struct nm_statement* nm_statement_new(enum nm_effect effect)
{
    struct nm_statement* statement = calloc(1, sizeof(struct nm_statement));
    if (statement == NULL) {
        return NULL;
    }
    statement->effect = effect;
    nn_string_set_init(&statement->actions);
    np_vector_init(&statement->conditions, &condition_free);
    return statement;
}

void nm_statement_free(struct nm_statement* statement)
{
    nn_string_set_deinit(&statement->actions);
    np_vector_deinit(&statement->conditions);
}

enum nm_effect nm_statement_eval(const struct nm_statement* statement, const char* action, const struct np_string_map* attributes)
{
    if (!nn_string_set_contains(&statement->actions, action)) {
        return NM_EFFECT_NO_MATCH;
    }

    enum nm_condition_result r = match_conditions(statement, attributes);
    if (r == NM_CONDITION_RESULT_NO_MATCH) {
        return NM_EFFECT_NO_MATCH;
    }
    if (r == NM_CONDITION_RESULT_ERROR) {
        return NM_EFFECT_ERROR;
    }

    // action and conditions matches
    return statement->effect;

}

np_error_code nm_statement_add_action(struct nm_statement* statement, const char* action)
{
    return nn_string_set_insert(&statement->actions, action);
}

enum nm_condition_result match_conditions(const struct nm_statement* statement, const struct np_string_map* attributes)
{
    const struct nm_condition* condition;
    NP_VECTOR_FOREACH(condition, &statement->conditions)
    {
        enum nm_condition_result r = nm_condition_matches(condition, attributes);
        if (r == NM_CONDITION_RESULT_NO_MATCH || r == NM_CONDITION_RESULT_ERROR) {
            return r;
        }
    }
    return NM_CONDITION_RESULT_MATCH;
}

void condition_free(void* condition)
{
    struct nm_condition* cond = condition;
    nm_condition_free(cond);
}
