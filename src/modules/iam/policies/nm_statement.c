#include "nm_statement.h"
#include "nm_condition.h"

#include <nn/string_set.h>
#include <nn/string_map.h>
#include <nn/llist.h>

#include <platform/np_heap.h>





static enum nm_condition_result match_conditions(const struct nm_iam_statement* statement, const struct nn_string_map* attributes);

struct nm_iam_statement* nm_statement_new(enum nm_iam_effect effect)
{
    struct nm_iam_statement* statement = np_calloc(1, sizeof(struct nm_iam_statement));
    if (statement == NULL) {
        return NULL;
    }
    statement->effect = effect;
    nn_string_set_init(&statement->actions);
    nn_llist_init(&statement->conditions);
    nn_llist_node_init(&statement->listNode);
    return statement;
}

void nm_statement_free(struct nm_iam_statement* statement)
{
    nn_string_set_deinit(&statement->actions);

    struct nn_llist_iterator it = nn_llist_begin(&statement->conditions);
    while(!nn_llist_is_end(&it))
    {
        struct nm_iam_condition* condition = nn_llist_get_item(&it);
        nn_llist_erase_node(&condition->listNode);
        nm_condition_free(condition);
        it = nn_llist_begin(&statement->conditions);
    }

    nn_llist_deinit(&statement->conditions);
    np_free(statement);
}

enum nm_iam_effect nm_statement_eval(const struct nm_iam_statement* statement, const char* action, const struct nn_string_map* attributes)
{
    if (!nn_string_set_contains(&statement->actions, action)) {
        return NM_IAM_EFFECT_NO_MATCH;
    }

    enum nm_condition_result r = match_conditions(statement, attributes);
    if (r == NM_CONDITION_RESULT_NO_MATCH) {
        return NM_IAM_EFFECT_NO_MATCH;
    }
    if (r == NM_CONDITION_RESULT_ERROR) {
        return NM_IAM_EFFECT_ERROR;
    }

    // action and conditions matches
    return statement->effect;

}

bool nm_statement_add_action(struct nm_iam_statement* statement, const char* action)
{
    return nn_string_set_insert(&statement->actions, action);
}

bool nm_statement_add_condition(struct nm_iam_statement* statement, struct nm_iam_condition* condition)
{
    nn_llist_append(&statement->conditions, &condition->listNode, condition);
    return true;
}

enum nm_condition_result match_conditions(const struct nm_iam_statement* statement, const struct nn_string_map* attributes)
{
    const struct nm_iam_condition* condition;
    NN_LLIST_FOREACH(condition, &statement->conditions)
    {
        enum nm_condition_result r = nm_condition_matches(condition, attributes);
        if (r == NM_CONDITION_RESULT_NO_MATCH || r == NM_CONDITION_RESULT_ERROR) {
            return r;
        }
    }
    return NM_CONDITION_RESULT_MATCH;
}
