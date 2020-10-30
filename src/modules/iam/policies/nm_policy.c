#include "nm_policy.h"
#include "nm_statement.h"

#include <nn/llist.h>

#include <stdlib.h>
#include <string.h>

struct nm_iam_policy* nm_policy_new(const char* idIn)
{
    struct nm_iam_policy* p = NULL;
    char* id = NULL;

    id = strdup(idIn);
    p = calloc(1, sizeof(struct nm_iam_policy));
    if (p == NULL || id == NULL) {
        free(id);
        free(p);
        return NULL;
    }
    nn_llist_init(&p->statements);
    nn_llist_node_init(&p->listNode);
    p->id = id;

    return p;
}

void nm_policy_free(struct nm_iam_policy* policy)
{
    struct nn_llist_iterator it = nn_llist_begin(&policy->statements);
    while(!nn_llist_is_end(&it))
    {
        struct nm_iam_statement* s = nn_llist_get_item(&it);
        nn_llist_erase_node(&s->listNode);
        nm_statement_free(s);
        it = nn_llist_begin(&policy->statements);
    }
    nn_llist_deinit(&policy->statements);
    free(policy->id);
    free(policy);
}

// Add statement to a policy, this takes ownership over the statement.
bool nm_policy_add_statement(struct nm_iam_policy* policy, struct nm_iam_statement* stmt)
{
    nn_llist_append(&policy->statements, &stmt->listNode, stmt);
    return true;
}

void nm_policy_eval_init(struct nm_policy_eval_state* state)
{
    state->effect = NM_IAM_EFFECT_NO_MATCH;
}

enum nm_iam_effect nm_policy_eval_get_effect(struct nm_policy_eval_state* state)
{
    return state->effect;
}


void nm_policy_eval(struct nm_policy_eval_state* state, struct nm_iam_policy* policy, const char* action, const struct nn_string_map* attributes)
{
    struct nm_iam_statement* stmt;
    NN_LLIST_FOREACH(stmt, &policy->statements) {
        nm_policy_statement_eval(state, stmt, action, attributes);
    }
}

void nm_policy_statement_eval(struct nm_policy_eval_state* state, struct nm_iam_statement* statement, const char* action, const struct nn_string_map* attributes)
{
    if (state->effect == NM_IAM_EFFECT_DENY || state->effect == NM_IAM_EFFECT_ERROR) {
        // This is the final state.
        return;
    }
    enum nm_iam_effect e = nm_statement_eval(statement, action, attributes);
    if (e == NM_IAM_EFFECT_ERROR || e == NM_IAM_EFFECT_DENY || e == NM_IAM_EFFECT_ALLOW) {
        state->effect = e;
    }
    // on no match do not change the state.
}

enum nm_iam_effect nm_policy_eval_simple(struct nm_iam_policy* policy, const char* action, const struct nn_string_map* attributes)
{
    struct nm_policy_eval_state state;
    nm_policy_eval_init(&state);
    nm_policy_eval(&state, policy, action, attributes);
    return nm_policy_eval_get_effect(&state);
}
