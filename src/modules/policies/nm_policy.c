#include "nm_policy.h"
#include "nm_statement.h"

#include <stdlib.h>
#include <string.h>

struct nm_policy* nm_policy_new(const char* idIn)
{
    struct nm_policy* p = NULL;
    char* id = NULL;

    id = strdup(idIn);
    p = calloc(1, sizeof(struct nm_policy));
    if (p == NULL || id == NULL) {
        free(id);
        free(p);
        return NULL;
    }
    nn_vector_init(&p->statements, sizeof(void*));
    p->id = id;

    return p;
}

void nm_policy_free(struct nm_policy* policy)
{
    struct nm_statement* stmt;
    NN_VECTOR_FOREACH(&stmt, &policy->statements) {
        nm_statement_free(stmt);
    }
    nn_vector_deinit(&policy->statements);
    free(policy->id);
    free(policy);
}

// Add statement to a policy, this takes ownership over the statement.
bool nm_policy_add_statement(struct nm_policy* policy, struct nm_statement* stmt)
{
    return nn_vector_push_back(&policy->statements, &stmt);
}

void nm_policy_eval_init(struct nm_policy_eval_state* state)
{
    state->effect = NM_EFFECT_NO_MATCH;
}

enum nm_effect nm_policy_eval_get_effect(struct nm_policy_eval_state* state)
{
    return state->effect;
}


void nm_policy_eval(struct nm_policy_eval_state* state, struct nm_policy* policy, const char* action, const struct nn_string_map* attributes)
{
    struct nm_statement* stmt;
    NN_VECTOR_FOREACH(&stmt, &policy->statements) {
        nm_policy_statement_eval(state, stmt, action, attributes);
    }
}

void nm_policy_statement_eval(struct nm_policy_eval_state* state, struct nm_statement* statement, const char* action, const struct nn_string_map* attributes)
{
    if (state->effect == NM_EFFECT_DENY || state->effect == NM_EFFECT_ERROR) {
        // This is the final state.
        return;
    }
    enum nm_effect e = nm_statement_eval(statement, action, attributes);
    if (e == NM_EFFECT_ERROR || e == NM_EFFECT_DENY || e == NM_EFFECT_ALLOW) {
        state->effect = e;
    }
    // on no match do not change the state.
}

enum nm_effect nm_policy_eval_simple(struct nm_policy* policy, const char* action, const struct nn_string_map* attributes)
{
    struct nm_policy_eval_state state;
    nm_policy_eval_init(&state);
    nm_policy_eval(&state, policy, action, attributes);
    return nm_policy_eval_get_effect(&state);
}
