#include "nm_policy.h"
#include "nm_statement.h"

#include <stdlib.h>

static void statement_free(void* statement);


struct nm_policy* nm_policy_new(const char* id)
{
    struct nm_policy* p = calloc(1, sizeof(struct nm_policy));
    if (p == NULL) {
        return NULL;
    }

    p->id = strdup(id);
    np_vector_init(&p->statements, &statement_free);
    return p;
}

void nm_policy_free(struct nm_policy* policy)
{
    np_vector_deinit(&policy->statements);
    free(policy->id);
    free(policy);
}

// Add statement to a policy, this takes ownership over the statement.
np_error_code nm_policy_add_statement(struct nm_policy* policy)
{
    return np_vector_push_back(&policy->statements, policy);
}

enum nm_effect nm_policy_eval(struct nm_policy* policy, const char* action, struct np_string_map* attributes)
{
    enum nm_effect decision = NM_EFFECT_NO_MATCH;
    struct np_vector_iterator it;
    for (np_vector_front(&policy->statements, &it);
         !np_vector_end(&it);
         np_vector_next(&it))
    {
        struct nm_statement* s = np_vector_get_element(&it);
        enum nm_effect e = nm_statement_eval(s, action, attributes);
        if (e == NM_EFFECT_ERROR || e == NM_EFFECT_DENY) {
            return e;
        }
        if (e == NM_EFFECT_ALLOW) {
            decision = e;
        }
    }
    return decision;
}

void statement_free(void* statement)
{
    struct nm_statement* s = statement;
    nm_statement_free(s);
}
