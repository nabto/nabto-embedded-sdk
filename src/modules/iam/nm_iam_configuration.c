#include "nm_iam_configuration.h"
#include "nm_iam_role.h"
#include "policies/nm_condition.h"
#include "policies/nm_policy.h"
#include "policies/nm_statement.h"

#include "nm_iam_allocator.h"

#include <nn/string.h>
#include <string.h>

struct nm_iam_configuration* nm_iam_configuration_new(void)
{
    struct nm_iam_configuration* c = nm_iam_calloc(1, sizeof(struct nm_iam_configuration));
    if (c == NULL) {
        return NULL;
    }
    nn_llist_init(&c->roles);
    nn_llist_init(&c->policies);
    return c;
}

void nm_iam_configuration_free(struct nm_iam_configuration* conf)
{
    if (conf == NULL) {
        return;
    }
    struct nn_llist_iterator it = nn_llist_begin(&conf->roles);
    while(!nn_llist_is_end(&it))
    {
        struct nm_iam_role* r = nn_llist_get_item(&it);
        nn_llist_erase_node(&r->listNode);
        nm_iam_configuration_role_free(r);
        it = nn_llist_begin(&conf->roles);
    }

    it = nn_llist_begin(&conf->policies);
    while(!nn_llist_is_end(&it))
    {
        struct nm_iam_policy* p = nn_llist_get_item(&it);
        nn_llist_erase_node(&p->listNode);
        nm_iam_configuration_policy_free(p);
        it = nn_llist_begin(&conf->policies);
    }

    nn_llist_deinit(&conf->roles);
    nn_llist_deinit(&conf->policies);
    nm_iam_free(conf->unpairedRole);
    nm_iam_free(conf);
}

bool set_string(char** dst, const char* role)
{
    if (role == NULL) {
        nm_iam_free(*dst);
        *dst = NULL;
        return true;
    }
    char* tmp = nn_strdup(role, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(*dst);
        *dst = tmp;
    }
    return (tmp != 0);
}

bool nm_iam_configuration_set_unpaired_role(struct nm_iam_configuration* conf, const char* role)
{
    return set_string(&conf->unpairedRole, role);
}

bool nm_iam_configuration_add_policy(struct nm_iam_configuration* conf, struct nm_iam_policy* policy)
{
    nn_llist_append(&conf->policies, &policy->listNode, policy);
    return true;
}

bool nm_iam_configuration_add_role(struct nm_iam_configuration* conf, struct nm_iam_role* role)
{
    nn_llist_append(&conf->roles, &role->listNode, role);
    return true;
}

struct nm_iam_policy* nm_iam_configuration_policy_new(const char* name)
{
    return nm_policy_new(name);
}

void nm_iam_configuration_policy_free(struct nm_iam_policy* policy)
{
    nm_policy_free(policy);
}

struct nm_iam_statement* nm_iam_configuration_policy_create_statement(struct nm_iam_policy* policy, enum nm_iam_effect effect)
{
    struct nm_iam_statement* stmt = nm_statement_new(effect);
    if(stmt == NULL || !nm_policy_add_statement(policy, stmt)) {
        nm_iam_free(stmt);
        return NULL;
    }
    return stmt;
}

bool nm_iam_configuration_statement_add_action(struct nm_iam_statement* statement, const char* action)
{
    return nm_statement_add_action(statement, action);
}

struct nm_iam_condition* nm_iam_configuration_statement_create_condition(struct nm_iam_statement* statement, enum nm_iam_condition_operator op, const char* key)
{
    struct nm_iam_condition* c = nm_condition_new_with_key(op, key);
    if (c == NULL || !nm_statement_add_condition(statement, c)) {
        nm_iam_free(c);
        return NULL;
    }
    return c;
}

bool nm_iam_configuration_condition_add_value(struct nm_iam_condition* condition, const char* value)
{
    return nm_condition_add_value(condition, value);
}

struct nm_iam_role* nm_iam_configuration_role_new(const char* name)
{
    return nm_iam_role_new(name);
}

void nm_iam_configuration_role_free(struct nm_iam_role* role)
{
    nm_iam_role_free(role);
}

bool nm_iam_configuration_role_add_policy(struct nm_iam_role* role, const char* policy)
{
    return nm_iam_role_add_policy(role, policy);
}
