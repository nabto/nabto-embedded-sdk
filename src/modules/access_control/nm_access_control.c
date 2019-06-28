#include "nm_access_control.h"

#include <platform/np_platform.h>

#include <string.h>
#include <stdlib.h>

bool nm_access_control_can_access(uint8_t* fingerprint, enum np_access_control_permission feature)
{
    return true;
}

void np_access_control_init(struct np_platform* pl)
{
    pl->accCtrl.can_access = &nm_access_control_can_access;
}

void nm_iam_init(struct nm_iam* iam)
{
    nm_iam_list_init(&iam->users);
    nm_iam_list_init(&iam->actions);
    nm_iam_list_init(&iam->roles);
    nm_iam_list_init(&iam->policies);
    nm_iam_list_init(&iam->variables);
}

struct nm_iam_action* nm_iam_action_new(const char* name)
{
    struct nm_iam_action* action = (struct nm_iam_action*)name;
    return action;
}

void nm_iam_action_free(struct nm_iam_action* action)
{
    // the pointer is just the const char* owner elsewhere
}

bool nm_iam_add_action(struct nm_iam* iam, struct nm_iam_action* action)
{
    nm_iam_list_insert_entry_back(&iam->actions, action);
    return true;
}

struct nm_iam_action* nm_iam_get_action(struct nm_iam* iam, const char* action)
{
    struct nm_iam_list_entry* iterator = iam->actions.sentinel.next;
    while (iterator != &iam->actions.sentinel) {
        struct nm_iam_action* a = (struct nm_iam_action*)iterator->item;
        const char* name = (const char*)a;
        if (strcmp(name, action) == 0) {
            return a;
        }
        iterator = iterator->next;
    }
    return NULL;
}

struct nm_iam_policy* nm_iam_policy_new(struct nm_iam* iam, const char* name)
{
    if (strlen(name) > (NM_IAM_POLICY_NAME_LEN - 1)) {
        return false;
    }
    struct nm_iam_policy* policy = (struct nm_iam_policy*)malloc(sizeof(struct nm_iam_policy));
    memset(policy, 0, sizeof(struct nm_iam_policy));

    strcpy(policy->name, name);
    nm_iam_list_init(&policy->statements);
    return policy;
}

bool nm_iam_policy_free(struct nm_iam* iam, struct nm_iam_policy* policy)
{
    // ensure no roles is using the policy
    {
        struct nm_iam_list_entry* iterator = iam->roles.sentinel.next;
        while (iterator != &iam->roles.sentinel) {
            struct nm_iam_role* role = (struct nm_iam_role*)iterator->item;
            struct nm_iam_list_entry* policyIterator = role->policies.sentinel.next;
            while (policyIterator != &role->policies.sentinel) {
                if (policyIterator->item == (void*)policy) {
                    // policy in use
                    return false;
                }
                policyIterator = policyIterator->next;
            }
            iterator = iterator->next;
        }
    }

    // free policy
    {
        struct nm_iam_list_entry* iterator = policy->statements.sentinel.next;
        while (iterator != &policy->statements.sentinel) {
            struct nm_iam_statement* statement = (struct nm_iam_statement*)iterator->item;
            nm_iam_statement_free(statement);
            iterator = iterator->next;
        }
        nm_iam_list_clear(&policy->statements);

        free(policy);
        return true;
    }
}

struct nm_iam_statement* nm_iam_statement_new()
{
    struct nm_iam_statement* statement = (struct nm_iam_statement*)malloc(sizeof(struct nm_iam_statement));
    nm_iam_list_init(&statement->actions);
    nm_iam_list_init(&statement->conditions);
    return statement;
}

void nm_iam_statement_free(struct nm_iam_statement* statement)
{
    nm_iam_list_clear(&statement->actions);

    struct nm_iam_list_entry* iterator = statement->conditions.sentinel.next;
    while (iterator != &statement->conditions.sentinel) {
        struct nm_iam_condition* condition = (struct nm_iam_condition*)iterator->item;
        nm_iam_condition_free(condition);
        iterator = iterator->next;
    }
    nm_iam_list_clear(&statement->conditions);
    free(statement);
}

bool nm_iam_statement_has_action(struct nm_iam_statement* statement, struct nm_iam_action* action)
{
    struct nm_iam_list_entry* iterator = statement->actions.sentinel.next;
    while (iterator != &statement->actions.sentinel) {
        if (iterator->item == action) {
            return true;
        }
        iterator = iterator->next;
    }
    return false;
}

void nm_iam_list_init(struct nm_iam_list* list) {
    list->sentinel.next = &list->sentinel;
    list->sentinel.prev = &list->sentinel;
    list->sentinel.item = NULL;
}

// Remove all entries from a list. The data is not touched.
void nm_iam_list_clear(struct nm_iam_list* list)
{
    struct nm_iam_list_entry* iterator = list->sentinel.next;
    while (iterator != &list->sentinel) {
        struct nm_iam_list_entry* entry = iterator;
        iterator = iterator->next;
        nm_iam_list_entry_free(entry);
    }

    list->sentinel.next = &list->sentinel;
    list->sentinel.prev = &list->sentinel;
}

void nm_iam_list_insert_entry_back(struct nm_iam_list* list, void* item)
{
    struct nm_iam_list_entry* entry = nm_iam_list_entry_new();
    entry->item = item;
    struct nm_iam_list_entry* before = list->sentinel.prev;
    struct nm_iam_list_entry* after = &list->sentinel;

    before->next = entry;
    entry->next = after;
    after->prev = entry;
    entry->prev = before;
}

void nm_iam_list_remove_entry(struct nm_iam_list_entry* entry)
{
    struct nm_iam_list_entry* before = entry->prev;
    struct nm_iam_list_entry* after = entry->next;

    before->next = after;
    after->prev = before;

    nm_iam_list_entry_free(entry);
}

struct nm_iam_list_entry* nm_iam_list_entry_new()
{
    struct nm_iam_list_entry* entry = (struct nm_iam_list_entry*)malloc(sizeof(struct nm_iam_list_entry));
    return entry;
}

void nm_iam_list_entry_free(struct nm_iam_list_entry* entry)
{
    free(entry);
}

struct nm_iam_condition* nm_iam_condition_new()
{
    return (struct nm_iam_condition*)malloc(sizeof(struct nm_iam_condition));
}

void nm_iam_condition_free(struct nm_iam_condition* condition)
{
    free(condition);
}
