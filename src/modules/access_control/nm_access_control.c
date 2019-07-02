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

void nm_iam_add_policy(struct nm_iam* iam, struct nm_iam_policy* policy)
{
    nm_iam_list_insert_entry_back(&iam->policies, policy);
}

struct nm_iam_variable_instance* nm_iam_find_variable(struct nm_iam_list* variableInstances, struct nm_iam_variable* variable)
{
    struct nm_iam_list_entry* iterator = variableInstances->sentinel.next;
    while(iterator != &variableInstances->sentinel) {
        struct nm_iam_variable_instance* currentVariable = (struct nm_iam_variable_instance*)iterator->item;
        if (currentVariable->variable == variable) {
            return currentVariable;
        }
        iterator = iterator->next;
    }
    return NULL;
}

bool nm_iam_expression_has_all_variables(struct nm_iam_expression* expression, struct nm_iam_list* variableInstances)
{
    if (expression->type == NM_IAM_EXPRESSION_TYPE_PREDICATE) {
        struct nm_iam_predicate* predicate = &expression->data.predicate;
        if (nm_iam_find_variable(variableInstances, predicate->lhs) != NULL) {
            if (predicate->rhs.type == NM_IAM_PREDICATE_ITEM_TYPE_VARIABLE) {
                return (nm_iam_find_variable(variableInstances, predicate->rhs.data.variable) != NULL);
            } else {
                return true;
            }
        } else {
            return false;
        }
    } else if (expression->type == NM_IAM_EXPRESSION_TYPE_BOOLEAN_EXPRESSION) {
        struct nm_iam_boolean_expression* booleanExpression = &expression->data.booleanExpression;
        return
            nm_iam_expression_has_all_variables(booleanExpression->lhs, variableInstances) &&
            nm_iam_expression_has_all_variables(booleanExpression->rhs, variableInstances);
    }

    return false;
}

bool nm_iam_evaluate_string_equal(struct nm_iam_value* lhs, struct nm_iam_value* rhs)
{
    if (lhs->type == NM_IAM_VALUE_TYPE_STRING && rhs->type == NM_IAM_VALUE_TYPE_STRING) {
        return (strcmp(lhs->data.string, rhs->data.string) == 0);
    }
    return false;
}

bool nm_iam_evaluate_number_equal(struct nm_iam_value* lhs, struct nm_iam_value* rhs)
{
    if (lhs->type == NM_IAM_VALUE_TYPE_NUMBER && rhs->type == NM_IAM_VALUE_TYPE_NUMBER) {
        return (lhs->data.number == rhs->data.number);
    }
    return false;
}

bool nm_iam_evaluate_predicate(struct nm_iam_predicate* predicate, struct nm_iam_list* variableInstances)
{
    struct nm_iam_value lhs;
    struct nm_iam_value rhs;

    struct nm_iam_variable_instance* lhsVariableInstance = nm_iam_find_variable(variableInstances, predicate->lhs);
    lhs = lhsVariableInstance->value;

    if (predicate->rhs.type == NM_IAM_PREDICATE_ITEM_TYPE_VARIABLE) {
        struct nm_iam_variable_instance* rhsVariableInstance = nm_iam_find_variable(variableInstances, predicate->rhs.data.variable);
        rhs = rhsVariableInstance->value;
    } else if (predicate->rhs.type == NM_IAM_PREDICATE_ITEM_TYPE_VALUE) {
        rhs = predicate->rhs.data.value;
    } else {
        // unknown rhs type
        return false;
    }

    if (predicate->type == NM_IAM_PREDICATE_TYPE_STRING_EQUAL) {
        return nm_iam_evaluate_string_equal(&lhs, &rhs);
    } else if (predicate->type == NM_IAM_PREDICATE_TYPE_NUMBER_EQUAL) {
        return nm_iam_evaluate_number_equal(&lhs, &rhs);
    } else {
        // unknown predicate
        return false;
    }

    // never here
    return false;
}

bool nm_iam_evaluate_expression(struct nm_iam_expression* expression, struct nm_iam_list* variableInstances)
{
    if (expression->type == NM_IAM_EXPRESSION_TYPE_PREDICATE) {
        struct nm_iam_predicate* predicate = &expression->data.predicate;
        struct nm_iam_variable_instance* lhs = nm_iam_find_variable(variableInstances, predicate->lhs);


    }
    return false;
}

enum nm_iam_evaluation_result nm_iam_eval_statement(struct nm_iam_statement* statement, struct nm_iam_user* user, struct nm_iam_list* variableInstances, struct nm_iam_action* action)
{
    // 1. check that action matches
    // 2. check that the conditions has all the required variables.
    // 3. check if the conditions evaluates to true or false.
    return NM_IAM_EVALUATION_RESULT_DENY;
}

bool nm_iam_has_access_to_action(struct nm_iam* iam, struct nm_iam_user* user, struct nm_iam_list* variableInstances, struct nm_iam_action* action)
{
    //bool granted = false;
    /* for (role r : roles) { */
    /*     for (policy p : policies) { */
    /*         for (statement s : statements) { */

    /*         } */
    /*     } */
    /* } */
    return false;
}

bool nm_iam_add_variable(struct nm_iam* iam, const char* name, enum nm_iam_value_type type)
{
    struct nm_iam_variable* variable = (struct nm_iam_variable*)malloc(sizeof(struct nm_iam_variable));
    variable->name = name;
    variable->type = type;
    nm_iam_list_insert_entry_back(&iam->variables, variable);
    return true;
}

struct nm_iam_variable* nm_iam_get_variable(struct nm_iam* iam, const char* name)
{
    struct nm_iam_list_entry* iterator = iam->variables.sentinel.next;
    while (iterator != &iam->variables.sentinel) {
        struct nm_iam_variable* variable = (struct nm_iam_variable*)iterator->item;
        if (strcmp(variable->name, name) == 0) {
            return variable;
        }
        iterator = iterator->next;
    }
    return NULL;
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

void nm_iam_policy_add_statement(struct nm_iam_policy* policy, struct nm_iam_statement* statement)
{
    nm_iam_list_insert_entry_back(&policy->statements, statement);
}

struct nm_iam_statement* nm_iam_statement_new()
{
    struct nm_iam_statement* statement = (struct nm_iam_statement*)malloc(sizeof(struct nm_iam_statement));
    memset(statement,0,sizeof(struct nm_iam_statement));
    nm_iam_list_init(&statement->actions);

    return statement;
}

void nm_iam_statement_free(struct nm_iam_statement* statement)
{
    nm_iam_list_clear(&statement->actions);

    if (statement->conditions != NULL) {
        nm_iam_expression_free(statement->conditions);
    }
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

void nm_iam_statement_add_action(struct nm_iam_statement* statement, struct nm_iam_action* action)
{
    nm_iam_list_insert_entry_back(&statement->actions, action);
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

struct nm_iam_expression* nm_iam_expression_new()
{
    return (struct nm_iam_expression*)malloc(sizeof(struct nm_iam_expression));
}

void nm_iam_expression_free(struct nm_iam_expression* expression)
{
    free(expression);
}

struct nm_iam_expression* nm_iam_expression_and(struct nm_iam_expression* lhs, struct nm_iam_expression* rhs)
{
    struct nm_iam_expression* expression = nm_iam_expression_new();
    expression->type = NM_IAM_BOOLEAN_EXPRESSION_TYPE_AND;
    expression->data.booleanExpression.lhs = lhs;
    expression->data.booleanExpression.rhs = rhs;
    return expression;
}

struct nm_iam_expression* nm_iam_expression_string_equal(struct nm_iam_variable* lhs, struct nm_iam_predicate_item item)
{
    struct nm_iam_expression* expression = nm_iam_expression_new();
    expression->data.predicate.type = NM_IAM_PREDICATE_TYPE_STRING_EQUAL;
    expression->data.predicate.lhs = lhs;
    expression->data.predicate.rhs = item;
    return expression;
}

struct nm_iam_expression* nm_iam_expression_number_equal(struct nm_iam_variable* lhs, struct nm_iam_predicate_item rhs)
{
    struct nm_iam_expression* expression = nm_iam_expression_new();
    expression->data.predicate.type = NM_IAM_PREDICATE_TYPE_NUMBER_EQUAL;
    expression->data.predicate.lhs = lhs;
    expression->data.predicate.rhs = rhs;
    return expression;
}

struct nm_iam_predicate_item nm_iam_predicate_item_string(const char* string)
{
    struct nm_iam_predicate_item item;
    item.type = NM_IAM_PREDICATE_ITEM_TYPE_VALUE;
    item.data.value.type = NM_IAM_VALUE_TYPE_STRING;
    item.data.value.data.string = string;
    return item;
}

struct nm_iam_predicate_item nm_iam_predicate_item_number(uint32_t number)
{
    struct nm_iam_predicate_item item;
    item.type = NM_IAM_PREDICATE_ITEM_TYPE_VALUE;
    item.data.value.type = NM_IAM_VALUE_TYPE_NUMBER;
    item.data.value.data.number = number;
    return item;
}

struct nm_iam_predicate_item nm_iam_predicate_item_variable(struct nm_iam_variable* variable)
{
    struct nm_iam_predicate_item item;
    item.type = NM_IAM_PREDICATE_ITEM_TYPE_VARIABLE;
    item.data.variable = variable;
    return item;
}
