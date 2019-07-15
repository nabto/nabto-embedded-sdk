#include "nm_iam.h"
#include "nm_iam_util.h"

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
    nm_iam_list_init(&iam->attributeNames);
}

struct nm_iam_attribute* nm_iam_find_attribute(struct nm_iam_attributes* attributes, struct nm_iam_attribute_name* attributeName)
{
    struct nm_iam_list_entry* iterator = attributes->attributes.sentinel.next;
    while(iterator != &attributes->attributes.sentinel) {
        struct nm_iam_attribute* current = (struct nm_iam_attribute*)iterator->item;
        if (current->name == attributeName) {
            return current;
        }
        iterator = iterator->next;
    }
    return NULL;
}

bool nm_iam_expression_has_all_attributes(struct nm_iam_expression* expression, struct nm_iam_attributes* attributes)
{
    if (expression->type == NM_IAM_EXPRESSION_TYPE_PREDICATE) {
        struct nm_iam_predicate* predicate = &expression->data.predicate;
        if (predicate->lhs.type == NM_IAM_PREDICATE_ITEM_TYPE_ATTRIBUTE) {
            if (nm_iam_find_attribute(attributes, predicate->lhs.data.attributeName) == NULL) {
                return false;
            }
        }
        if (predicate->rhs.type == NM_IAM_PREDICATE_ITEM_TYPE_ATTRIBUTE) {
            if (nm_iam_find_attribute(attributes, predicate->rhs.data.attributeName) == NULL) {
                return false;
            }
        }
        return true;
    } else if (expression->type == NM_IAM_EXPRESSION_TYPE_BOOLEAN_EXPRESSION) {
        struct nm_iam_boolean_expression* booleanExpression = &expression->data.booleanExpression;
        struct nm_iam_list_entry* iterator = booleanExpression->expressions.sentinel.next;

        while (iterator != &booleanExpression->expressions.sentinel) {
            struct nm_iam_expression* current = (struct nm_iam_expression*)iterator->item;
            if (!nm_iam_expression_has_all_attributes(current, attributes)) {
                return false;
            }
            iterator = iterator->next;
        }
        return true;
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

bool nm_iam_evaluate_predicate(struct nm_iam_predicate* predicate, struct nm_iam_attributes* attributes)
{
    struct nm_iam_value lhs;
    struct nm_iam_value rhs;

    if (predicate->lhs.type == NM_IAM_PREDICATE_ITEM_TYPE_ATTRIBUTE) {
        struct nm_iam_attribute* lhsAttribute = nm_iam_find_attribute(attributes, predicate->lhs.data.attributeName);
        lhs = lhsAttribute->value;
    } else if (predicate->lhs.type == NM_IAM_PREDICATE_ITEM_TYPE_VALUE) {
        lhs = predicate->lhs.data.value;
    } else {
        return false;
    }

    if (predicate->rhs.type == NM_IAM_PREDICATE_ITEM_TYPE_ATTRIBUTE) {
        struct nm_iam_attribute* rhsAttribute = nm_iam_find_attribute(attributes, predicate->rhs.data.attributeName);
        rhs = rhsAttribute->value;
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

bool nm_iam_evaluate_expression(struct nm_iam_expression* expression, struct nm_iam_attributes* attributes)
{
    if (expression->type == NM_IAM_EXPRESSION_TYPE_PREDICATE) {
        struct nm_iam_predicate* predicate = &expression->data.predicate;
        return nm_iam_evaluate_predicate(predicate, attributes);
    } else if (expression->type == NM_IAM_EXPRESSION_TYPE_BOOLEAN_EXPRESSION) {
        struct nm_iam_boolean_expression* booleanExpression = &expression->data.booleanExpression;

        if (booleanExpression->type == NM_IAM_BOOLEAN_EXPRESSION_TYPE_AND) {
            struct nm_iam_list_entry* iterator = booleanExpression->expressions.sentinel.next;
            while(iterator != &booleanExpression->expressions.sentinel) {
                struct nm_iam_expression* current = (struct nm_iam_expression*)iterator->item;
                if (!nm_iam_evaluate_expression(current, attributes)) {
                    return false;
                }
                iterator = iterator->next;
            }
            return true;
        } else if (booleanExpression->type == NM_IAM_BOOLEAN_EXPRESSION_TYPE_OR) {
            struct nm_iam_list_entry* iterator = booleanExpression->expressions.sentinel.next;
            while(iterator != &booleanExpression->expressions.sentinel) {
                struct nm_iam_expression* current = (struct nm_iam_expression*)iterator->item;
                if (nm_iam_evaluate_expression(current, attributes)) {
                    return true;
                }
                iterator = iterator->next;
            }
            return false;
        } else {
            return false;
        }
    }
    return false;
}

enum nm_iam_evaluation_result nm_iam_evaluate_statement(struct nm_iam_statement* statement, struct nm_iam_attributes* attributes, struct nm_iam_action* action)
{
    // 1. check that action matches
    // 2. check that the conditions has all the required attributes.
    // 3. check if the conditions evaluates to true or false.

    if (!nm_iam_find_action_in_list(&statement->actions, action)) {
        return NM_IAM_EVALUATION_RESULT_NONE;
    }

    // if conditions is NULL then the check is only based on the list of actions.
    if (statement->conditions == NULL) {
        if (statement->effect == NM_IAM_EFFECT_ALLOW) {
            return NM_IAM_EVALUATION_RESULT_ALLOW;
        } else if (statement->effect == NM_IAM_EFFECT_DENY) {
            return NM_IAM_EVALUATION_RESULT_DENY;
        } else {
            // never here
            return NM_IAM_EVALUATION_RESULT_NONE;
        }
    }

    if (!nm_iam_expression_has_all_attributes(statement->conditions, attributes)) {
        // TODO decide if this is deny or none
        return NM_IAM_EVALUATION_RESULT_NONE;
    }


    if (nm_iam_evaluate_expression(statement->conditions, attributes)) {
        if (statement->effect == NM_IAM_EFFECT_ALLOW) {
            return NM_IAM_EVALUATION_RESULT_ALLOW;
        } else if (statement->effect == NM_IAM_EFFECT_DENY) {
            return NM_IAM_EVALUATION_RESULT_DENY;
        }
    } else {
        return NM_IAM_EVALUATION_RESULT_NONE;
    }

    // never here
    return NM_IAM_EVALUATION_RESULT_NONE;

}

bool nm_iam_has_access_to_action(struct nm_iam* iam, struct nm_iam_user* user, struct nm_iam_attributes* attributes, struct nm_iam_action* action)
{
    bool granted = false;
    /* for (role r : roles) { */
    /*     for (policy p : policies) { */
    /*         for (statement s : statements) { */

    /*         } */
    /*     } */
    /* } */

    struct nm_iam_list_entry* roleIterator = user->roles.sentinel.next;
    while(roleIterator != &user->roles.sentinel) {
        struct nm_iam_role* role = (struct nm_iam_role*)roleIterator->item;
        struct nm_iam_list_entry* policyIterator = role->policies.sentinel.next;
        while(policyIterator != & role->policies.sentinel) {
            struct nm_iam_policy* policy = (struct nm_iam_policy*)policyIterator->item;
            struct nm_iam_list_entry* statementIterator = policy->statements.sentinel.next;
            while (statementIterator != &policy->statements.sentinel) {
                struct nm_iam_statement* statement = (struct nm_iam_statement*)(statementIterator->item);
                enum nm_iam_evaluation_result result = nm_iam_evaluate_statement(statement, attributes, action);
                if (result == NM_IAM_EVALUATION_RESULT_NONE) {
                    // no change
                } else if (result == NM_IAM_EVALUATION_RESULT_ALLOW) {
                    granted = true;
                } else if (result == NM_IAM_EVALUATION_RESULT_DENY) {
                    granted = false;
                }
                statementIterator = statementIterator->next;
            }
            policyIterator = policyIterator->next;

        }
        roleIterator = roleIterator->next;
    }
    return granted;
}

bool nm_iam_add_attribute_name(struct nm_iam* iam, const char* name, enum nm_iam_value_type type)
{
    struct nm_iam_attribute_name* attributeName = (struct nm_iam_attribute_name*)malloc(sizeof(struct nm_iam_attribute_name));
    attributeName->name = name;
    attributeName->type = type;
    nm_iam_list_insert_entry_back(&iam->attributeNames, attributeName);
    return true;
}

struct nm_iam_attribute_name* nm_iam_get_attribute_name(struct nm_iam* iam, const char* name)
{
    struct nm_iam_list_entry* iterator = iam->attributeNames.sentinel.next;
    while (iterator != &iam->attributeNames.sentinel) {
        struct nm_iam_attribute_name* attribute = (struct nm_iam_attribute_name*)iterator->item;
        if (strcmp(attribute->name, name) == 0) {
            return attribute;
        }
        iterator = iterator->next;
    }

    struct nm_iam_attribute_name* attributeName = (struct nm_iam_attribute_name*)malloc(sizeof(struct nm_iam_attribute_name));
    attributeName->name = name;
    nm_iam_list_insert_entry_back(&iam->attributeNames, attributeName);

    return attributeName;
}

void nm_iam_add_role(struct nm_iam* iam, struct nm_iam_role* role)
{
    nm_iam_list_insert_entry_back(&iam->roles, role);
}

struct nm_iam_role* nm_iam_find_role(struct nm_iam* iam, const char* name)
{
    struct nm_iam_list_entry* iterator = iam->roles.sentinel.next;
    while(iterator != &iam->roles.sentinel) {
        struct nm_iam_role* role = (struct nm_iam_role*)iterator->item;
        if (strcmp(role->name, name) == 0) {
            return role;
        }
        iterator = iterator->next;
    }
    return NULL;
}

void nm_iam_add_user(struct nm_iam* iam, struct nm_iam_user* user)
{
    nm_iam_list_insert_entry_back(&iam->users, user);
}

struct nm_iam_user* nm_iam_find_user(struct nm_iam* iam, const char* name)
{
    struct nm_iam_list_entry* iterator = iam->users.sentinel.next;
    while(iterator != &iam->users.sentinel) {
        struct nm_iam_user* user = (struct nm_iam_user*)iterator->item;
        if (strcmp(user->name, name) == 0) {
            return user;
        }
        iterator = iterator->next;
    }
    return NULL;
}

void nm_iam_add_policy(struct nm_iam* iam, struct nm_iam_policy* policy)
{
    nm_iam_list_insert_entry_back(&iam->policies, policy);
}

struct nm_iam_policy* nm_iam_find_policy(struct nm_iam* iam, const char* name)
{
    struct nm_iam_list_entry* iterator = iam->policies.sentinel.next;
    while(iterator != &iam->policies.sentinel) {
        struct nm_iam_policy* policy = (struct nm_iam_policy*)iterator->item;
        if (strcmp(policy->name, name) == 0) {
            return policy;
        }
        iterator = iterator->next;
    }
    return NULL;
}

struct nm_iam_action* nm_iam_action_new(const char* name)
{
    struct nm_iam_action* action = (struct nm_iam_action*)strdup(name);
    return action;
}

void nm_iam_action_free(struct nm_iam_action* action)
{
    free(action);
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
    // insert the action and return the newly created action
    struct nm_iam_action* a = nm_iam_action_new(action);
    nm_iam_list_insert_entry_back(&iam->actions, a);
    return a;
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

struct nm_iam_expression* nm_iam_expression_new(enum nm_iam_expression_type type)
{
    struct nm_iam_expression* expression = (struct nm_iam_expression*)malloc(sizeof(struct nm_iam_expression));
    expression->type = type;

    if (type == NM_IAM_EXPRESSION_TYPE_BOOLEAN_EXPRESSION) {
        nm_iam_list_init(&expression->data.booleanExpression.expressions);
    }
    return expression;
}

struct nm_iam_expression* nm_iam_boolean_expression_new(enum nm_iam_boolean_expression_type type)
{
    struct nm_iam_expression* expression = nm_iam_expression_new(NM_IAM_EXPRESSION_TYPE_BOOLEAN_EXPRESSION);
    expression->data.booleanExpression.type = type;
    return expression;
}

struct nm_iam_expression* nm_iam_predicate_new(enum nm_iam_predicate_type type)
{
    struct nm_iam_expression* expression = nm_iam_expression_new(NM_IAM_EXPRESSION_TYPE_PREDICATE);
    expression->data.predicate.type = type;
    return expression;
}

void nm_iam_expression_free(struct nm_iam_expression* expression)
{
    // todo free expression list
    free(expression);
}

struct nm_iam_expression* nm_iam_expression_and()
{
    struct nm_iam_expression* expression = nm_iam_expression_new(NM_IAM_EXPRESSION_TYPE_BOOLEAN_EXPRESSION);
    expression->data.booleanExpression.type = NM_IAM_BOOLEAN_EXPRESSION_TYPE_AND;
    return expression;
}

void nm_iam_boolean_expression_add_expression(struct nm_iam_expression* expression, struct nm_iam_expression* e)
{
    nm_iam_list_insert_entry_back(&expression->data.booleanExpression.expressions, e);
}

struct nm_iam_expression* nm_iam_expression_string_equal(struct nm_iam_predicate_item lhs, struct nm_iam_predicate_item rhs)
{
    struct nm_iam_expression* expression = nm_iam_expression_new(NM_IAM_EXPRESSION_TYPE_PREDICATE);
    expression->data.predicate.type = NM_IAM_PREDICATE_TYPE_STRING_EQUAL;
    expression->data.predicate.lhs = lhs;
    expression->data.predicate.rhs = rhs;
    return expression;
}

struct nm_iam_expression* nm_iam_expression_number_equal(struct nm_iam_predicate_item lhs, struct nm_iam_predicate_item rhs)
{
    struct nm_iam_expression* expression = nm_iam_expression_new(NM_IAM_EXPRESSION_TYPE_PREDICATE);
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

struct nm_iam_predicate_item nm_iam_predicate_item_attribute(struct nm_iam* iam, const char* name)
{
    struct nm_iam_attribute_name* attributeName = nm_iam_get_attribute_name(iam, name);
    struct nm_iam_predicate_item item;
    item.type = NM_IAM_PREDICATE_ITEM_TYPE_ATTRIBUTE;
    item.data.attributeName = attributeName;
    return item;
}

struct nm_iam_role* nm_iam_role_new(const char* name)
{
    struct nm_iam_role* role = (struct nm_iam_role*)malloc(sizeof(struct nm_iam_role));
    role->name = name;
    nm_iam_list_init(&role->policies);
    return role;
}

void nm_iam_role_free(struct nm_iam_role* role)
{
    // TODO free list of roles
    free(role);
}

void nm_iam_role_add_policy(struct nm_iam_role* role, struct nm_iam_policy* policy)
{
    nm_iam_list_insert_entry_back(&role->policies, policy);
}


// USERS

struct nm_iam_user* nm_iam_user_new(const char* name)
{
    struct nm_iam_user* user = (struct nm_iam_user*)malloc(sizeof(struct nm_iam_user));
    user->name = name;
    nm_iam_list_init(&user->roles);
    return user;
}

void nm_iam_user_free(struct nm_iam_user* user)
{
    // todo free list of roles.
    free(user);
}

void nm_iam_user_add_role(struct nm_iam_user* user, struct nm_iam_role* role)
{
    nm_iam_list_insert_entry_back(&user->roles, role);
}

struct nm_iam_attribute* nm_iam_attribute_new(struct nm_iam_attribute_name* name)
{
    struct nm_iam_attribute* attribute = (struct nm_iam_attribute*)malloc(sizeof(struct nm_iam_attribute));
    attribute->name = name;
    return attribute;
}

void nm_iam_attribute_free(struct nm_iam_attribute* attribute)
{
    free(attribute);
}

struct nm_iam_attributes* nm_iam_attributes_new()
{
    struct nm_iam_attributes* attributes = (struct nm_iam_attributes*)malloc(sizeof(struct nm_iam_attributes));
    nm_iam_list_init(&attributes->attributes);
    return attributes;
}

void nm_iam_attributes_free(struct nm_iam_attributes* attributes)
{
    // todo free list
    free(attributes);
}

void nm_iam_attributes_add_string(struct nm_iam* iam, struct nm_iam_attributes* attributes, const char* attributeName, const char* attributeValue)
{
    struct nm_iam_attribute_name* name = nm_iam_get_attribute_name(iam, attributeName);
    struct nm_iam_attribute* attribute = nm_iam_attribute_new(name);
    attribute->value.type = NM_IAM_VALUE_TYPE_STRING;
    attribute->value.data.string = attributeValue;

    nm_iam_list_insert_entry_back(&attributes->attributes, attribute);
}

void nm_iam_attributes_add_number(struct nm_iam* iam, struct nm_iam_attributes* attributes, const char* attributeName, uint32_t number)
{
    struct nm_iam_attribute_name* name = nm_iam_get_attribute_name(iam, attributeName);
    struct nm_iam_attribute* attribute = nm_iam_attribute_new(name);
    attribute->value.type = NM_IAM_VALUE_TYPE_NUMBER;
    attribute->value.data.number = number;

    nm_iam_list_insert_entry_back(&attributes->attributes, attribute);
}
