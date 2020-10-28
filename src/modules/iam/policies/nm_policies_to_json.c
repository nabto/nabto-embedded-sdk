#include "nm_policies_to_json.h"

#include "nm_statement.h"
#include "nm_policy.h"
#include "nm_condition.h"

#include <nn/llist.h>
#include <nn/string_set.h>

static cJSON* nm_condition_to_json(const struct nm_iam_condition* condition);
static cJSON* nm_conditions_to_json(const struct nn_llist* conditions);
static cJSON* nm_string_set_to_json(const struct nn_string_set* set);
static cJSON* nm_statement_to_json(const struct nm_iam_statement* statement);
static cJSON* nm_statements_to_json(const struct nn_llist* statements);


cJSON* nm_policy_to_json(const struct nm_iam_policy* policy)
{
    cJSON* json = cJSON_CreateObject();
    cJSON_AddItemToObject(json, "Id", cJSON_CreateString(policy->id));

    cJSON_AddItemToObject(json, "Statements", nm_statements_to_json(&policy->statements));
    return json;
}

// local functions

cJSON* nm_condition_to_json(const struct nm_iam_condition* condition)
{
    cJSON* kv = cJSON_CreateObject();
    cJSON_AddItemToObject(kv, condition->key, nm_string_set_to_json(&condition->values));

    cJSON* op = cJSON_CreateObject();
    cJSON_AddItemToObject(op, nm_condition_operator_to_string(condition->op), kv);
    return op;
}

cJSON* nm_conditions_to_json(const struct nn_llist* conditions)
{
    cJSON* array = cJSON_CreateArray();
    struct nm_iam_condition* condition;
    NN_LLIST_FOREACH(&condition, conditions) {
        cJSON_AddItemToArray(array, nm_condition_to_json(condition));
    }
    return array;
}

cJSON* nm_string_set_to_json(const struct nn_string_set* set)
{
    cJSON* array = cJSON_CreateArray();
    const char* str;
    NN_STRING_SET_FOREACH(str, set) {
        cJSON_AddItemToArray(array, cJSON_CreateString(str));
    }
    return array;
}

cJSON* nm_statement_to_json(const struct nm_iam_statement* statement)
{
    cJSON* json = cJSON_CreateObject();
    if (statement->effect == NM_EFFECT_ALLOW) {
        cJSON_AddItemToObject(json, "Effect", cJSON_CreateString("Allow"));
    } else if (statement->effect == NM_EFFECT_DENY) {
        cJSON_AddItemToObject(json, "Effect", cJSON_CreateString("Deny"));
    }

    cJSON_AddItemToObject(json, "Actions", nm_string_set_to_json(&statement->actions));

    if (!nn_llist_empty(&statement->conditions)) {
        cJSON_AddItemToObject(json, "Conditions", nm_conditions_to_json(&statement->conditions));
    }

    return json;
}

cJSON* nm_statements_to_json(const struct nn_llist* statements)
{
    cJSON* array = cJSON_CreateArray();
    struct nm_iam_statement* statement;
    NN_LLIST_FOREACH(&statement, statements) {
        cJSON_AddItemToArray(array, nm_statement_to_json(statement));
    }
    return array;
}
