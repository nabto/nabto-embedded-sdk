#include "nm_policies_to_json.h"

#include "nm_effect.h"
#include "nm_statement.h"
#include "nm_policy.h"
#include "nm_condition.h"

#include <platform/np_vector.h>
#include <nn/string_set.h>

static cJSON* nm_condition_to_json(const struct nm_condition* condition);
static cJSON* nm_conditions_to_json(const struct np_vector* conditions);
static cJSON* nm_string_set_to_json(const struct nn_string_set* set);
static cJSON* nm_statement_to_json(const struct nm_statement* statement);
static cJSON* nm_statements_to_json(const struct np_vector* statements);


cJSON* nm_policy_to_json(const struct nm_policy* policy)
{
    cJSON* json = cJSON_CreateObject();
    cJSON_AddItemToObject(json, "Id", cJSON_CreateString(policy->id));

    cJSON_AddItemToObject(json, "Statements", nm_statements_to_json(&policy->statements));
    return json;
}

// local functions

cJSON* nm_condition_to_json(const struct nm_condition* condition)
{
    cJSON* kv = cJSON_CreateObject();
    cJSON_AddItemToObject(kv, condition->key, nm_string_set_to_json(&condition->values));

    cJSON* op = cJSON_CreateObject();
    cJSON_AddItemToObject(op, nm_condition_operator_to_string(condition->op), kv);
    return op;
}

cJSON* nm_conditions_to_json(const struct np_vector* conditions)
{
    cJSON* array = cJSON_CreateArray();
    struct np_vector_iterator it;
    for (np_vector_front(conditions, &it);
         !np_vector_end(&it);
         np_vector_next(&it))
    {
        struct nm_condition* condition = np_vector_get_element(&it);
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

cJSON* nm_statement_to_json(const struct nm_statement* statement)
{
    cJSON* json = cJSON_CreateObject();
    if (statement->effect == NM_EFFECT_ALLOW) {
        cJSON_AddItemToObject(json, "Effect", cJSON_CreateString("Allow"));
    } else if (statement->effect == NM_EFFECT_DENY) {
        cJSON_AddItemToObject(json, "Effect", cJSON_CreateString("Deny"));
    }

    cJSON_AddItemToObject(json, "Actions", nm_string_set_to_json(&statement->actions));

    if (!np_vector_empty(&statement->conditions)) {
        cJSON_AddItemToObject(json, "Conditions", nm_conditions_to_json(&statement->conditions));
    }

    return json;
}

cJSON* nm_statements_to_json(const struct np_vector* statements)
{
    cJSON* array = cJSON_CreateArray();
    struct np_vector_iterator it;
    for (np_vector_front(statements, &it);
         !np_vector_end(&it);
         np_vector_next(&it))
    {
        struct nm_statement* statement = np_vector_get_element(&it);
        cJSON_AddItemToArray(array, nm_statement_to_json(statement));
    }
    return array;
}
