#include "nm_policies_from_json.h"
#include "nm_condition.h"
#include "nm_statement.h"
#include "nm_policy.h"

#include <nn/string_set.h>

static bool nm_statement_from_json_parse(const cJSON* actions, const cJSON* conditions, struct nm_statement* statement, struct nn_log* logger);
static bool nm_condition_from_json_parse(const cJSON* kv, struct nm_condition* condition, struct nn_log* logger);
static bool nm_policy_from_json_parse(const cJSON* json, struct nm_policy* policy, struct nn_log* logger);


struct nm_condition* nm_condition_from_json(const cJSON* json, struct nn_log* logger)
{
    if (!cJSON_IsObject(json)) {
        return NULL;
    }
    cJSON* operation = cJSON_GetArrayItem(json, 0);
    if (operation == NULL || !cJSON_IsObject(operation)) {
        return NULL;
    }

    enum nm_condition_operator op;
    if (!nm_condition_parse_operator(operation->string, &op)) {
        return NULL;
    }

    struct nm_condition* condition = nm_condition_new(op);
    if (condition == NULL) {
        return NULL;
    }
    if (nm_condition_from_json_parse(operation->child, condition, logger)) {
        return condition;
    }
    nm_condition_free(condition);
    return NULL;
}

bool nm_condition_from_json_parse(const cJSON* kv, struct nm_condition* condition, struct nn_log* logger)
{
    // json = { "key": ["value1", "value2"] }
    // An object is also an iterable array
    // string = "key", type = "array"
    if (!cJSON_IsArray(kv)) {
        return false;
    }

    condition->key = strdup(kv->string);

    size_t valuesSize = cJSON_GetArraySize(kv);
    size_t i;
    for (i = 0; i < valuesSize; i++) {
        cJSON* value = cJSON_GetArrayItem(kv, i);
        if (!cJSON_IsString(value)) {
            return false;
        }
        nn_string_set_insert(&condition->values, value->valuestring);
    }

    return true;
}

struct nm_statement* nm_statement_from_json(const cJSON* json, struct nn_log* logger)
{
    if (!cJSON_IsObject(json)) {
        return false;
    }

    cJSON* effect = cJSON_GetObjectItem(json, "Effect");
    cJSON* actions = cJSON_GetObjectItem(json, "Actions");
    cJSON* conditions = cJSON_GetObjectItem(json, "Conditions");

    if (!cJSON_IsString(effect) ||
        !cJSON_IsArray(actions))
    {
        return NULL;
    }
    char* effectString = effect->valuestring;

    enum nm_effect e;

    if (strcmp(effectString, "Allow") == 0) {
        e = NM_EFFECT_ALLOW;
    } else if (strcmp(effectString, "Deny") == 0) {
        e = NM_EFFECT_DENY;
    } else {
        return NULL;
    }

    struct nm_statement* s = nm_statement_new(e);
    if (s == NULL) {
        return NULL;
    }

    if (nm_statement_from_json_parse(actions, conditions, s, logger)) {
        return s;
    } else {
        nm_statement_free(s);
        return NULL;
    }
}

bool nm_statement_from_json_parse(const cJSON* actions, const cJSON* conditions, struct nm_statement* statement, struct nn_log* logger)
{
    size_t actionsSize = cJSON_GetArraySize(actions);
    size_t i;
    for (i = 0; i < actionsSize; i++) {
        cJSON* action = cJSON_GetArrayItem(actions, i);
        if (!cJSON_IsString(action)) {
            return false;
        }
        if (nm_statement_add_action(statement, action->valuestring) != NABTO_EC_OK) {
            return false;
        }
    }

    if (cJSON_IsArray(conditions)) {
        size_t conditionsSize = cJSON_GetArraySize(conditions);
        for (i = 0; i < conditionsSize; i++) {
            cJSON* c = cJSON_GetArrayItem(conditions, i);
            struct nm_condition* tmp = nm_condition_from_json(c, logger);
            if (tmp == NULL) {
                return false;
            }
            if (np_vector_push_back(&statement->conditions, tmp) != NABTO_EC_OK) {
                return false;
            }
        }
    }
    return true;
}

struct nm_policy* nm_policy_from_json(const cJSON* json, struct nn_log* logger)
{
    if (!cJSON_IsObject(json)) {
        return false;
    }
    cJSON* id = cJSON_GetObjectItem(json, "Id");
    cJSON* statements = cJSON_GetObjectItem(json, "Statements");
    if (!cJSON_IsString(id) ||
        !cJSON_IsArray(statements))
    {
        return false;
    }

    struct nm_policy* policy = nm_policy_new(id->valuestring);

    if (policy == NULL) {
        return NULL;
    }

    if (nm_policy_from_json_parse(statements, policy, logger)) {
        return policy;
    }
    nm_policy_free(policy);
    return NULL;
}

bool nm_policy_from_json_parse(const cJSON* statements, struct nm_policy* policy, struct nn_log* logger)
{
    size_t count = cJSON_GetArraySize(statements);
    size_t i;
    for (i = 0; i < count; i++) {
        cJSON* statement = cJSON_GetArrayItem(statements, i);
        struct nm_statement* s = nm_statement_from_json(statement, logger);
        if (s == NULL) {
            return false;
        }
        np_vector_push_back(&policy->statements, s);
    }
    return true;
}
