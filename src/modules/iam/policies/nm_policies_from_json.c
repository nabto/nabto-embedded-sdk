#include "nm_policies_from_json.h"
#include "nm_condition.h"
#include "nm_policy.h"
#include "nm_statement.h"

#include <nn/string.h>
#include <nn/string_set.h>

#include "../nm_iam_allocator.h"

#include <string.h>

static bool nm_statement_from_json_parse(const cJSON* actions, const cJSON* conditions, struct nm_iam_statement* statement, struct nn_log* logger);
static bool nm_condition_from_json_parse(const cJSON* kv, struct nm_iam_condition* condition, struct nn_log* logger);
static bool nm_policy_from_json_parse(const cJSON* json, struct nm_iam_policy* policy, struct nn_log* logger);


struct nm_iam_condition* nm_condition_from_json(const cJSON* json, struct nn_log* logger)
{
    if (!cJSON_IsObject(json)) {
        return NULL;
    }
    cJSON* operation = cJSON_GetArrayItem(json, 0);
    if (operation == NULL || !cJSON_IsObject(operation)) {
        return NULL;
    }

    enum nm_iam_condition_operator op = NM_IAM_CONDITION_OPERATOR_BOOL;
    if (!nm_condition_parse_operator(operation->string, &op)) {
        return NULL;
    }

    struct nm_iam_condition* condition = nm_condition_new(op);
    if (condition == NULL) {
        return NULL;
    }
    if (nm_condition_from_json_parse(operation->child, condition, logger)) {
        return condition;
    }
    nm_condition_free(condition);
    return NULL;
}

bool nm_condition_from_json_parse(const cJSON* kv, struct nm_iam_condition* condition, struct nn_log* logger)
{
    (void)logger;
    // json = { "key": ["value1", "value2"] }
    // An object is also an iterable array
    // string = "key", type = "array"
    if (!cJSON_IsArray(kv)) {
        return false;
    }

    condition->key = nn_strdup(kv->string, nm_iam_allocator_get());

    size_t valuesSize = cJSON_GetArraySize(kv);
    int i = 0;
    for (i = 0; i < (int)valuesSize; i++) {
        cJSON* value = cJSON_GetArrayItem(kv, i);
        if (!cJSON_IsString(value)) {
            return false;
        }
        nn_string_set_insert(&condition->values, value->valuestring);
    }

    return true;
}

struct nm_iam_statement* nm_statement_from_json(const cJSON* json, struct nn_log* logger)
{
    if (!cJSON_IsObject(json)) {
        return NULL;
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

    enum nm_iam_effect e = NM_IAM_EFFECT_DENY;

    if (strcmp(effectString, "Allow") == 0) {
        e = NM_IAM_EFFECT_ALLOW;
    } else if (strcmp(effectString, "Deny") == 0) {
        e = NM_IAM_EFFECT_DENY;
    } else {
        return NULL;
    }

    struct nm_iam_statement* s = nm_statement_new(e);
    if (s == NULL) {
        return NULL;
    }

    if (nm_statement_from_json_parse(actions, conditions, s, logger)) {
        return s;
    }
    nm_statement_free(s);
    return NULL;
}

bool nm_statement_from_json_parse(const cJSON* actions, const cJSON* conditions, struct nm_iam_statement* statement, struct nn_log* logger)
{
    size_t actionsSize = cJSON_GetArraySize(actions);
    int i = 0;
    for (i = 0; i < (int)actionsSize; i++) {
        cJSON* action = cJSON_GetArrayItem(actions, i);
        if (!cJSON_IsString(action)) {
            return false;
        }
        if (!nm_statement_add_action(statement, action->valuestring)) {
            return false;
        }
    }

    if (cJSON_IsArray(conditions)) {
        size_t conditionsSize = cJSON_GetArraySize(conditions);
        for (i = 0; i < (int)conditionsSize; i++) {
            cJSON* c = cJSON_GetArrayItem(conditions, i);
            struct nm_iam_condition* tmp = nm_condition_from_json(c, logger);
            if (tmp == NULL) {
                return false;
            }
            nn_llist_append(&statement->conditions, &tmp->listNode, tmp);
        }
    }
    return true;
}

struct nm_iam_policy* nm_policy_from_json(const cJSON* json, struct nn_log* logger)
{
    if (!cJSON_IsObject(json)) {
        return NULL;
    }
    cJSON* id = cJSON_GetObjectItem(json, "Id");
    cJSON* statements = cJSON_GetObjectItem(json, "Statements");
    if (!cJSON_IsString(id) ||
        !cJSON_IsArray(statements))
    {
        return NULL;
    }

    struct nm_iam_policy* policy = nm_policy_new(id->valuestring);

    if (policy == NULL) {
        return NULL;
    }

    if (nm_policy_from_json_parse(statements, policy, logger)) {
        return policy;
    }
    nm_policy_free(policy);
    return NULL;
}

bool nm_policy_from_json_parse(const cJSON* statements, struct nm_iam_policy* policy, struct nn_log* logger)
{
    size_t count = cJSON_GetArraySize(statements);
    int i = 0;
    for (i = 0; i < (int)count; i++) {
        cJSON* statement = cJSON_GetArrayItem(statements, i);
        struct nm_iam_statement* s = nm_statement_from_json(statement, logger);
        if (s == NULL) {
            return false;
        }
        nn_llist_append(&policy->statements, &s->listNode, s);
    }
    return true;
}
