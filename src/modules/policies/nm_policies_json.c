#include "nm_policies_json.h"

struct nm_condition* nm_condition_from_json(const cJSON* condition)
{
    if (!cJSON_IsObject(condition)) {
        return NULL;
    }
}

struct nm_statement* nm_statement_from_json(const cJSON* json, struct nm_statement* statement)
{
    if (!cJSON_IsObject(statement)) {
        return NULL;
    }

    cJSON* effect = cJSON_GetObjectItem(json, "Effect");
    cJSON* actions = cJSON_GetObjectItem(json, "Actions");
    cJSON* conditions = cJSON_GetObjectItem(json, "Conditions");

    if (!cJSON_IsString(effect) ||
        !cJSON_IsArrray(actions))
    {
        return NULL;
    }
    char* effectString = effect->valuestring;

    if (strcmp(effectString, "Allow") == 0) {
        statement->effect = NM_EFFECT_ALLOW;
    } else if (strcmp(effectString, "Deny") == 0) {
        statement->effect = NM_EFFECT_DENY;
    } else {
        return NULL;
    }

    size_t actionsSize = cJSON_GetArraySize(actions);
    size_t i;
    for (i = 0; i < actionsSize; i++) {
        cJSON* action = cJSON_GetArrayItem(actions, i);
        if (!cJSON_IsString(action)) {
            return false;
        }
        if (np_string_set_add(&statement->actions, action->valuestring) != NABTO_EC_OK) {
            return false;
        }
    }

    if (cJSON_IsArray(conditions)) {
        size_t conditionsSize = cJSON_GetArraySize(conditions);
        for (i = 0; i < conditionsSize; i++) {
            struct nm_condition* c = nm_condition_new();

        }
    }
}

struct nm_policy* nm_policy_from_json(const cJSON* policy)
{
    if (!cJSON_IsObject(policy)) {
        return NULL;
    }
    cJSON* id = cJSON_GetObjectItem(policy, "Id");
    cJSON* statements = cJSON_GetObjectItem(policy, "Statements");
    if (!cJSON_IsString(id) ||
        !cJSON_IsArray(statements))
    {
        return NULL;
    }

    size_t count = cJSON_GetArraySize(statements);
    size_t i;
    for (i = 0; i < count; i++) {
        cJSON* statement = cJSON_GetArrayItem(statements, i);
        struct nm_statement* s = nm_statement_from_json(statement);
        if (s == NULL) {
            return NULL;
        }
        // TODO add to
    }

}
