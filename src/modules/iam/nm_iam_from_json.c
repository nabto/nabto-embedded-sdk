#include "nm_iam_from_json.h"

#include "nm_iam_role.h"
#include "nm_iam_user.h"


struct nm_iam_role* nm_iam_role_from_json(const cJSON* json)
{
    cJSON* id = cJSON_GetObjectItem(json, "Id");
    cJSON* policies = cJSON_GetObjectItem(json, "Policies");

    if (!cJSON_IsString(id) ||
        !cJSON_IsArray(policies))
    {
        return NULL;
    }

    struct nm_iam_role* role = nm_iam_role_new(id->valuestring);
    size_t policiesSize = cJSON_GetArraySize(policies);
    for (size_t i = 0; i < policiesSize; i++) {
        cJSON* p = cJSON_GetArrayItem(policies, i);
        // todo handle non strings.
        if (cJSON_IsString(p)) {
            np_string_set_add(&role->policies, p->valuestring);
        }
    }
    return role;
}

bool load_attributes(struct np_string_map* attributes, const cJSON* json)
{
    if (!cJSON_IsObject(json)) {
        return false;
    }

    cJSON* item;
    cJSON_ArrayForEach(item, json)
    {
        if (cJSON_IsString(item)) {
            np_string_map_insert(attributes, item->string, item->valuestring);
        }
    }

    return true;
}

struct nm_iam_user* nm_iam_user_from_json(const cJSON* json)
{
    cJSON* id = cJSON_GetObjectItem(json, "Id");
    cJSON* serverConnectToken = cJSON_GetObjectItem(json, "ServerConnectToken");
    cJSON* fingerprint = cJSON_GetObjectItem(json, "Fingerprint");
    cJSON* attributes = cJSON_GetObjectItem(json, "Attributes");
    cJSON* roles = cJSON_GetObjectItem(json, "Roles");

    if (!cJSON_IsString(id)) {
        return NULL;
    }

    struct nm_iam_user* user = nm_iam_user_new(id->valuestring);
    if (user == NULL) {
        return NULL;
    }

    if (cJSON_IsString(serverConnectToken)) {
        user->serverConnectToken = strdup(serverConnectToken->valuestring);
    }

    if (cJSON_IsArray(roles)) {
        size_t rolesSize = cJSON_GetArraySize(roles);
        for (size_t i = 0; i < rolesSize; i++) {
            cJSON* item = cJSON_GetArrayItem(roles, i);
            if (cJSON_IsString(item)) {
                np_string_set_add(&user->roles, item->valuestring);
            }
        }
    }

}
