#include "nm_iam_from_json.h"

struct nm_iam_role* nm_iam_role_from_json(cJSON* json)
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
