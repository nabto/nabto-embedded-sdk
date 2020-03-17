#include "nm_iam_to_json.h"

#include "nm_iam_role.h"
#include "nm_iam_user.h"

#include <cjson/cJSON.h>

cJSON* nm_iam_role_to_json(struct nm_iam_role* role)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "Id", cJSON_CreateString(role->id));

    cJSON* policies = cJSON_CreateArray();
    struct np_string_set_iterator it;
    for(np_string_set_front(&role->policies, &it);
        !np_string_set_end(&it);
        np_string_set_next(&it))
    {
        const char* str = np_string_set_get_element(&it);
        cJSON_AddItemToArray(policies, cJSON_CreateString(str));
    }

    cJSON_AddItemToObject(root, "Policies", policies);
    return root;
}


cJSON* nm_iam_user_to_json(struct nm_iam_user* user)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "Id", cJSON_CreateString(user->id));
    if (user->fingerprint != NULL) {
        cJSON_AddItemToObject(root, "Fingerprint", cJSON_CreateString(user->fingerprint));
    }
    if (user->serverConnectToken != NULL) {
        cJSON_AddItemToObject(root, "ServerConnectToken", cJSON_CreateString(user->serverConnectToken));
    }

    if (!np_string_set_empty(&user->roles)) {
        cJSON* array = cJSON_CreateArray();
        struct np_string_set_iterator it;
        for (np_string_set_front(&user->roles, &it);
             !np_string_set_end(&it);
             np_string_set_next(&it))
        {
            const char* role = np_string_set_get_element(&it);
            cJSON_AddItemToArray(array, cJSON_CreateString(role));
        }
    }

    if (!np_string_map_empty(&user->attributes)) {
        cJSON* kvPairs = cJSON_CreateObject();
        struct np_string_map_iterator it;
        for(np_string_map_front(&user->attributes, &it);
            !np_string_map_end(&it);
            np_string_map_next(&it))
        {
            struct np_string_map_item* item = np_string_map_get_element(&it);
            cJSON_AddItemToObject(kvPairs, item->key, cJSON_CreateString(item->value));
        }
    }
    return root;
}
