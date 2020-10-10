#include "nm_iam_to_json.h"

#include "nm_iam_role.h"
#include "nm_iam_user.h"

#include <cjson/cJSON.h>

cJSON* nm_iam_role_to_json(struct nm_iam_role* role)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "Id", cJSON_CreateString(role->id));

    cJSON* policies = cJSON_CreateArray();
    const char* str;
    NN_STRING_SET_FOREACH(str, &role->policies) {
        cJSON_AddItemToArray(policies, cJSON_CreateString(str));
    }

    cJSON_AddItemToObject(root, "Policies", policies);
    return root;
}


cJSON* nm_iam_user_to_json(struct nm_iam_user* user)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "Id", cJSON_CreateString(user->id));
    if (user->name != NULL) {
        cJSON_AddItemToObject(root, "Name", cJSON_CreateString(user->name));
    }
    if (user->fingerprint != NULL) {
        cJSON_AddItemToObject(root, "Fingerprint", cJSON_CreateString(user->fingerprint));
    }
    if (user->serverConnectToken != NULL) {
        cJSON_AddItemToObject(root, "ServerConnectToken", cJSON_CreateString(user->serverConnectToken));
    }

    if (user->role != NULL) {
        cJSON_AddItemToObject(root, "Role", cJSON_CreateString(user->role));
    }

    if (!nn_string_map_empty(&user->attributes)) {
        cJSON* kvPairs = cJSON_CreateObject();
        struct nn_string_map_iterator it;
        for (it = nn_string_map_begin(&user->attributes); !nn_string_map_is_end(&it); nn_string_map_next(&it))
        {
            cJSON_AddItemToObject(kvPairs, nn_string_map_key(&it), cJSON_CreateString(nn_string_map_value(&it)));
        }
        cJSON_AddItemToObject(root, "Attributes", kvPairs);
    }
    return root;
}
