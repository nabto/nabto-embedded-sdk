#include "nm_iam_to_json.h"

#include "nm_iam_role.h"

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
