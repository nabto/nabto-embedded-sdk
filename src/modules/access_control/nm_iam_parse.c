#include "nm_iam_parse.h"

#include <cjson/cJSON.h>

/**
Example policy
{
  "version": 1,
  "name": "FirmwareUpdate",
  "statements": [
    {
      "effect": "allow",
      "actions": [ "firmeware:update", "firmware:show" ]
    }
  ]
}
*/

/**
 * Example policy

{
  "version": 1,
  "name": "SshTunnels",
  "statements": [
    {
      "effect": "allow",
      "actions": [ "tcptunnel:Open", "tcptunnel:Get" ],
      "conditions": [
        { "StringEqual": { "tcptunnel:Host": [ "localhost" ] } },
        { "integerEqual": { "tcptunnel:Port": [ 22 ] } }
      ]
    },
    {
      "effect": "allow",
      "actions": [ "tcptunnel:List" ]
    }
  ]
}
 */


/**
 * Example policy

{
  "version": 1,
  "name": "ShowOwnTunnels",
  "statements": [
    {
      "effect": "allow",
      "actions": [ "tcptunnel:Show" ],
      "condition": [
        { "StringEqual": { "tcptunnel:UserId": [ "${connection:UserId}" ] } }
      ]
    }
  ]
}
 */



bool nm_iam_parse_policy(struct nm_iam* iam, const char* json)
{
    cJSON* root = cJSON_Parse(json);
    bool status;
    if (root == NULL) {
        return false;
    }

    status = nm_iam_parse_policy_json(&iam, root);

    cJSON_Delete(root);
    return status;
}

bool nm_iam_parse_policy_json(struct nm_iam* iam, cJSON* root)
{
    const cJSON* version = NULL;
    const cJSON* name = NULL;
    const cJSON* statements = NULL;
    version = cJSON_GetObjectItemCaseSensitive(root, "version");
    name = cJSON_GetObjectItemCaseSensitive(root, "name");
    statements = cJSON_GetObjectItemCaseSensitive(root, "statements");
    if (!cJSON_IsNumber(version) ||
        !cJSON_IsString(name) ||
        !cJSON_IsArray(statements))
    {
        return false;
    }

    if (version->valueint != 1) {
        // invalid version
        return false;
    }

}
