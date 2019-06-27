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

}
