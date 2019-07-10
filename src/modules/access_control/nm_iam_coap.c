#include "nm_iam_coap.h"


// create_user
// delete_user
// list_users
// get_user
// add_role_to_user
// remove_role_from_user


// TODO add these in the future
// create_role
// delete_role
// list_roles
// get_role
// add_policy_to_role
// remove_policy_from_role

// TODO add these in the future
// create_policy
// delete_policy
// list_policies
// get_policy


/**
 * CoAP POST /iam/users
 * {
 *   "Name": "Foobar",
 *   "Roles": [...]
 * }
 */
void nm_iam_coap_create_user(NabtoDeviceCoapRequest* request, struct nm_iam* iam)
{
    // check access
    // add user
    // persist iam
    // return 201
}

/**
 * CoAP DELETE /iam/users/:id
 */
void nm_iam_coap_delete_user(NabtoDeviceCoapRequest* request, struct nm_iam* iam)
{
    // check access "iam:DeleteUser"
    // delete user
    // persist iam
    // return 202
}

/**
 * CoAP GET /iam/users
 */
void nm_iam_coap_list_users(NabtoDeviceCoapRequest* request)
{
    // check access "iam:ListUsers"
    // return 200
}

/**
 * CoAP GET /iam/users/:id
 * {
 *   "Name": "...",
 *   "Roles": ["...", "..."],
 *   "Fingerprints": ["...", "..."]
 * }
 */
void nm_iam_coap_get_user(NabtoDeviceCoapRequest* request)
{
    // check access "iam:GetUser"
    // return 200
}

/**
 * CoAP PUT /iam/users/:userid/roles/:roleid
 */
void nm_iam_coap_add_role_to_user()
{
    // check access "iam:AddRoleToUser"
}


/**
 * CoAP DELETE /iam/users/:userid/roles/:roleid
 */
void nm_iam_coap_remove_role_from_user()
{
    // check access "iam:RemoveRoleFromUser"
}


/**
 * CoAP GET /iam/roles
 * { "Roles": ["role1", "role2", "role3"] }
 */
void nm_iam_coap_list_roles()
{
    // check access "iam:ListRoles"
}
