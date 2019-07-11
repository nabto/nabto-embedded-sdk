#include "nm_iam_coap.h"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdbool.h>

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

static void nm_iam_coap_create_user(NabtoDeviceCoapRequest* request, void* userData);
static void nm_iam_coap_delete_user(NabtoDeviceCoapRequest* request, void* userData);
static void nm_iam_coap_list_users(NabtoDeviceCoapRequest* request, void* userData);
static void nm_iam_coap_get_user(NabtoDeviceCoapRequest* request, void* userData);
static void nm_iam_coap_add_role_to_user(NabtoDeviceCoapRequest* request, void* userData);
static void nm_iam_coap_remove_role_from_user(NabtoDeviceCoapRequest* request, void* userData);


static void access_denied(NabtoDeviceCoapRequest* request);

static void internal_error(NabtoDeviceCoapRequest* request);

static void bad_request(NabtoDeviceCoapRequest* request);

static void ok_response(NabtoDeviceCoapRequest* request, uint16_t code);

static bool add_iam_attributes(NabtoDeviceCoapRequest* request, NabtoDeviceIamEnv* iamEnv);

void nm_iam_coap_register_handlers(NabtoDevice* device)
{
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_GET,
                                   (const char*[]){"iam", "users", NULL},
                                   nm_iam_coap_list_users, device);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_GET,
                                   (const char*[]){"iam", "users", "{user}"},
                                   nm_iam_coap_get_user, device);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_PUT,
                                   (const char*[]){"iam", "users", "{user}", NULL },
                                   nm_iam_coap_create_user, device);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_DELETE,
                                   (const char*[]){"iam", "users", "{user}", NULL},
                                   nm_iam_coap_delete_user, device);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_PUT,
                                   (const char*[]){"iam", "users", "{user}", "roles", "{role}", NULL},
                                   nm_iam_coap_add_role_to_user, device);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_DELETE,
                                   (const char*[]){"iam", "users", "{user}", "roles", "{role}", NULL},
                                   nm_iam_coap_remove_role_from_user, device);


}

/**
 * CoAP PUT /iam/users/{user}
 *
 * if the user already exists return
 */
void nm_iam_coap_create_user(NabtoDeviceCoapRequest* request, void* userData)
{

    // check access
    // add user
    // persist iam
    // return 201
}

/**
 * CoAP DELETE /iam/users/:id
 */
void nm_iam_coap_delete_user(NabtoDeviceCoapRequest* request, void* userData)
{
    // check access "iam:DeleteUser"
    // delete user
    // persist iam
    // return 202
}

static void create_cbor_response(NabtoDeviceCoapRequest* request, void* cbor, size_t cborLength)
{
    NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
    nabto_device_coap_response_set_code(response, 205);
    nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_device_coap_response_set_payload(response, cbor, cborLength);
    nabto_device_coap_response_ready(response);
}

/**
 * CoAP GET /iam/users
 */
void nm_iam_coap_list_users(NabtoDeviceCoapRequest* request, void* userData)
{
    NabtoDevice* device = (NabtoDevice*)userData;
    NabtoDeviceIamEnv* env = nabto_device_iam_env_from_coap_request(request);
    NabtoDeviceError ec = nabto_device_iam_check_action(env, "iam:ListUsers");
    if (ec == NABTO_DEVICE_EC_OK) {
        void* cbor;
        size_t cborLength;
        ec = nabto_device_iam_users_list(device, &cbor, &cborLength);
        if (ec) {
            nabto_device_coap_error_response(request, 500, "");
        } else {
            create_cbor_response(request, cbor, cborLength);
            nabto_device_free(cbor);
        }
    } else {
        // return 403
        access_denied(request);
    }
}

/**
 * CoAP GET /iam/users/{user}
 * {
 *   "Name": "...",
 *   "Roles": ["...", "..."],
 *   "Fingerprints": ["...", "..."]
 * }
 */
void nm_iam_coap_get_user(NabtoDeviceCoapRequest* request, void* userData)
{
    NabtoDeviceError ec;
    NabtoDevice* device = (NabtoDevice*)userData;
    NabtoDeviceIamEnv* env = nabto_device_iam_env_from_coap_request(request);

    if (!add_iam_attributes(request, env)) {
        return internal_error(request);
    }

    ec = nabto_device_iam_check_action(env, "iam:GetUser");
    if (ec == NABTO_DEVICE_EC_OK) {
        void* cbor;
        size_t cborLength;
        ec = nabto_device_iam_users_get(device,
                                        nabto_device_coap_request_get_parameter(request, "user"),
                                        &cbor, &cborLength);
        if (ec) {
            nabto_device_coap_error_response(request, 500, "");
        } else {
            create_cbor_response(request, cbor, cborLength);
            nabto_device_free(cbor);
        }
    } else {
        access_denied(request);
    }
}

/**
 * CoAP PUT /iam/users/:userid/roles/:roleid
 */
void nm_iam_coap_add_role_to_user(NabtoDeviceCoapRequest* request, void* userData)
{
    NabtoDeviceError ec;
    NabtoDevice* device = (NabtoDevice*)userData;
    NabtoDeviceIamEnv* env = nabto_device_iam_env_from_coap_request(request);

    if (!add_iam_attributes(request, env)) {
        return internal_error(request);
    }

    ec = nabto_device_iam_check_action(env, "iam:AddRoleToUser");
    if (ec == NABTO_DEVICE_EC_OK) {
        ec = nabto_device_iam_users_add_role(device,
                                             nabto_device_coap_request_get_parameter(request, "user"),
                                             nabto_device_coap_request_get_parameter(request, "role"));
        if (ec) {
            nabto_device_coap_error_response(request, 500, "");
        } else {
            ok_response(request, 201);
        }
    } else {
        access_denied(request);
    }
}


/**
 * CoAP DELETE /iam/users/:userid/roles/:roleid
 */
void nm_iam_coap_remove_role_from_user(NabtoDeviceCoapRequest* request, void* userData)
{
    NabtoDeviceError ec;
    NabtoDevice* device = (NabtoDevice*)userData;
    NabtoDeviceIamEnv* env = nabto_device_iam_env_from_coap_request(request);
    // check access "iam:RemoveRoleFromUser"
    if (!add_iam_attributes(request, env)) {
        return internal_error(request);
    }
    ec = nabto_device_iam_check_action(env, "iam:RemoveRoleFromUser");
    if (ec == NABTO_DEVICE_EC_OK) {
        ec = nabto_device_iam_users_remove_role(device,
                                                nabto_device_coap_request_get_parameter(request, "user"),
                                                nabto_device_coap_request_get_parameter(request, "role"));
        if (ec) {
            nabto_device_coap_error_response(request, 500, "");
        } else {
            ok_response(request, 202);
        }
    } else {
        access_denied(request);
    }
}


/**
 * CoAP GET /iam/roles
 * { "Roles": ["role1", "role2", "role3"] }
 */
void nm_iam_coap_list_roles()
{
    // check access "iam:ListRoles"
}

bool add_iam_attributes(NabtoDeviceCoapRequest* request, NabtoDeviceIamEnv* iamEnv)
{
    NabtoDeviceError ec;
    const char* user = nabto_device_coap_request_get_parameter(request, "user");
    if (user != NULL) {
        ec = nabto_device_iam_env_add_attribute_string(iamEnv, "iam:User", user);
        if (ec) {
            return false;
        }
    }

    const char* role = nabto_device_coap_request_get_parameter(request, "role");
    if (role != NULL) {
        ec = nabto_device_iam_env_add_attribute_string(iamEnv, "iam:Role", role);
        if (ec) {
            return false;
        }
    }

    return true;
}

void access_denied(NabtoDeviceCoapRequest* request)
{
    nabto_device_coap_error_response(request, 403, "Access Denied");
}

void internal_error(NabtoDeviceCoapRequest* request)
{
    nabto_device_coap_error_response(request, 500, "Internal Error");
}

void bad_request(NabtoDeviceCoapRequest* request)
{
    nabto_device_coap_error_response(request, 400, "Bad Request");
}

void ok_response(NabtoDeviceCoapRequest* request, uint16_t code)
{
    NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
    nabto_device_coap_response_set_code(response, code);
    nabto_device_coap_response_ready(response);
}
