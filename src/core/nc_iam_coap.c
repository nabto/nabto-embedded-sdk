#include "nc_iam_coap.h"
#include "nc_iam.h"

#include "nc_coap_server.h"

#include <stdlib.h>

static void nc_iam_coap_users_list(struct nabto_coap_server_request* request, void* userData);
static void nc_iam_coap_users_get(struct nabto_coap_server_request* request, void* userData);
static void nc_iam_coap_users_create(struct nabto_coap_server_request* request, void* userData);
static void nc_iam_coap_users_delete(struct nabto_coap_server_request* request, void* userData);
static void nc_iam_coap_users_add_fingerprint(struct nabto_coap_server_request* request, void* userData);
static void nc_iam_coap_users_remove_fingerprint(struct nabto_coap_server_request* request, void* userData);
static void nc_iam_coap_users_add_role(struct nabto_coap_server_request* request, void* userData);
static void nc_iam_coap_users_remove_role(struct nabto_coap_server_request* request, void* userData);



static nabto_coap_code ec_to_coap_code(np_error_code ec);
static void access_denied(struct nabto_coap_server_request* request);
static void error_response(struct nabto_coap_server_request* request, np_error_code ec);
static void ok_response(struct nabto_coap_server_request* request, nabto_coap_code code);


void nc_iam_coap_register_handlers(struct nc_device_context* device)
{
    struct nabto_coap_server* server = nc_coap_server_get_server(&device->coap);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_GET,
                                   (const char*[]){"iam", "users", NULL},
                                   nc_iam_coap_users_list, device);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_GET,
                                   (const char*[]){"iam", "users", "{user}", NULL},
                                   nc_iam_coap_users_get, device);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_PUT,
                                   (const char*[]){"iam", "users", "{user}", NULL },
                                   nc_iam_coap_users_create, device);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_DELETE,
                                   (const char*[]){"iam", "users", "{user}", NULL },
                                   nc_iam_coap_users_delete, device);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_PUT,
                                   (const char*[]){"iam", "users", "{user}", "fingerprints", "{fingerprint}", NULL },
                                   nc_iam_coap_users_add_fingerprint, device);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_DELETE,
                                   (const char*[]){"iam", "users", "{user}", "fingerprints", "{fingerprint}", NULL },
                                   nc_iam_coap_users_remove_fingerprint, device);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_PUT,
                                   (const char*[]){"iam", "users", "{user}", "roles", "{role}", NULL },
                                   nc_iam_coap_users_add_role, device);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_DELETE,
                                   (const char*[]){"iam", "users", "{user}", "roles", "{role}", NULL },
                                   nc_iam_coap_users_remove_role, device);
}


static void create_cbor_response(struct nabto_coap_server_request* request, void* cbor, size_t cborLength)
{
    struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
    nabto_coap_server_response_set_code(response, NABTO_COAP_CODE(2,05));
    nabto_coap_server_response_set_content_format(response, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_coap_server_response_set_payload(response, cbor, cborLength);
    nabto_coap_server_response_ready(response);
}

/**
 * CoAP GET /iam/users
 */
void nc_iam_coap_users_list(struct nabto_coap_server_request* request, void* userData)
{
    struct nc_device_context* device = userData;
    np_error_code ec;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);
    ec = nc_iam_check_access(connection, "IAM:ListUsers", NULL, 0);
    if (ec == NABTO_EC_OK) {
        uint8_t cbor[128];
        size_t used;

        ec = nc_iam_list_users(&device->iam, cbor, 128, &used);
        if (ec) {
            error_response(request, ec);
        } else {
            create_cbor_response(request, cbor, used);
        }
    } else {
        // return 403
        access_denied(request);
    }
}

/**
 * CoAP GET /iam/users/{user}
 */
void nc_iam_coap_users_get(struct nabto_coap_server_request* request, void* userData)
{
    struct nc_device_context* device = userData;
    np_error_code ec;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    const char* user = nabto_coap_server_request_get_parameter(request, "user");

    struct nc_iam_attributes attributes;
    memset(&attributes, 0, sizeof(struct nc_iam_attributes));
    nc_iam_attributes_add_string(&attributes, "IAM:UserId", user);

    ec = nc_iam_check_access_attributes(connection, "IAM:GetUser", &attributes);
    if (ec == NABTO_EC_OK) {
        uint8_t cbor[128];
        size_t used;

        ec = nc_iam_user_get(&device->iam, user, cbor, 128, &used);
        if (ec) {
            error_response(request, ec);
        } else {
            create_cbor_response(request, cbor, used);
        }
    } else {
        // return 403
        access_denied(request);
    }
}

/**
 * CoAP PUT /iam/users/{user}
 */
void nc_iam_coap_users_create(struct nabto_coap_server_request* request, void* userData)
{
    struct nc_device_context* device = userData;
    np_error_code ec;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    const char* user = nabto_coap_server_request_get_parameter(request, "user");

    struct nc_iam_attributes attributes;
    memset(&attributes, 0, sizeof(struct nc_iam_attributes));
    nc_iam_attributes_add_string(&attributes, "IAM:UserId", user);

    ec = nc_iam_check_access_attributes(connection, "IAM:CreateUser", &attributes);
    if (ec == NABTO_EC_OK) {
        ec = nc_iam_create_user(&device->iam, user);
        if (ec) {
            error_response(request, ec);
        } else {
            ok_response(request, NABTO_COAP_CODE(2,01));
        }
    } else {
        // return 403
        access_denied(request);
    }
}

/**
 * CoAP DELETE /iam/users/{user}
 */
void nc_iam_coap_users_delete(struct nabto_coap_server_request* request, void* userData)
{
    struct nc_device_context* device = userData;
    np_error_code ec;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    const char* user = nabto_coap_server_request_get_parameter(request, "user");

    struct nc_iam_attributes attributes;
    memset(&attributes, 0, sizeof(struct nc_iam_attributes));
    nc_iam_attributes_add_string(&attributes, "IAM:UserId", user);

    ec = nc_iam_check_access_attributes(connection, "IAM:DeleteUser", &attributes);
    if (ec == NABTO_EC_OK) {
        ec = nc_iam_delete_user(device, user);
        if (ec) {
            error_response(request, ec);
        } else {
            ok_response(request, NABTO_COAP_CODE(2,02));
        }
    } else {
        // return 403
        access_denied(request);
    }
}

void nc_iam_coap_users_add_fingerprint(struct nabto_coap_server_request* request, void* userData)
{
    struct nc_device_context* device = userData;
    np_error_code ec;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    const char* user = nabto_coap_server_request_get_parameter(request, "user");
    const char* fingerprint = nabto_coap_server_request_get_parameter(request, "fingerprint");

    struct nc_iam_attributes attributes;
    memset(&attributes, 0, sizeof(struct nc_iam_attributes));
    nc_iam_attributes_add_string(&attributes, "IAM:UserId", user);

    ec = nc_iam_check_access_attributes(connection, "IAM:AddFingerprintUser", &attributes);
    if (ec == NABTO_EC_OK) {
        ec = nc_iam_user_add_fingerprint(&device->iam, user, fingerprint);
        if (ec) {
            error_response(request, ec);
        } else {
            ok_response(request, NABTO_COAP_CODE(2,01));
        }
    } else {
        // return 403
        access_denied(request);
    }
}

void nc_iam_coap_users_remove_fingerprint(struct nabto_coap_server_request* request, void* userData)
{
    struct nc_device_context* device = userData;
    np_error_code ec;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    const char* user = nabto_coap_server_request_get_parameter(request, "user");
    const char* fingerprint = nabto_coap_server_request_get_parameter(request, "fingerprint");

    struct nc_iam_attributes attributes;
    memset(&attributes, 0, sizeof(struct nc_iam_attributes));
    nc_iam_attributes_add_string(&attributes, "IAM:UserId", user);

    ec = nc_iam_check_access_attributes(connection, "IAM:RemoveFingerprintUser", &attributes);
    if (ec == NABTO_EC_OK) {
        ec = nc_iam_user_remove_fingerprint(&device->iam, user, fingerprint);
        if (ec) {
            error_response(request, ec);
        } else {
            ok_response(request, NABTO_COAP_CODE(2,02));
        }
    } else {
        // return 403
        access_denied(request);
    }
}

void nc_iam_coap_users_add_role(struct nabto_coap_server_request* request, void* userData)
{
    struct nc_device_context* device = userData;
    np_error_code ec;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    const char* user = nabto_coap_server_request_get_parameter(request, "user");
    const char* role = nabto_coap_server_request_get_parameter(request, "role");

    struct nc_iam_attributes attributes;
    memset(&attributes, 0, sizeof(struct nc_iam_attributes));
    nc_iam_attributes_add_string(&attributes, "IAM:UserId", user);

    ec = nc_iam_check_access_attributes(connection, "IAM:AddRoleUser", &attributes);
    if (ec == NABTO_EC_OK) {
        ec = nc_iam_user_add_role(&device->iam, user, role);
        if (ec) {
            error_response(request, ec);
        } else {
            ok_response(request, NABTO_COAP_CODE(2,01));
        }
    } else {
        // return 403
        access_denied(request);
    }
}

void nc_iam_coap_users_remove_role(struct nabto_coap_server_request* request, void* userData)
{
    struct nc_device_context* device = userData;
    np_error_code ec;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    const char* user = nabto_coap_server_request_get_parameter(request, "user");
    const char* role = nabto_coap_server_request_get_parameter(request, "role");

    struct nc_iam_attributes attributes;
    memset(&attributes, 0, sizeof(struct nc_iam_attributes));
    nc_iam_attributes_add_string(&attributes, "IAM:UserId", user);

    ec = nc_iam_check_access_attributes(connection, "IAM:RemoveRoleUser", &attributes);
    if (ec == NABTO_EC_OK) {
        ec = nc_iam_user_remove_role(&device->iam, user, role);
        if (ec) {
            error_response(request, ec);
        } else {
            ok_response(request, NABTO_COAP_CODE(2,02));
        }
    } else {
        // return 403
        access_denied(request);
    }
}

void access_denied(struct nabto_coap_server_request* request)
{
    nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(4,03), "Access Denied");
}

nabto_coap_code ec_to_coap_code(np_error_code ec)
{
    switch (ec) {
        case NABTO_EC_NO_SUCH_RESOURCE: return NABTO_COAP_CODE(4,04);
        case NABTO_EC_IN_USE: return NABTO_COAP_CODE(4,00);
        case NABTO_EC_INVALID_ARGUMENT: return NABTO_COAP_CODE(4,00);
        default: return NABTO_COAP_CODE(5,00);
    }
}

void error_response(struct nabto_coap_server_request* request, np_error_code ec)
{
    nabto_coap_server_create_error_response(request, ec_to_coap_code(ec), np_error_code_to_string(ec));
}

void ok_response(struct nabto_coap_server_request* request, nabto_coap_code code)
{
    struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
    nabto_coap_server_response_set_code(response, code);
    nabto_coap_server_response_ready(response);
}
