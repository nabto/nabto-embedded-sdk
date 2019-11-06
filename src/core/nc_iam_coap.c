#include "nc_iam_coap.h"
#include "nc_iam.h"

#include "nc_coap_server.h"

#include <cbor.h>

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
    // TODO: make coap resources removable
    struct nabto_coap_server_resource* resource;
    struct nabto_coap_server* server = nc_coap_server_get_server(&device->coapServer);
    // TODO: check if add fails
nabto_coap_server_add_resource(server, NABTO_COAP_CODE_GET,
                                   (const char*[]){"iam", "users", NULL},
                                   nc_iam_coap_users_list, device, &resource);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_GET,
                                   (const char*[]){"iam", "users", "{user}", NULL},
                                   nc_iam_coap_users_get, device, &resource);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_PUT,
                                   (const char*[]){"iam", "users", "{user}", NULL },
                                   nc_iam_coap_users_create, device, &resource);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_DELETE,
                                   (const char*[]){"iam", "users", "{user}", NULL },
                                   nc_iam_coap_users_delete, device, &resource);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_PUT,
                                   (const char*[]){"iam", "users", "{user}", "fingerprints", "{fingerprint}", NULL },
                                   nc_iam_coap_users_add_fingerprint, device, &resource);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_DELETE,
                                   (const char*[]){"iam", "users", "{user}", "fingerprints", "{fingerprint}", NULL },
                                   nc_iam_coap_users_remove_fingerprint, device, &resource);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_PUT,
                                   (const char*[]){"iam", "users", "{user}", "roles", "{role}", NULL },
                                   nc_iam_coap_users_add_role, device, &resource);
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_DELETE,
                                   (const char*[]){"iam", "users", "{user}", "roles", "{role}", NULL },
                                   nc_iam_coap_users_remove_role, device, &resource);
}


static void create_cbor_response(struct nabto_coap_server_request* request, void* cbor, size_t cborLength)
{
    nabto_coap_error ec;
    nabto_coap_server_response_set_code(request, NABTO_COAP_CODE(2,05));
    nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);

    ec = nabto_coap_server_response_set_payload(request, cbor, cborLength);
    if (ec != NABTO_COAP_ERROR_OK) {
        error_response(request, nc_coap_server_error_module_to_core(ec));
    } else {
        // On errors we should still cleanup the request
        nabto_coap_server_response_ready(request);
        nabto_coap_server_request_free(request);
    }
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

    uint8_t cborAttributes[128];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, cborAttributes, 128, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "IAM:UserId");
    cbor_encode_text_stringz(&map, user);
    cbor_encoder_close_container(&encoder, &map);

    size_t used = cbor_encoder_get_buffer_size(&encoder, cborAttributes);

    ec = nc_iam_check_access(connection, "IAM:GetUser", &cborAttributes, used);
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

    uint8_t cborAttributes[128];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, cborAttributes, 128, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "IAM:UserId");
    cbor_encode_text_stringz(&map, user);
    cbor_encoder_close_container(&encoder, &map);

    size_t used = cbor_encoder_get_buffer_size(&encoder, cborAttributes);

    ec = nc_iam_check_access(connection, "IAM:CreateUser", &cborAttributes, used);
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

    uint8_t cborAttributes[128];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, cborAttributes, 128, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "IAM:UserId");
    cbor_encode_text_stringz(&map, user);
    cbor_encoder_close_container(&encoder, &map);

    size_t used = cbor_encoder_get_buffer_size(&encoder, cborAttributes);
    ec = nc_iam_check_access(connection, "IAM:DeleteUser", &cborAttributes, used);
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

    uint8_t cborAttributes[128];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, cborAttributes, 128, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "IAM:UserId");
    cbor_encode_text_stringz(&map, user);
    cbor_encoder_close_container(&encoder, &map);

    size_t used = cbor_encoder_get_buffer_size(&encoder, cborAttributes);

    ec = nc_iam_check_access(connection, "IAM:AddFingerprintUser", &cborAttributes, used);
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

    uint8_t cborAttributes[128];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, cborAttributes, 128, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "IAM:UserId");
    cbor_encode_text_stringz(&map, user);
    cbor_encoder_close_container(&encoder, &map);

    size_t used = cbor_encoder_get_buffer_size(&encoder, cborAttributes);

    ec = nc_iam_check_access(connection, "IAM:RemoveFingerprintUser", &cborAttributes, used);
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

    uint8_t cborAttributes[128];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, cborAttributes, 128, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "IAM:UserId");
    cbor_encode_text_stringz(&map, user);
    cbor_encoder_close_container(&encoder, &map);

    size_t used = cbor_encoder_get_buffer_size(&encoder, cborAttributes);

    ec = nc_iam_check_access(connection, "IAM:AddRoleUser", &cborAttributes, used);
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

    uint8_t cborAttributes[128];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, cborAttributes, 128, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "IAM:UserId");
    cbor_encode_text_stringz(&map, user);
    cbor_encoder_close_container(&encoder, &map);

    size_t used = cbor_encoder_get_buffer_size(&encoder, cborAttributes);

    ec = nc_iam_check_access(connection, "IAM:RemoveRoleUser", &cborAttributes, used);
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
    // If we cannot send error response, we cannot fail nicely, ignoring errors
    nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,03), "Access Denied");
    nabto_coap_server_request_free(request);
}

nabto_coap_code ec_to_coap_code(np_error_code ec)
{
    switch (ec) {
        case NABTO_EC_NOT_FOUND: return NABTO_COAP_CODE(4,04);
        case NABTO_EC_IN_USE: return NABTO_COAP_CODE(4,00);
        case NABTO_EC_INVALID_ARGUMENT: return NABTO_COAP_CODE(4,00);
        default: return NABTO_COAP_CODE(5,00);
    }
}

void error_response(struct nabto_coap_server_request* request, np_error_code ec)
{
    // If we cannot send error response, we cannot fail nicely, ignoring errors
    nabto_coap_server_send_error_response(request, ec_to_coap_code(ec), np_error_code_to_string(ec));
    nabto_coap_server_request_free(request);
}

void ok_response(struct nabto_coap_server_request* request, nabto_coap_code code)
{
    nabto_coap_server_response_set_code(request, code);
    // on errors we should still cleanup the request
    nabto_coap_server_response_ready(request);
    nabto_coap_server_request_free(request);
}
