#include "nc_iam_coap.h"
#include "nc_iam.h"

#include "nc_coap_server.h"

#include <stdlib.h>

static void nc_iam_coap_list_users(struct nabto_coap_server_request* request, void* userData);

static void access_denied(struct nabto_coap_server_request* request);

static void internal_error(struct nabto_coap_server_request* request);

static void bad_request(struct nabto_coap_server_request* request);

static void ok_response(struct nabto_coap_server_request* request, uint16_t code);


void nc_iam_coap_register_handlers(struct nc_device_context* device)
{
    nabto_coap_server_add_resource(nc_coap_server_get_server(&device->coap), NABTO_COAP_CODE_GET,
                                   (const char*[]){"iam", "users", NULL},
                                   nc_iam_coap_list_users, device);
    /* nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_GET, */
    /*                                (const char*[]){"iam", "users", "{user}"}, */
    /*                                nc_iam_coap_get_user, device); */
    /* nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_PUT, */
    /*                                (const char*[]){"iam", "users", "{user}", NULL }, */
    /*                                nc_iam_coap_create_user, device); */
    /* nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_DELETE, */
    /*                                (const char*[]){"iam", "users", "{user}", NULL}, */
    /*                                nc_iam_coap_delete_user, device); */
    /* nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_PUT, */
    /*                                (const char*[]){"iam", "users", "{user}", "roles", "{role}", NULL}, */
    /*                                nc_iam_coap_add_role_to_user, device); */
    /* nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_DELETE, */
    /*                                (const char*[]){"iam", "users", "{user}", "roles", "{role}", NULL}, */
    /*                                nc_iam_coap_remove_role_from_user, device); */


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
void nc_iam_coap_list_users(struct nabto_coap_server_request* request, void* userData)
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
            internal_error(request);
        } else {
            create_cbor_response(request, cbor, used);
        }
    } else {
        // return 403
        access_denied(request);
    }
}


void access_denied(struct nabto_coap_server_request* request)
{
    nabto_coap_server_create_error_response(request, 403, "Access Denied");
}

void internal_error(struct nabto_coap_server_request* request)
{
    nabto_coap_server_create_error_response(request, 500, "Internal Error");
}

void bad_request(struct nabto_coap_server_request* request)
{
    nabto_coap_server_create_error_response(request, 400, "Bad Request");
}

void ok_response(struct nabto_coap_server_request* request, uint16_t code)
{
    struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
    nabto_coap_server_response_set_code(response, code);
    nabto_coap_server_response_ready(response);
}
