#include <nabto/nabto_device_config.h>

#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)

#include "nc_spake2.h"
#include "nc_cbor.h"
#include "nc_coap.h"
#include "nc_connection.h"
#include <core/nc_coap_server.h>

#include <tinycbor/cbor.h>

void nc_spake2_handle_coap_1(struct nc_coap_server_request* request, void* data);
void nc_spake2_handle_coap_2(struct nc_coap_server_request* request, void* data);

np_error_code nc_spake2_coap_init(struct nc_spake2_module* module, struct nc_coap_server_context* coap) {
    nabto_coap_error err = nc_coap_server_add_resource(coap, NABTO_COAP_METHOD_POST,
                                         (const char*[]){"p2p", "pwd-auth", "1", NULL},
                                         &nc_spake2_handle_coap_1, module,
                                         &module->spake21);
    if (err != NABTO_COAP_ERROR_OK) {
        return nc_coap_error_to_core(err);
    }

    err = nc_coap_server_add_resource(coap, NABTO_COAP_METHOD_POST,
                                         (const char*[]){"p2p", "pwd-auth", "2", NULL},
                                         &nc_spake2_handle_coap_2, module,
                                         &module->spake22);

    return nc_coap_error_to_core(err);
}

void nc_spake2_coap_deinit(struct nc_spake2_module* module)
{
    if (module->spake21 != NULL) {
        nc_coap_server_remove_resource(module->spake21);
        module->spake21 = NULL;
    }
    if (module->spake22 != NULL) {
        nc_coap_server_remove_resource(module->spake22);
        module->spake22 = NULL;
    }
}


/*
{
    "Username": "user id to distinguish users TBD",
    "T": binary encoding of the point according to SEC1, 2.3.3 (mbedtls_ecp_point_write_binary)
}
*/
static bool read_username_and_password(struct nc_spake2_password_request* passwordRequest, uint8_t* payload, size_t payloadLength)
{
    CborParser parser;
    CborValue map;
    if (cbor_parser_init(payload, payloadLength, 0, &parser, &map) != CborNoError) {
        return false;
    }

    // Read Username
    // Read T
    CborValue username;
    CborValue T;
    if (cbor_value_map_find_value(&map, "Username", &username) != CborNoError ||
        cbor_value_map_find_value(&map, "T", &T) != CborNoError) {
        return false;
    }

    if (!nc_cbor_copy_text_string(&username, &passwordRequest->username,
                                  4096) ||
        !nc_cbor_copy_byte_string(&T, &passwordRequest->T, &passwordRequest->Tlen, 256)) {
        return false;
    }
    return true;
}

void nc_spake2_handle_coap_1(struct nc_coap_server_request* request, void* data)
{
    uint8_t* payload = NULL;
    size_t payloadLength = 0;

    struct nc_spake2_module* spake2 = data;

    if (spake2->tokens == 0) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,29), NULL);
        nc_coap_server_request_free(request);
        return;
    }

    int32_t contentFormat = nc_coap_server_request_get_content_format(request);
    struct nc_spake2_password_request* passwordRequest = NULL;
    nc_coap_server_request_get_payload(request, (void**)&payload, &payloadLength);

    if (spake2->passwordRequestHandler == NULL) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,04), NULL);
    } else if (contentFormat != NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,15), NULL);
    } else if (payload == NULL) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,00), NULL);
    } else {
        passwordRequest = nc_spake2_password_request_new();
        if (passwordRequest == NULL) {
            nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(5,00), NULL);
        } else {
            passwordRequest->coapRequest = request;
            passwordRequest->pl = spake2->pl;
            if (!read_username_and_password(passwordRequest, payload,
                                            payloadLength)) {
                nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,00), NULL);
            } else {
                spake2->passwordRequestHandler(passwordRequest, spake2->passwordRequestHandlerData);
                return;
            }
        }
    }
    // if we get to here an error response has been generated. Return in the ok case.
    nc_spake2_password_request_free(passwordRequest);
    nc_coap_server_request_free(request);
}


void nc_spake2_handle_coap_2(struct nc_coap_server_request* request, void* data)
{
    uint8_t* payload = NULL;
    size_t payloadLength = 0;
    struct nc_connection* connection = nc_coap_server_request_get_connection(request);

    struct nc_spake2_module* spake2 = data;

    if (spake2->tokens == 0) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,29), NULL);
        nc_coap_server_request_free(request);
        return;
    }

    nc_coap_server_request_get_payload(request, (void**)&payload, &payloadLength);

    if (spake2->passwordRequestHandler == NULL) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,04), NULL);
    } else if (payload == NULL || payloadLength != 32) {
        nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,00), NULL);
    } else {
        if (!connection->hasSpake2Key) {
            nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,00), NULL);
        } else {
            uint8_t responseData[32];
            if (spake2->pl->spake2.key_confirmation(payload, payloadLength, connection->spake2Key, 32, responseData, 32) != NABTO_EC_OK) {
                nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,01), NULL);
                nc_spake2_spend_token(spake2);
            } else {
                connection->passwordAuthenticated = true;
                nc_coap_server_response_set_code_human(request, 201);
                nc_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM);
                nc_coap_server_response_set_payload(request, responseData, 32);
                nc_coap_server_response_ready(request);

            }
        }
    }
    nc_coap_server_request_free(request);
}

#endif
