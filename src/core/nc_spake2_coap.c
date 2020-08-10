
#include "nc_spake2.h"
#include <coap/nabto_coap_server.h>
#include <core/nc_coap_server.h>

#include <mbedtls/sha256.h>

#include <cbor.h>

void nc_spake2_handle_coap_1(struct nabto_coap_server_request* request, void* data);
void nc_spake2_handle_coap_2(struct nabto_coap_server_request* request, void* data);

void nc_spake2_coap_init(struct nc_spake2_module* module, struct nc_coap_server_context* coap) {
    nabto_coap_error err;
    err = nabto_coap_server_add_resource(nc_coap_server_get_server(coap), NABTO_COAP_CODE_POST,
                                         (const char*[]){"p2p", "pwd-auth", "1", NULL},
                                         &nc_spake2_handle_coap_1, module,
                                         &module->spake21);

    err = nabto_coap_server_add_resource(nc_coap_server_get_server(coap), NABTO_COAP_CODE_POST,
                                         (const char*[]){"p2p", "pwd-auth", "2", NULL},
                                         &nc_spake2_handle_coap_2, module,
                                         &module->spake22);
}

bool read_text_string(CborValue* value, char* out, size_t maxLength)
{
    if (!cbor_value_is_text_string(value)) {
        return false;
    }
    size_t strLength;
    cbor_value_calculate_string_length(value, &strLength);
    if (strLength > maxLength) {
        return false;
    }

    cbor_value_copy_text_string(value, out, &strLength, NULL);
    return true;
}

static bool read_group_element(CborValue* value, mbedtls_ecp_group* grp, mbedtls_ecp_point* p)
{
    uint8_t buffer[256];
    if (!cbor_value_is_byte_string(value)) {
        return false;
    }

    size_t length;
    cbor_value_calculate_string_length(value, &length);
    if (length > sizeof(buffer)) {
        return false;
    }

    cbor_value_copy_byte_string(value, buffer, &length, NULL);

    int status = mbedtls_ecp_point_read_binary(grp, p, buffer, length);
    if (status != 0) {
        return false;
    }
    return true;
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
    cbor_parser_init(payload, payloadLength, 0, &parser, &map);

    // Read Username
    // Read T
    CborValue username;
    CborValue T;
    cbor_value_map_find_value(&map, "Username", &username);
    cbor_value_map_find_value(&map, "T", &T);

    if (!read_group_element(&T, &passwordRequest->grp, &passwordRequest->T)) {
        return false;
    }

    if (!read_text_string(&username, passwordRequest->username, NC_SPAKE2_USERNAME_MAX_LENGTH)) {
        return false;
    }

    return true;
}

void nc_spake2_handle_coap_1(struct nabto_coap_server_request* request, void* data)
{
    uint8_t* payload;
    size_t payloadLength;

    struct nc_spake2_module* spake2 = data;

    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);
    connection->passwordAuthenticationRequests++;

    int32_t contentFormat = nabto_coap_server_request_get_content_format(request);
    struct nc_spake2_password_request* passwordRequest = NULL;
    nabto_coap_server_request_get_payload(request, (void**)&payload, &payloadLength);

    if (spake2->passwordRequest == NULL) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,04), NULL);
    } else if (connection->passwordAuthenticationRequests > NC_SPAKE2_MAX_PASSWORD_AUTHENTICATION_REQUESTS) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,29), NULL);
    } else if (contentFormat != NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,15), NULL);
    } else if (payload == NULL) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,00), NULL);
    } else {
        passwordRequest = nc_spake2_password_request_new();
        if (passwordRequest == NULL) {
            nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(5,00), NULL);
        } else {
            passwordRequest->coapRequest = request;
            if (!read_username_and_password(passwordRequest, payload, payloadLength)) {
                nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,00), NULL);
            } else {
                spake2->passwordRequest(passwordRequest, spake2->passwordRequestData);
                return;
            }
        }
    }
    // if we get to here an error response has been generated. Return in the ok case.
    nc_spake2_password_request_free(passwordRequest);
    nabto_coap_server_request_free(request);
}


void nc_spake2_handle_coap_2(struct nabto_coap_server_request* request, void* data)
{
    uint8_t* payload;
    size_t payloadLength;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    struct nc_spake2_module* spake2 = data;

    nabto_coap_server_request_get_payload(request, (void**)&payload, &payloadLength);

    connection->passwordAuthenticationRequests++;
    if (spake2->passwordRequest == NULL) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,04), NULL);
    } else if (connection->passwordAuthenticationRequests > NC_SPAKE2_MAX_PASSWORD_AUTHENTICATION_REQUESTS) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,29), NULL);
    } else if (payload == NULL || payloadLength != 32) {
        nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,00), NULL);
    } else {
        if (!connection->hasSpake2Key) {
            nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,00), NULL);
        } else {
            uint8_t hash1[32];
            uint8_t hash2[32];
            mbedtls_sha256_ret(connection->spake2Key, 32, hash1, 0);
            mbedtls_sha256_ret(hash1, 32, hash2, 0);
            if (memcmp(payload, hash2, 32) != 0) {
                nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(4,01), NULL);
            } else {
                nabto_coap_server_response_set_code_human(request, 201);
                nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM);
                nabto_coap_server_response_set_payload(request, hash1, 32);
                nabto_coap_server_response_ready(request);
            }
        }
    }
    nabto_coap_server_request_free(request);
}
