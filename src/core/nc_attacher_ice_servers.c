#include "nc_attacher.h"
#include "nc_coap.h"
#include "nc_cbor.h"
#include "nc_coap_rest_error.h"

#include <platform/np_error_code.h>
#include <platform/np_logging.h>
#include <platform/np_allocator.h>
#include <nabto_coap/nabto_coap_client.h>

#include "tinycbor/cbor.h"

#define LOG NABTO_LOG_MODULE_ATTACHER

static void coap_handler(struct nabto_coap_client_request* request, void* data);
size_t encode_request(const char* identifier, uint8_t* buffer, size_t bufferSize);
bool parse_response(const uint8_t* buffer, size_t bufferSize, struct nc_attacher_request_ice_servers_context* ctx);

static const char* coapPath[] = { "device", "ice-servers" };

static void ice_server_clean(struct nc_attacher_ice_server* server) {
        void* url;
        NN_VECTOR_FOREACH(&url, &server->urls) {
            np_free(url);
        }
        nn_vector_deinit(&server->urls);
        np_free(server->username);
        np_free(server->credential);
}

void nc_attacher_ice_servers_ctx_init(struct nc_attacher_request_ice_servers_context* ctx, struct nc_attach_context* attacher) {
    ctx->attacher = attacher;
    ctx->coapRequest = nabto_coap_client_request_new(nc_coap_client_get_client(attacher->coapClient),
        NABTO_COAP_METHOD_POST,
        2, coapPath,
        &coap_handler,
        ctx, attacher->dtls);
    nn_vector_init(&ctx->iceServers, sizeof(struct nc_attacher_ice_server), np_allocator_get());
}

void nc_attacher_ice_servers_ctx_deinit(struct nc_attacher_request_ice_servers_context* ctx) {
    void* elm;
    NN_VECTOR_FOREACH_REFERENCE(elm, &ctx->iceServers) {
        ice_server_clean((struct nc_attacher_ice_server*)elm);
    }
    nn_vector_deinit(&ctx->iceServers);
    nabto_coap_client_request_free(ctx->coapRequest);
}

np_error_code nc_attacher_request_ice_servers(struct nc_attacher_request_ice_servers_context* ctx, const char* identifier, nc_attacher_request_ice_servers_callback cb, void* userData)
{
    if (ctx->attacher->state != NC_ATTACHER_STATE_ATTACHED) {
        return NABTO_EC_NOT_ATTACHED;
    }

    nabto_coap_client_request_set_content_format(ctx->coapRequest, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);

    size_t bufferSize = encode_request(identifier, NULL, 0);

    uint8_t* buffer = np_calloc(1, bufferSize);
    if (buffer == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    encode_request(identifier, buffer, bufferSize);

    nabto_coap_error err = nabto_coap_client_request_set_payload(ctx->coapRequest, buffer, bufferSize);
    np_free(buffer);
    if (err != NABTO_COAP_ERROR_OK) {
        return nc_coap_error_to_core(err);
    }

    ctx->cb = cb;
    ctx->cbData = userData;
    nabto_coap_client_request_send(ctx->coapRequest);
    return NABTO_EC_OK;
}

size_t encode_request(const char* identifier, uint8_t* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    CborError err = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "Failed to create CBOR map: %d", err);
        return 0;
    }

    err = cbor_encode_text_stringz(&map, "Identifier");
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "Failed to encode 'Identifier' key: %d", err);
        return 0;
    }
    err = cbor_encode_text_stringz(&map, identifier);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "Failed to encode identifier value: %d", err);
        return 0;
    }
    err = cbor_encoder_close_container(&encoder, &map);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "Failed to close CBOR map: %d", err);
        return 0;
    }
    return cbor_encoder_get_extra_bytes_needed(&encoder);
}

static void coap_handler(struct nabto_coap_client_request* request, void* data)
{
    struct nc_attacher_request_ice_servers_context* ctx = data;
    enum nabto_coap_client_status status =
        nabto_coap_client_request_get_status(request);
    np_error_code ec = NABTO_EC_OK;
    if (status == NABTO_COAP_CLIENT_STATUS_STOPPED) {
        ec = NABTO_EC_STOPPED;
    }
    else if (status == NABTO_COAP_CLIENT_STATUS_TIMEOUT) {
        ec = NABTO_EC_TIMEOUT;
    }
    else if (status != NABTO_COAP_CLIENT_STATUS_OK) {
        ec = NABTO_EC_UNKNOWN;
    }
    else {
        struct nabto_coap_client_response* res =
            nabto_coap_client_request_get_response(request);

        uint16_t resCode = nabto_coap_client_response_get_code(res);
        uint16_t contentFormat = 0;
        nabto_coap_client_response_get_content_format(res, &contentFormat);

        const uint8_t* payload = NULL;
        size_t payloadLength = 0;
        nabto_coap_client_response_get_payload(res, &payload, &payloadLength);

        ec = NABTO_EC_UNKNOWN;
        if (resCode != 201) {
            struct nc_coap_rest_error error;
            nc_coap_rest_error_decode_response(res, &error);
            NABTO_LOG_ERROR(LOG, "Failed to get TURN server. (%d)%s", resCode, error.message);
            nc_coap_rest_error_deinit(&error);
            ec = NABTO_EC_FAILED;
        }
        else if (contentFormat != NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
            NABTO_LOG_ERROR(LOG, "Unexpected content format");
            ec = NABTO_EC_BAD_RESPONSE;
        }
        else if (payload == NULL) {
            NABTO_LOG_ERROR(LOG, "Expected a payload in the response");
            ec = NABTO_EC_BAD_RESPONSE;
        }
        else {
            if (parse_response(payload, payloadLength, ctx)) {
                ec = NABTO_EC_OK;
            }
            else {
                NABTO_LOG_ERROR(LOG, "Could not parse CBOR response from basestation");
                ec = NABTO_EC_BAD_RESPONSE;
            }
        }
    }

    ctx->cb(ec, ctx->cbData);
}

bool parse_response(const uint8_t* buffer, size_t bufferSize, struct nc_attacher_request_ice_servers_context* ctx) {
    CborParser parser;
    CborValue root;
    CborValue it;
    CborError err = cbor_parser_init(buffer, bufferSize, 0, &parser, &root);
    if (err != CborNoError) {
        NABTO_LOG_INFO(LOG, "cbor_parser_init failed: %d", err);
        return false;
    }
    if (!cbor_value_is_array(&root)) {
        NABTO_LOG_INFO(LOG, "root is not array");
        return false;
    }
    err = cbor_value_enter_container(&root, &it);
    if (err != CborNoError) {
        NABTO_LOG_INFO(LOG, "Failed to enter root container: %d", err);
        return false;
    }

    while (!cbor_value_at_end(&it)) {
        CborValue username;
        CborValue credential;
        CborValue urls;

        if (!cbor_value_is_map(&it)) {
            NABTO_LOG_INFO(LOG, "Array element not a map");
        }

        err = cbor_value_map_find_value(&it, "Username", &username);
        if (err != CborNoError) {
            NABTO_LOG_INFO(LOG, "Failed to find 'Username': %d", err);
        }
        err = cbor_value_map_find_value(&it, "Credential", &credential);
        if (err != CborNoError) {
            NABTO_LOG_INFO(LOG, "Failed to find 'Credential': %d", err);
        }
        err = cbor_value_map_find_value(&it, "Urls", &urls);
        if (err != CborNoError) {
            NABTO_LOG_INFO(LOG, "Failed to find 'Urls': %d", err);
        }

        struct nc_attacher_ice_server server;
        memset(&server, 0, sizeof(struct nc_attacher_ice_server));

        CborError err2;
        if (!nc_cbor_copy_text_string(&username, &server.username, 4096)) {
            NABTO_LOG_INFO(LOG, "Failed to copy 'Username'");
        }
        if (!nc_cbor_copy_text_string(&credential, &server.credential, 4096)) {
            NABTO_LOG_INFO(LOG, "Failed to copy 'Credential'");
        }
        if (!cbor_value_is_array(&urls)) {
            ice_server_clean(&server);
            NABTO_LOG_INFO(LOG, "'Urls' is not an array");
            return false;
        }
        err = cbor_value_enter_container(&urls, &it); // reuse 'it' for inner container
        if (err != CborNoError) {
            ice_server_clean(&server);
            NABTO_LOG_INFO(LOG, "Failed to enter 'Urls' container: %d", err);
            return false;
        }
        CborValue urlsIt;
        err = cbor_value_enter_container(&urls, &urlsIt);
        if (err != CborNoError) {
            ice_server_clean(&server);
            NABTO_LOG_INFO(LOG, "Failed to enter 'Urls' array: %d", err);
            return false;
        }
        nn_vector_init(&server.urls, sizeof(char*), np_allocator_get());
        while (!cbor_value_at_end(&urlsIt)) {
            char * url = NULL;
            if (!nc_cbor_copy_text_string(&urlsIt, &url, 4096)) {
                ice_server_clean(&server);
                NABTO_LOG_INFO(LOG, "Failed to copy url");
                return false;
            }
            if (!nn_vector_push_back(&server.urls, &url)) {
                ice_server_clean(&server);
                NABTO_LOG_INFO(LOG, "Failed to push url to vector");
                return false;
            }
            err = cbor_value_advance(&urlsIt);
            if (err != CborNoError) {
                ice_server_clean(&server);
                NABTO_LOG_INFO(LOG, "Failed to advance urls iterator: %d", err);
                return false;
            }
        }
        err = cbor_value_leave_container(&urls, &urlsIt);
        if (err != CborNoError) {
            NABTO_LOG_INFO(LOG, "Failed to leave 'Urls' container: %d", err);
            ice_server_clean(&server);
            return false;
        }
        err = cbor_value_advance(&it);
        if (err != CborNoError) {
            NABTO_LOG_INFO(LOG, "Failed to advance iterator: %d", err);
            ice_server_clean(&server);
            return false;
        }
        if (!nn_vector_push_back(&ctx->iceServers, &server)) {
            NABTO_LOG_INFO(LOG, "Failed to push server to vector");
            ice_server_clean(&server);
            return false;
        }
    }

    err = cbor_value_leave_container(&root, &it);
    if (err != CborNoError) {
        NABTO_LOG_INFO(LOG, "Could not leave the root container: %d", err);
        return false;
    }

    return true;
}
