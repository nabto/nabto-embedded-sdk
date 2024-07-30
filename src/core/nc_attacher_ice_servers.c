#include "nc_attacher.h"
#include "nc_coap.h"
#include "nc_cbor.h"
#include "nc_coap_rest_error.h"

#include <platform/np_error_code.h>
#include <platform/np_logging.h>
#include <platform/np_allocator.h>
#include <coap/nabto_coap_client.h>

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
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "Identifier");
    cbor_encode_text_stringz(&map, identifier);
    cbor_encoder_close_container(&encoder, &map);

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
                NABTO_LOG_ERROR(LOG, "Could not parse cbor response from basestation");
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

    cbor_parser_init(buffer, bufferSize, 0, &parser, &root);
    if (!cbor_value_is_array(&root) ||
        cbor_value_enter_container(&root, &it) != CborNoError) {
        NABTO_LOG_INFO(LOG, "root is not array");
        return false;
    }

    while (!cbor_value_at_end(&it)) {
        CborValue username;
        CborValue credential;
        CborValue urls;


        if (!cbor_value_is_map(&it)) {
            NABTO_LOG_INFO(LOG, "Array element not a map");
        }

        cbor_value_map_find_value(&it, "Username", &username);
        cbor_value_map_find_value(&it, "Credential", &credential);
        cbor_value_map_find_value(&it, "Urls", &urls);

        struct nc_attacher_ice_server server;
        memset(&server, 0, sizeof(struct nc_attacher_ice_server));

        CborValue urlsIt;
        nc_cbor_copy_text_string(&username, &server.username, 4096);
        nc_cbor_copy_text_string(&credential, &server.credential, 4096);
        if (!cbor_value_is_array(&urls) ||
            cbor_value_enter_container(&urls, &urlsIt) != CborNoError)
        {
            ice_server_clean(&server);
            NABTO_LOG_INFO(LOG, "Failed to get username, credential, or urls");
            return false;
        }

        nn_vector_init(&server.urls, sizeof(char*), np_allocator_get());
        while (!cbor_value_at_end(&urlsIt)) {
            char * url = NULL;
            if (!nc_cbor_copy_text_string(&urlsIt, &url, 4096) ||
                !nn_vector_push_back(&server.urls, &url) ||
                cbor_value_advance(&urlsIt) != CborNoError)
            {
                ice_server_clean(&server);
                NABTO_LOG_INFO(LOG, "Failed to copy url or advance iterator");
                return false;
            }
        }
        if (cbor_value_leave_container(&urls, &urlsIt) != CborNoError ||
            cbor_value_advance(&it) != CborNoError)
        {
            NABTO_LOG_INFO(LOG, "Failed to leave containers or advance iterator");
            ice_server_clean(&server);
            return false;
        }
        nn_vector_push_back(&ctx->iceServers, &server);
    }

    if (cbor_value_leave_container(&root, &it) != CborNoError) {
        // Server was pushed to the vector, so it will be clean up by deinit
        NABTO_LOG_INFO(LOG, "Could not leave the root container");
        return false;
    }

    return true;

}
