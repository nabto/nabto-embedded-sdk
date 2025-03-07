#include <tinycbor/cbor.h>
#include <core/nc_coap.h>
#include <core/nc_coap_rest_error.h>
#include <core/nc_version.h>
#include <core/nc_stun.h>
#include <core/nc_device.h>
#include <platform/np_logging.h>
#include <platform/np_allocator.h>

#include "nc_attacher.h"

#define LOG NABTO_LOG_MODULE_ATTACHER

const char* attachStartPath[] = {"device", "attach-start"};

static void coap_attach_start_handler(struct nabto_coap_client_request* request,
                                      void* data);

static size_t encode_cbor_request(CborEncoder* encoder,
                                  struct nc_attach_context* ctx);

static enum nc_attacher_status coap_attach_start_handle_response(
    struct nabto_coap_client_request* request, struct nc_attach_context* ctx);

static enum nc_attacher_status handle_attached(struct nc_attach_context* ctx,
                                               CborValue* root);
static enum nc_attacher_status handle_redirect(struct nc_attach_context* ctx,
                                               CborValue* root);

np_error_code nc_attacher_attach_start_request(
    struct nc_attach_context* ctx,
    nc_attacher_attach_start_callback startCallback, void* userData)
{
    if (ctx->startCallback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }

    size_t bufferSize;
    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, NULL, 0, 0);
        bufferSize = encode_cbor_request(&encoder, ctx);
        if (bufferSize == 0) {
            NABTO_LOG_ERROR(LOG, "CBOR encoding size calculation failed");
            return NABTO_EC_UNKNOWN;
        }
    }

    uint8_t* buffer = np_calloc(1, bufferSize);
    if (buffer == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct nabto_coap_client_request* req;
    req = nabto_coap_client_request_new(
        nc_coap_client_get_client(ctx->coapClient), NABTO_COAP_METHOD_POST, 2,
        attachStartPath, &coap_attach_start_handler, ctx, ctx->dtls);

    if (req == NULL) {
        np_free(buffer);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, buffer, bufferSize, 0);
        /* If encoding succeeds, cbor_encoder_get_extra_bytes_needed should be 0 */
        if (encode_cbor_request(&encoder, ctx) != 0) {
            NABTO_LOG_ERROR(LOG, "CBOR encoding failed");
            nabto_coap_client_request_free(req);
            np_free(buffer);
            return NABTO_EC_UNKNOWN;
        }
    }

    np_error_code ec = NABTO_EC_OPERATION_STARTED;
    nabto_coap_client_request_set_content_format(
        req, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_coap_error err =
        nabto_coap_client_request_set_payload(req, buffer, bufferSize);
    if (err != NABTO_COAP_ERROR_OK) {
        ec = nc_coap_error_to_core(err);
        nabto_coap_client_request_free(req);
    } else {
        ctx->startCallback = startCallback;
        ctx->startCallbackUserData = userData;
        nabto_coap_client_request_send(req);
    }
    np_free(buffer);
    return ec;
}

enum nc_attacher_status coap_attach_start_handle_response(
    struct nabto_coap_client_request* request, struct nc_attach_context* ctx)
{
    struct nabto_coap_client_response* res =
        nabto_coap_client_request_get_response(request);
    if (!res) {
        return NC_ATTACHER_STATUS_ERROR;
    }
    uint16_t resCode = nabto_coap_client_response_get_code(res);
    if (!nc_coap_is_status_ok(resCode)) {
        struct nc_coap_rest_error error;
        nc_coap_rest_error_decode_response(res, &error);
        enum nc_attacher_status ec = NC_ATTACHER_STATUS_ERROR;

        switch (error.nabtoErrorCode) {
            case NABTO_PROTOCOL_UNKNOWN_DEVICE_FINGERPRINT:
                NABTO_LOG_ERROR(LOG,
                                "The server does not recognize the "
                                "fingerprint of the device. Check that the "
                                "fingerprint is in sync with the server");
                ec = NC_ATTACHER_STATUS_UNKNOWN_FINGERPRINT;
                break;
            case NABTO_PROTOCOL_WRONG_PRODUCT_ID:
                NABTO_LOG_ERROR(
                    LOG,
                    "Product ID / fingerprint mismatch: The Product ID %s is "
                    "likely wrong; the fingerprint is configured in the "
                    "basestation for a device in another Product than the one "
                    "provided. Please check you provided the intended Product "
                    "ID.",
                    ctx->productId);
                ec = NC_ATTACHER_STATUS_WRONG_PRODUCT_ID;
                break;
            case NABTO_PROTOCOL_WRONG_DEVICE_ID:
                NABTO_LOG_ERROR(
                    LOG,
                    "Device ID / fingerprint mismatch: The Device ID %s is "
                    "likely wrong; it is not the Device ID for which the "
                    "provided fingerprint is configured in the basestation. "
                    "Please check you provided the intended device ID.",
                    ctx->deviceId);
                ec = NC_ATTACHER_STATUS_WRONG_DEVICE_ID;
                break;
            default:
                NABTO_LOG_ERROR(LOG,
                                "Attach failed with coap code %d, error "
                                "code %d, message: %s, ",
                                error.coapResponseCode, error.nabtoErrorCode,
                                error.message ? error.message : "");
                ec = NC_ATTACHER_STATUS_ERROR;

        }
        nc_coap_rest_error_deinit(&error);
        return ec;
    }
    const uint8_t* payload;
    size_t payloadSize;
    if (!nabto_coap_client_response_get_payload(res, &payload, &payloadSize)) {
        NABTO_LOG_ERROR(LOG, "No payload in CoAP response");
        return NC_ATTACHER_STATUS_ERROR;
    }

    CborParser parser;
    CborValue root;
    CborValue status;
    CborError err = cbor_parser_init(payload, payloadSize, 0, &parser, &root);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_parser_init failed: %d", err);
        return NC_ATTACHER_STATUS_ERROR;
    }

    if (!cbor_value_is_map(&root)) {
        NABTO_LOG_ERROR(LOG, "Invalid coap response format");
        return NC_ATTACHER_STATUS_ERROR;
    }

    err = cbor_value_map_find_value(&root, "Status", &status);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for Status failed: %d", err);
        return NC_ATTACHER_STATUS_ERROR;
    }

    if (!cbor_value_is_unsigned_integer(&status)) {
        NABTO_LOG_ERROR(LOG, "Status not an integer");
        return NC_ATTACHER_STATUS_ERROR;
    }

    uint64_t s;
    err = cbor_value_get_uint64(&status, &s);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_value_get_uint64 for Status failed: %d", err);
        return NC_ATTACHER_STATUS_ERROR;
    }

    if (s == ATTACH_STATUS_ATTACHED) {
        // this will free the request
        return handle_attached(ctx, &root);
    } else if (s == ATTACH_STATUS_REDIRECT) {
        return handle_redirect(ctx, &root);
    } else {
        NABTO_LOG_ERROR(LOG, "Status recognized");
        return NC_ATTACHER_STATUS_ERROR;
    }
}

enum nc_attacher_status handle_attached(struct nc_attach_context* ctx,
                                        CborValue* root)
{
    CborError err;
    CborValue keepAlive;
    err = cbor_value_map_find_value(root, "KeepAlive", &keepAlive);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for KeepAlive failed: %d", err);
    } else if (cbor_value_is_map(&keepAlive)) {
        CborValue interval;
        CborValue retryInterval;
        CborValue maxRetries;
        err = cbor_value_map_find_value(&keepAlive, "Interval", &interval);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for Interval failed: %d", err);
        } else {
            err = cbor_value_map_find_value(&keepAlive, "RetryInterval", &retryInterval);
            if (err != CborNoError) {
                NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for RetryInterval failed: %d", err);
            } else {
                err = cbor_value_map_find_value(&keepAlive, "MaxRetries", &maxRetries);
                if (err != CborNoError) {
                    NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for MaxRetries failed: %d", err);
                } else {
                    if (cbor_value_is_unsigned_integer(&interval) &&
                        cbor_value_is_unsigned_integer(&retryInterval) &&
                        cbor_value_is_unsigned_integer(&maxRetries))
                    {
                        uint64_t i, ri, mr;
                        err = cbor_value_get_uint64(&interval, &i);
                        if (err != CborNoError) {
                            NABTO_LOG_ERROR(LOG, "cbor_value_get_uint64 for Interval failed: %d", err);
                        } else {
                            err = cbor_value_get_uint64(&retryInterval, &ri);
                            if (err != CborNoError) {
                                NABTO_LOG_ERROR(LOG, "cbor_value_get_uint64 for RetryInterval failed: %d", err);
                            } else {
                                err = cbor_value_get_uint64(&maxRetries, &mr);
                                if (err != CborNoError) {
                                    NABTO_LOG_ERROR(LOG, "cbor_value_get_uint64 for MaxRetries failed: %d", err);
                                } else {
                                    NABTO_LOG_TRACE(
                                        LOG, "starting ka with int: %u, retryInt: %u, maxRetries: %u",
                                        i, ri, mr);
                                    nc_keep_alive_set_settings(&ctx->keepAlive, (uint32_t)i, (uint32_t)ri, (uint32_t)mr);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    CborValue stun;
    err = cbor_value_map_find_value(root, "Stun", &stun);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for Stun failed: %d", err);
    } else if (cbor_value_is_map(&stun)) {
        CborValue host;
        CborValue port;
        err = cbor_value_map_find_value(&stun, "Host", &host);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for STUN Host failed: %d", err);
        }
        err = cbor_value_map_find_value(&stun, "Port", &port);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for STUN Port failed: %d", err);
        }
        if (cbor_value_is_text_string(&host) &&
            cbor_value_is_unsigned_integer(&port))
        {
            uint64_t p;
            size_t stringLength;
            err = cbor_value_calculate_string_length(&host, &stringLength);
            if (err != CborNoError || stringLength > 255) {
                NABTO_LOG_ERROR(LOG,
                                "Basestation reported invalid STUN host, STUN "
                                "will be impossible");
            } else {
                size_t len = stringLength + 1;
                char* stunHost = np_calloc(1, len);
                if (stunHost == NULL) {
                    NABTO_LOG_ERROR(LOG, "cannot allocate memory for the stun host, stun will be impossible.");
                } else {
                    err = cbor_value_copy_text_string(&host, stunHost, &len, NULL);
                    if (err != CborNoError) {
                        NABTO_LOG_ERROR(LOG, "cbor_value_copy_text_string for STUN host failed: %d", err);
                    } else {
                        err = cbor_value_get_uint64(&port, &p);
                        if (err != CborNoError) {
                            NABTO_LOG_ERROR(LOG, "cbor_value_get_uint64 for STUN port failed: %d", err);
                        } else {
                            nc_stun_set_host(&ctx->device->stun, stunHost, (uint16_t)p);
                        }
                    }
                    np_free(stunHost);
                }
            }
        } else {
            NABTO_LOG_ERROR(LOG,
                            "Basestation reported invalid STUN information, "
                            "STUN will be impossible");
        }
    } else {
        NABTO_LOG_ERROR(LOG,
                        "Basestation did not report STUN information, STUN "
                        "will be impossible");
    }
    return NC_ATTACHER_STATUS_ATTACHED;
}

enum nc_attacher_status handle_redirect(struct nc_attach_context* ctx,
                                        CborValue* root)
{
    CborError err;
    CborValue host;
    CborValue port;
    CborValue fingerprint;

    err = cbor_value_map_find_value(root, "Host", &host);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for Host failed: %d", err);
        return NC_ATTACHER_STATUS_ERROR;
    }
    err = cbor_value_map_find_value(root, "Port", &port);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for Port failed: %d", err);
        return NC_ATTACHER_STATUS_ERROR;
    }
    err = cbor_value_map_find_value(root, "Fingerprint", &fingerprint);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_value_map_find_value for Fingerprint failed: %d", err);
        return NC_ATTACHER_STATUS_ERROR;
    }

    if (cbor_value_is_text_string(&host) &&
        cbor_value_is_unsigned_integer(&port) &&
        cbor_value_is_byte_string(&fingerprint))
    {
        uint64_t p;
        size_t hostLength;
        err = cbor_value_get_string_length(&host, &hostLength);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "cbor_value_get_string_length for Host failed: %d", err);
            return NC_ATTACHER_STATUS_ERROR;
        }
        err = cbor_value_get_uint64(&port, &p);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "cbor_value_get_uint64 for Port failed: %d", err);
            return NC_ATTACHER_STATUS_ERROR;
        }

        if (hostLength < 1 || hostLength > 256) {
            NABTO_LOG_ERROR(LOG,
                            "Redirect response had invalid hostname length: %u",
                            hostLength);
            return NC_ATTACHER_STATUS_ERROR;
        }
        if (ctx->dns != NULL) {
            np_free(ctx->dns);
        }
        ctx->dns = calloc(1, hostLength + 1);
        if (ctx->dns == NULL) {
            NABTO_LOG_ERROR(LOG, "Out of memory when handling redirect.");
            return NC_ATTACHER_STATUS_ERROR;
        }
        err = cbor_value_copy_text_string(&host, ctx->dns, &hostLength, NULL);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "cbor_value_copy_text_string for redirect host failed: %d", err);
            free(ctx->dns);
            ctx->dns = NULL;
            return NC_ATTACHER_STATUS_ERROR;
        }
        ctx->currentPort = (uint16_t)p;

    } else {
        NABTO_LOG_ERROR(LOG, "Redirect response not understood");
        return NC_ATTACHER_STATUS_ERROR;
    }
    return NC_ATTACHER_STATUS_REDIRECT;
}

void coap_attach_start_handler(struct nabto_coap_client_request* request,
                               void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    nc_attacher_attach_start_callback cb = ctx->startCallback;
    void* userData = ctx->startCallbackUserData;

    enum nc_attacher_status result =
        coap_attach_start_handle_response(request, ctx);

    nabto_coap_client_request_free(request);
    ctx->startCallback = NULL;
    ctx->startCallbackUserData = NULL;
    cb(result, userData);
}

size_t encode_cbor_request(CborEncoder* encoder, struct nc_attach_context* ctx)
{
    CborEncoder map;
    CborError err = cbor_encoder_create_map(encoder, &map, CborIndefiniteLength);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encoder_create_map failed: %d", err);
        return 0;
    }

    err = cbor_encode_text_stringz(&map, "NabtoVersion");
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encode_text_stringz NabtoVersion failed: %d", err);
        return 0;
    }
    err = cbor_encode_text_stringz(&map, nc_version());
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encode_text_stringz nc_version failed: %d", err);
        return 0;
    }

    err = cbor_encode_text_stringz(&map, "AppName");
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encode_text_stringz AppName failed: %d", err);
        return 0;
    }
    err = cbor_encode_text_stringz(&map, ctx->appName ? ctx->appName : "");
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encode_text_stringz appName failed: %d", err);
        return 0;
    }

    err = cbor_encode_text_stringz(&map, "AppVersion");
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encode_text_stringz AppVersion failed: %d", err);
        return 0;
    }
    err = cbor_encode_text_stringz(&map, ctx->appVersion ? ctx->appVersion : "");
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encode_text_stringz appVersion failed: %d", err);
        return 0;
    }

    err = cbor_encode_text_stringz(&map, "ProductId");
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encode_text_stringz ProductId failed: %d", err);
        return 0;
    }
    err = cbor_encode_text_stringz(&map, ctx->productId);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encode_text_stringz productId failed: %d", err);
        return 0;
    }

    err = cbor_encode_text_stringz(&map, "DeviceId");
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encode_text_stringz DeviceId failed: %d", err);
        return 0;
    }
    err = cbor_encode_text_stringz(&map, ctx->deviceId);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encode_text_stringz deviceId failed: %d", err);
        return 0;
    }

    err = cbor_encoder_close_container(encoder, &map);
    if (err != CborNoError) {
        NABTO_LOG_ERROR(LOG, "cbor_encoder_close_container failed: %d", err);
        return 0;
    }
    return cbor_encoder_get_extra_bytes_needed(encoder);
}
