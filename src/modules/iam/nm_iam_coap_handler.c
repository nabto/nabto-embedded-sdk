#include "nm_iam_coap_handler.h"

#include <stdlib.h>

static void start_listen(struct nm_iam_coap_handler* handler);
static void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);


NabtoDeviceError nm_iam_coap_handler_init(
    struct nm_iam_coap_handler* handler,
    NabtoDevice* device,
    struct nm_iam* iam,
    NabtoDeviceCoapMethod method,
    const char** paths,
    nm_iam_coap_request_handler requestHandler)
{
    memset(handler, 0, sizeof(struct nm_iam_coap_handler));
    handler->device = device;
    handler->iam = iam;
    handler->requestHandler = requestHandler;

    handler->future = nabto_device_future_new(device);
    handler->listener = nabto_device_listener_new(device);
    if (handler->future == NULL ||
        handler->listener == NULL)
    {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }

    NabtoDeviceError ec = nabto_device_coap_init_listener(device, handler->listener, method, paths);
    if (ec == NABTO_DEVICE_EC_OK) {
        start_listen(handler);
    }

    return ec;
}

void nm_iam_coap_handler_deinit(struct nm_iam_coap_handler* handler)
{
    if (handler->device != NULL) {
        nabto_device_listener_stop(handler->listener);
        nabto_device_future_free(handler->future);
        nabto_device_listener_free(handler->listener);
        handler->device = NULL;
        handler->iam = NULL;
        handler->listener = NULL;
        handler->future = NULL;
    }
}

void start_listen(struct nm_iam_coap_handler* handler)
{
    nabto_device_listener_new_coap_request(handler->listener, handler->future, &handler->request);
    nabto_device_future_set_callback(handler->future, request_callback, handler);
}

void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    struct nm_iam_coap_handler* handler = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    } else {
        handler->requestHandler(handler, handler->request);
        nabto_device_coap_request_free(handler->request);
        start_listen(handler);
    }
}


bool nm_iam_cbor_init_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
{
    uint16_t contentFormat;
    NabtoDeviceError ec;
    ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        nabto_device_coap_error_response(request, 400, "Invalid Content Format");
        return false;
    }
    void* payload;
    size_t payloadSize;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 400, "Missing payload");
        return false;
    }
    cbor_parser_init((const uint8_t*)payload, payloadSize, 0, parser, cborValue);
    return true;
}


bool nm_iam_cbor_decode_string(CborValue* value, char** str)
{
    if (cbor_value_is_text_string(value)) {
        size_t nameLength;
        cbor_value_calculate_string_length (value, &nameLength);
        if (nameLength < 1024) {
            *str = calloc(1, nameLength+1);
            if (*str == NULL) {
                return false;
            }
            size_t copySize = nameLength;
            if (cbor_value_copy_text_string (value, *str, &copySize, NULL) == CborNoError) {
                return true;
            }
        }
    }
    return false;
}

bool nm_iam_cbor_decode_kv_string(CborValue* map, const char* key, char** str)
{
    if (!cbor_value_is_map(map)) {
        return false;
    }
    CborValue nameValue;
    cbor_value_map_find_value(map, key, &nameValue);
    return nm_iam_cbor_decode_string(&nameValue, str);
}
