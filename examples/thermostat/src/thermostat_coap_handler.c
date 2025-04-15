#include "thermostat_coap_handler.h"

#include <tinycbor/cbor.h>

static void start_listen(struct thermostat_coap_handler* handler);
static void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);


NabtoDeviceError thermostat_coap_handler_init(
    struct thermostat_coap_handler* handler,
    NabtoDevice* device,
    struct thermostat* thermostat,
    NabtoDeviceCoapMethod method,
    const char** paths,
    thermostat_coap_request_handler requestHandler)
{
    memset(handler, 0, sizeof(struct thermostat_coap_handler));
    handler->device = device;
    handler->thermostat = thermostat;
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

void thermostat_coap_handler_stop(struct thermostat_coap_handler* handler)
{
    if (handler->device != NULL) {
        nabto_device_listener_stop(handler->listener);
    }
}

void thermostat_coap_handler_deinit(struct thermostat_coap_handler* handler)
{
    if (handler->device != NULL) {
        nabto_device_future_free(handler->future);
        nabto_device_listener_free(handler->listener);
        handler->device = NULL;
        handler->thermostat = NULL;
        handler->listener = NULL;
        handler->future = NULL;
    }
}

void start_listen(struct thermostat_coap_handler* handler)
{
    nabto_device_listener_new_coap_request(handler->listener, handler->future, &handler->request);
    nabto_device_future_set_callback(handler->future, request_callback, handler);
}

void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    (void)future;
    struct thermostat_coap_handler* handler = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }
    handler->requestHandler(handler, handler->request);
    nabto_device_coap_request_free(handler->request);
    start_listen(handler);
}

bool thermostat_init_cbor_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
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
