#ifndef _THERMOSTAT_COAP_HANDLER_H_
#define _THERMOSTAT_COAP_HANDLER_H_

#include <nabto/nabto_device.h>

#include <cbor.h>

struct thermostat;
struct thermostat_coap_handler;

typedef void (*thermostat_coap_request_handler)(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request);

struct thermostat_coap_handler {
    NabtoDevice* device;
    struct thermostat* thermostat;
    NabtoDeviceFuture* future;
    NabtoDeviceListener* listener;
    NabtoDeviceCoapRequest* request;
    thermostat_coap_request_handler requestHandler;
};

NabtoDeviceError thermostat_coap_handler_init(
    struct thermostat_coap_handler* handler,
    NabtoDevice* device,
    struct thermostat* thermostat,
    NabtoDeviceCoapMethod method,
    const char** paths,
    thermostat_coap_request_handler requestHandler);

void thermostat_coap_handler_stop(struct thermostat_coap_handler* handler);
void thermostat_coap_handler_deinit(struct thermostat_coap_handler* handler);


NabtoDeviceError thermostat_get_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat);
NabtoDeviceError thermostat_set_mode_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat);
NabtoDeviceError thermostat_set_power_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat);
NabtoDeviceError thermostat_set_target_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat);

bool thermostat_init_cbor_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue);

#endif
