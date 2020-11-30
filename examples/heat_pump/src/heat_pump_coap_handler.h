#ifndef _HEAT_PUMP_COAP_HANDLER_H_
#define _HEAT_PUMP_COAP_HANDLER_H_

#include <nabto/nabto_device.h>

#include <cbor.h>

struct heat_pump;
struct heat_pump_coap_handler;

typedef void (*heat_pump_coap_request_handler)(struct heat_pump_coap_handler* handler, NabtoDeviceCoapRequest* request);

struct heat_pump_coap_handler {
    NabtoDevice* device;
    struct heat_pump* heatPump;
    NabtoDeviceFuture* future;
    NabtoDeviceListener* listener;
    NabtoDeviceCoapRequest* request;
    heat_pump_coap_request_handler requestHandler;
};

NabtoDeviceError heat_pump_coap_handler_init(
    struct heat_pump_coap_handler* handler,
    NabtoDevice* device,
    struct heat_pump* heatPump,
    NabtoDeviceCoapMethod method,
    const char** paths,
    heat_pump_coap_request_handler requestHandler);

void heat_pump_coap_handler_stop(struct heat_pump_coap_handler* handler);
void heat_pump_coap_handler_deinit(struct heat_pump_coap_handler* handler);


NabtoDeviceError heat_pump_get_init(struct heat_pump_coap_handler* handler, NabtoDevice* device, struct heat_pump* heatPump);
NabtoDeviceError heat_pump_set_mode_init(struct heat_pump_coap_handler* handler, NabtoDevice* device, struct heat_pump* heatPump);
NabtoDeviceError heat_pump_set_power_init(struct heat_pump_coap_handler* handler, NabtoDevice* device, struct heat_pump* heatPump);
NabtoDeviceError heat_pump_set_target_init(struct heat_pump_coap_handler* handler, NabtoDevice* device, struct heat_pump* heatPump);

bool heat_pump_init_cbor_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue);

#endif
