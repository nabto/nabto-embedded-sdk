#ifndef _TCP_TUNNEL_COAP_H_
#define _TCP_TUNNEL_COAP_H_

#include <nabto/nabto_device.h>

#include <cbor.h>

struct tunnel_coap_handler;
typedef void (*tunnel_coap_request_handler)(struct tunnel_coap_handler* handler, NabtoDeviceCoapRequest* request);

struct tunnel_coap_handler {
    NabtoDevice* device;
    struct tunnel_coap_server* tunnel_coap_server;
    NabtoDeviceFuture* future;
    NabtoDeviceListener* listener;
    NabtoDeviceCoapRequest* request;
    tunnel_coap_request_handler requestHandler;
};

struct tunnel_coap_server {
    NabtoDevice* device;
    struct nm_iam* iam;
    struct nn_log* logger;
    struct ptz_state* state;
    struct tunnel_coap_handler coapPtzGetState;
    struct tunnel_coap_handler coapPtzMoveAbsolute;
    struct tunnel_coap_handler coapPtzMoveContinuousStart;
    struct tunnel_coap_handler coapPtzMoveContinuousStop;
    struct tunnel_coap_handler coapFactoryReset;
};

NabtoDeviceError tunnel_coap_handler_init(
    struct tunnel_coap_handler* handler,
    NabtoDevice* device,
    struct tunnel_coap_server* tunnel_coap_server,
    NabtoDeviceCoapMethod method,
    const char** paths,
    tunnel_coap_request_handler requestHandler);
void tunnel_coap_handler_stop(struct tunnel_coap_handler* handler);
void tunnel_coap_handler_deinit(struct tunnel_coap_handler* handler);

NabtoDeviceError tunnel_factory_reset_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);
NabtoDeviceError tunnel_ptz_get_state_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);
NabtoDeviceError tunnel_ptz_move_absolute_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);
NabtoDeviceError tunnel_ptz_move_continuous_start_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);
NabtoDeviceError tunnel_ptz_move_continuous_stop_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);
NabtoDeviceError tunnel_ptz_set_tilt_position_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);

//bool run_coap_server(NabtoDevice* device, struct tunnel_coap_server* coap_server);
NabtoDeviceError tunnel_coap_init(struct tunnel_coap_server* coap_server, NabtoDevice* device, struct nm_iam* iam, struct ptz_state* state, struct nn_log* logger);
void tunnel_coap_deinit(struct tunnel_coap_server* coap_server);

#endif
