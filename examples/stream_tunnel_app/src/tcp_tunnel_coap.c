#include <apps/common/logging.h>
#include <apps/common/json_config.h>
#include <apps/common/string_file.h>

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>
#include <modules/iam/nm_iam_configuration.h>
#include <modules/iam/nm_iam_state.h>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <cjson/cJSON.h>

#include "tcp_tunnel.h"
#include "tcp_tunnel_coap.h"

static NabtoDeviceError tunnel_coap_init_handlers(struct tunnel_coap_server* coap_server);
static void start_listen(struct tunnel_coap_handler* handler);
void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);

NabtoDeviceError tunnel_coap_init(struct tunnel_coap_server* coap_server, NabtoDevice* device, struct nm_iam* iam, struct ptz_state* state, struct nn_log* logger)
{
    memset(coap_server, 0, sizeof(struct tunnel_coap_server));
    coap_server->device = device;
    coap_server->iam = iam;
    coap_server->logger = logger;
    coap_server->state = state;
    return tunnel_coap_init_handlers(coap_server);
}

NabtoDeviceError tunnel_coap_init_handlers(struct tunnel_coap_server* coap_server) {
// NabtoDeviceError tunnel_ptz_get_state_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);
// NabtoDeviceError tunnel_ptz_move_absolute_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);
// NabtoDeviceError tunnel_ptz_move_continuous_start_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);
// NabtoDeviceError tunnel_ptz_move_continuous_stop_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);
// NabtoDeviceError tunnel_ptz_set_tilt_position_init(struct tunnel_coap_handler* handler, NabtoDevice* device, struct tunnel_coap_server* tunnel_coap_server);
    NabtoDeviceError ec;
    ec = tunnel_ptz_get_state_init(&coap_server->coapPtzGetState, coap_server->device, coap_server);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    return NABTO_DEVICE_EC_OK;
    // ec = tunnel_ptz_move_absolute_init(&coap_server->coapPtzMoveAbsolute, coap_server->device, coap_server);
    // if (ec != NABTO_DEVICE_EC_OK) {
    //     return ec;
    // }
    // ec = tunnel_ptz_move_continuous_start_init(&coap_server->coapPtzMoveContinuousStart, coap_server->device, coap_server);
    // if (ec != NABTO_DEVICE_EC_OK) {
    //     return ec;
    // }
    // ec = tunnel_ptz_move_continuous_start_init(&coap_server->coapPtzMoveContinuousStop, coap_server->device, coap_server);
    // if (ec != NABTO_DEVICE_EC_OK) {
    //     return ec;
    // }
    // ec = tunnel_ptz_move_continuous_start_init(&coap_server->coap, coap_server->device, coap_server);
    // if (ec != NABTO_DEVICE_EC_OK) {
    //     return ec;
    // }
}

void tunnel_coap_deinit(struct tunnel_coap_server* coap_server)
{
    tunnel_coap_handler_deinit(&coap_server->coapPtzGetState);
    tunnel_coap_handler_deinit(&coap_server->coapPtzMoveAbsolute);
    tunnel_coap_handler_deinit(&coap_server->coapPtzMoveContinuousStart);
    tunnel_coap_handler_deinit(&coap_server->coapPtzMoveContinuousStop);
}

void tunnel_coap_handler_deinit(struct tunnel_coap_handler* handler)
{
    if (handler->device != NULL) {
        nabto_device_future_free(handler->future);
        nabto_device_listener_free(handler->listener);
        handler->device = NULL;
        handler->tunnel_coap_server = NULL;
        handler->listener = NULL;
        handler->future = NULL;
    }
}

NabtoDeviceError tunnel_coap_handler_init(
    struct tunnel_coap_handler* handler,
    NabtoDevice* device,
    struct tunnel_coap_server* tunnel_coap_server,
    NabtoDeviceCoapMethod method,
    const char** paths,
    tunnel_coap_request_handler requestHandler)
{
    memset(handler, 0, sizeof(struct tunnel_coap_handler));
    handler->device = device;
    handler->tunnel_coap_server = tunnel_coap_server;
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

void start_listen(struct tunnel_coap_handler* handler)
{
    nabto_device_listener_new_coap_request(handler->listener, handler->future, &handler->request);
    nabto_device_future_set_callback(handler->future, request_callback, handler);
}

void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    (void)future;
    struct tunnel_coap_handler* handler = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    } else {
        handler->requestHandler(handler, handler->request);
        nabto_device_coap_request_free(handler->request);
        start_listen(handler);
    }
}
