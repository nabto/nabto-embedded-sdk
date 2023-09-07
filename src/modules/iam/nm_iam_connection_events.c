#include "nm_iam_connection_events.h"

#include "nm_iam.h"
#include "nm_iam_internal.h"

#include "nm_iam_allocator.h"

static void start_listen(struct nm_iam_connection_events_ctx* ctx);
static void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);

NabtoDeviceError nm_iam_connection_events_init(struct nm_iam_connection_events_ctx* ctx, NabtoDevice* device, struct nm_iam* iam)
{
    ctx->device = device;
    ctx->iam = iam;
    ctx->listener = nabto_device_listener_new(device);
    ctx->future = nabto_device_future_new(device);
    if (ctx->listener == NULL || ctx->future == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    NabtoDeviceError ec = nabto_device_connection_events_init_listener(device, ctx->listener);
    if (ec == NABTO_DEVICE_EC_OK) {
        start_listen(ctx);
    }
    return ec;
}

void nm_iam_connection_events_stop(struct nm_iam_connection_events_ctx* ctx)
{
    nabto_device_listener_stop(ctx->listener);
}

void nm_iam_connection_events_deinit(struct nm_iam_connection_events_ctx* ctx)
{
    nabto_device_future_free(ctx->future);
    nabto_device_listener_free(ctx->listener);
}

void start_listen(struct nm_iam_connection_events_ctx* ctx)
{
    nabto_device_listener_connection_event(ctx->listener, ctx->future, &ctx->ref, &ctx->ev);
    nabto_device_future_set_callback(ctx->future, request_callback, ctx);
}

void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    (void)future;
    struct nm_iam_connection_events_ctx* ctx = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    } else if (ctx->ev == NABTO_DEVICE_CONNECTION_EVENT_CLOSED){
        struct nm_iam* iam = ctx->iam;
        nm_iam_lock(iam);


        for (size_t i = 0; i < nn_vector_size(&iam->authorizedConnections); i++) {

            struct nm_iam_authorized_connection* conn = nn_vector_reference(&iam->authorizedConnections, i);
            if (conn->ref == ctx->ref) {
                nn_vector_erase(&iam->authorizedConnections, i);
                break;
            }

        }

        nm_iam_unlock(iam);
        start_listen(ctx);
    }
}

