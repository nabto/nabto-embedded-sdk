#ifndef NM_IAM_CONNECTION_EVENTS_H_
#define NM_IAM_CONNECTION_EVENTS_H_

#include <nabto/nabto_device.h>

struct nm_iam;

struct nm_iam_connection_events_ctx {
    NabtoDevice* device;
    struct nm_iam* iam;

    // local owned instances
    NabtoDeviceListener* listener;
    NabtoDeviceFuture* future;
    NabtoDeviceConnectionRef ref;
    NabtoDeviceConnectionEvent ev;
};

NabtoDeviceError nm_iam_connection_events_init(struct nm_iam_connection_events_ctx* ctx, NabtoDevice* device, struct nm_iam* iam);
void nm_iam_connection_events_stop(struct nm_iam_connection_events_ctx* ctx);
void nm_iam_connection_events_deinit(struct nm_iam_connection_events_ctx* ctx);


#endif
