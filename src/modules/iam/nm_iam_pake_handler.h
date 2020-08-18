#ifndef _NM_IAM_PAKE_HANDLER_H_
#define _NM_IAM_PAKE_HANDLER_H_

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

struct nm_iam;

struct nm_iam_pake_handler {
    NabtoDevice *device;
    struct nm_iam *iam;

    NabtoDeviceListener *listener;
    NabtoDeviceFuture *future;
    NabtoDevicePasswordAuthenticationRequest *request;
};

NabtoDeviceError nm_iam_pake_handler_init(struct nm_iam_pake_handler *handler,
                                          NabtoDevice *device,
                                          struct nm_iam *iam);
void nm_iam_pake_handler_deinit(struct nm_iam_pake_handler *handler);

#endif // _NM_IAM_PAKE_HANDLER_H_-
