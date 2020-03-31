#ifndef _NM_IAM_AUTH_HANDLER_H_
#define _NM_IAM_AUTH_HANDLER_H_

#include <nabto/nabto_device.h>

struct nm_iam;

struct nm_iam_auth_handler {
    NabtoDevice* device;
    struct nm_iam* iam;

    // local owned instances
    NabtoDeviceListener* listener;
    NabtoDeviceFuture* future;
    NabtoDeviceAuthorizationRequest* request;
};

NabtoDeviceError nm_iam_auth_handler_init(struct nm_iam_auth_handler* handler, NabtoDevice* device, struct nm_iam* iam);
void nm_iam_auth_handler_deinit(struct nm_iam_auth_handler* handler);


#endif
