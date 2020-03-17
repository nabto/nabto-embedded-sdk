#ifndef _NM_IAM_LIST_USERS_H_
#define _NM_IAM_LIST_USERS_H_

#include <nabto/nabto_device.h>

struct nm_iam;

struct nm_iam_list_users {
    // references
    NabtoDevice* device;
    struct nm_iam* iam;

    // local owned instances
    NabtoDeviceListener* listener;
    NabtoDeviceFuture* future;
    NabtoDeviceCoapRequest* request;
};

bool nm_iam_list_users_init(struct nm_iam_list_users* listUsers, NabtoDevice* device, struct nm_iam* iam);
void nm_iam_list_users_deinit(struct nm_iam_list_users* listUsers);

// the handler will be stopped when the device is stopped.

#endif
