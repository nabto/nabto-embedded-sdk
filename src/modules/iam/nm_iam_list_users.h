#ifndef _NM_IAM_LIST_USERS_H_
#define _NM_IAM_LIST_USERS_H_

#include <nabto/nabto_device.h>
#include "nm_iam_coap_handler.h"

struct nm_iam;

NabtoDeviceError nm_iam_list_users_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

// the handler will be stopped when the device is stopped.

#endif
