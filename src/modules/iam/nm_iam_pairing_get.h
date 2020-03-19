#ifndef _NM_IAM_PAIRING_GET_H_
#define _NM_IAM_PAIRING_GET_H_

#include <nabto/nabto_device.h>
#include "nm_iam_coap_handler.h"

NabtoDeviceError nm_iam_pairing_get_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

#endif
