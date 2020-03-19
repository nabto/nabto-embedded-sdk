#ifndef _NM_IAM_PAIRING_PASSWORD_H_
#define _NM_IAM_PAIRING_PASSWORD_H_

#include "nm_iam_coap_handler.h"

NabtoDeviceError nm_iam_pairing_password_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

#endif
