#ifndef _NM_IAM_PAIRING_H_
#define _NM_IAM_PAIRING_H_

#include "nm_iam.h"

bool nm_iam_pairing_is_local_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);
bool nm_iam_pairing_is_password_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);
bool nm_iam_pairing_is_password_invite_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);

#endif