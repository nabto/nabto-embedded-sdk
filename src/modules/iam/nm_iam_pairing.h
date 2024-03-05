#ifndef _NM_IAM_PAIRING_H_
#define _NM_IAM_PAIRING_H_

#include "nm_iam.h"

bool nm_iam_pairing_is_local_open_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);
bool nm_iam_pairing_is_password_open_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);
bool nm_iam_pairing_is_password_invite_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);
bool nm_iam_pairing_is_local_initial_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);

// take the fingerprint from the connection and load it into the user.
bool nm_iam_pairing_pair_user(struct nm_iam* iam, struct nm_iam_user* user, NabtoDeviceConnectionRef ref, const char* fpName);
bool nm_iam_pairing_is_user_paired(struct nm_iam_user* user);

#endif
