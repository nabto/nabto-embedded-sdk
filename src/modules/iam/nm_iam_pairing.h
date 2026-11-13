#ifndef NM_IAM_PAIRING_H_
#define NM_IAM_PAIRING_H_

#include "nm_iam.h"

#ifdef __cplusplus
extern "C" {
#endif

bool nm_iam_pairing_is_local_open_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);
bool nm_iam_pairing_is_password_open_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);
bool nm_iam_pairing_is_password_invite_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);
bool nm_iam_pairing_is_local_initial_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref);

/**
 * Take the fingerprint from the connection and load it into the user.
 *
 * @retval NM_IAM_ERROR_OK if the fingerprint was added to the user.
 * @retval NM_IAM_ERROR_USER_EXISTS if the fingerprint belongs to a user already.
 * @retval NM_IAM_ERROR_INTERNAL if the fingerprint could not be added.
 */
enum nm_iam_error nm_iam_pairing_pair_user(struct nm_iam* iam, struct nm_iam_user* user, NabtoDeviceConnectionRef ref, const char* fpName);
bool nm_iam_pairing_is_user_paired(struct nm_iam_user* user);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
