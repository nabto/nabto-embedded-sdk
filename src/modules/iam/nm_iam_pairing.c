#include "nm_iam_pairing.h"

const char* nm_iam_pairing_get_role(struct nm_iam* iam) {
    bool firstUser = nn_llist_empty(&iam->state->users);

    const char* role = NULL;
    if (firstUser) {
        role = iam->conf->firstUserRole;
    } else {
        role = iam->conf->secondaryUserRole;
    }
    return role;
}

bool nm_iam_pairing_is_local_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref)
{
    if (!nabto_device_connection_is_local(iam->device, ref)) {
        return false;
    }
    if (!nm_iam_check_access(iam, ref, "IAM:PairingLocalOpen", NULL)) {
        return false;
    }
    const char* role = nm_iam_pairing_get_role(iam);
    if(role == NULL) {
        return false;
    }
    return true;
}

bool nm_iam_pairing_is_password_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref)
{
    if (!nm_iam_check_access(iam, ref, "IAM:PairingPasswordOpen", NULL)) {
        return false;
    }
    if (iam->state->globalPairingPassword == NULL) {
        return false;
    }
    const char* role = nm_iam_pairing_get_role(iam);
    if(role == NULL) {
        return false;
    }
    return true;
}

bool nm_iam_pairing_is_password_invite_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref)
{
    if (!nm_iam_check_access(iam, ref, "IAM:PairingPasswordInvite", NULL)) {
        return false;
    }

    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &iam->state->users) {
        if (user->password != NULL) {
            return true;
        }
    }
    return false;
}