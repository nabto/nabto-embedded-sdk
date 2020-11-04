#include "nm_iam_pairing.h"
#include "nm_iam_internal.h"
#include "nm_iam_user.h"

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

bool nm_iam_pairing_is_local_invite_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref)
{
    if (!nm_iam_check_access(iam, ref, "IAM:PairingLocalInvite", NULL)) {
        return false;
    }

    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &iam->state->users) {
        if (user->fingerprint == NULL) {
            return true;
        }
    }
    return false;
}

bool nm_iam_pairing_is_local_initial_possible(struct nm_iam* iam, NabtoDeviceConnectionRef ref) 
{
    if (!nm_iam_check_access(iam, ref, "IAM:PairingLocalInitial", NULL)) {
        return false;
    }

    const char* initialUserUsername = iam->conf->initialUserUsername;
    struct nm_iam_user* initialUser = nm_iam_find_user_by_username(iam, initialUserUsername);
    if (initialUser == NULL) {
        return false;
    } else {
        if (nm_iam_pairing_is_user_paired(initialUser)) {
            return false;
        }
    }
    return true;
}

bool nm_iam_pairing_pair_user(struct nm_iam* iam, struct nm_iam_user* user, NabtoDeviceConnectionRef ref)
{
    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint(iam->device, ref, &fingerprint);
    if (ec) {
        return false;
    }

    bool status = nm_iam_user_set_fingerprint(user, fingerprint);
    nabto_device_string_free(fingerprint);
    return status;
}

bool nm_iam_pairing_is_user_paired(struct nm_iam_user* user)
{
    return (user->fingerprint != NULL);
}
