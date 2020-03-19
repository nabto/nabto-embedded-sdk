#ifndef _NM_IAM_H_
#define _NM_IAM_H_

#include "nm_iam_coap_handler.h"
#include "nm_iam_auth_handler.h"

#include <platform/np_vector.h>
#include <platform/np_string_map.h>

// the iam module needs a list of users, roles, policies

struct nm_iam {
    NabtoDevice* device;
    struct np_vector users;
    struct np_vector roles;
    struct np_vector policies;

    struct nm_iam_coap_handler coapIamUsersGetHandler;
    struct nm_iam_coap_handler coapPairingGetHandler;
    struct nm_iam_coap_handler coapPairingPasswordPostHandler;

    struct nm_iam_auth_handler authHandler;

    struct nm_iam_role* unpairedRole;

    char* pairingPassword;
};

void nm_iam_init(struct nm_iam* iam, NabtoDevice* device);
void nm_iam_deinit(struct nm_iam* iam);

char* nm_iam_next_user_id(struct nm_iam* iam);

bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct np_string_map* attributes);

bool nm_iam_enable_password_pairing(struct nm_iam* iam, const char* pairingPassword);

bool nm_iam_enable_remote_pairing(struct nm_iam* iam, const char* pairingServerConnectToken);

struct nm_iam_user* nm_iam_find_user_by_fingerprint(struct nm_iam* iam, const char* fingerprint);
struct nm_iam_role* nm_iam_find_role(struct nm_iam* iam, const char* roleStr);
struct nm_policy* nm_iam_find_policy(struct nm_iam* iam, const char* policyStr);

struct nm_iam_user* nm_iam_pair_new_client(struct nm_iam* iam, NabtoDeviceCoapRequest* request, const char* name);

#endif
