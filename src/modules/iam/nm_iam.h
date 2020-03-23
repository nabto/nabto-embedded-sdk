#ifndef _NM_IAM_H_
#define _NM_IAM_H_

#include "nm_iam_coap_handler.h"
#include "nm_iam_auth_handler.h"

#include <platform/np_vector.h>
#include <platform/np_string_map.h>

// the iam module needs a list of users, roles, policies

struct nm_policy;
struct np_string_set;

typedef void (*nm_iam_user_changed)(struct nm_iam* iam, const char* userId, void* userData);

struct nm_iam_change_callbacks {
    // called if a user is inserted, updated or removed.
    nm_iam_user_changed userChanged;
    void* userChangedData;
};


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

    struct nm_iam_change_callbacks changeCallbacks;
    char* pairingPassword;
};

/**
 * Init the iam module
 */
void nm_iam_init(struct nm_iam* iam, NabtoDevice* device);

void nm_iam_start(struct nm_iam* iam);

/**
 * Deinit the iam module
 */
void nm_iam_deinit(struct nm_iam* iam);

/**
 * Enable password pairing mode for the iam module
 */
bool nm_iam_enable_password_pairing(struct nm_iam* iam, const char* pairingPassword);

/**
 * Enable remote pairing for the iam module
 */
bool nm_iam_enable_remote_pairing(struct nm_iam* iam, const char* pairingServerConnectToken);

/**
 * Set change callbacks such that state can be persisted
 */
void nm_iam_set_user_changed_callback(struct nm_iam* iam, nm_iam_user_changed userChange, void* data);

/**
 * Find a user by the user id.
 *
 * @return NULL if no such user exists.
 */
struct nm_iam_user* nm_iam_find_user(struct nm_iam* iam, const char* id);

/**
 * Add a user to the iam system.
 * The system takes ownership of the user pointer.
 */
bool nm_iam_add_user(struct nm_iam* iam, struct nm_iam_user* user);

/**
 * Get a list of all users in the system.
 */
bool nm_iam_get_users(struct nm_iam* iam, struct np_string_set* ids);

/**
 * Add a role to the iam system.
 * The IAM system takes ownership of the role pointer.
 */
bool nm_iam_add_role(struct nm_iam* iam, struct nm_iam_role* role);


/**
 * Add a policy to the IAM system
 *
 * The ownership of the policy is transferred to the IAM system.
 */
bool nm_iam_add_policy(struct nm_iam* iam, struct nm_policy* policy);

/**
 * Check if the given connection has access to do the given action
 * provided the given attributes.
 */
bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct np_string_map* attributes);

#endif
