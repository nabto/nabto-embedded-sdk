#ifndef _NM_IAM_H_
#define _NM_IAM_H_


#include "nm_iam_coap_handler.h"
#include "nm_iam_auth_handler.h"
#include "nm_iam_pake_handler.h"

#include <nn/log.h>

#include <nn/vector.h>

#include <nn/string_map.h>
#include <nn/string_set.h>

#ifdef __cplusplus
extern "C" {
#endif

// the iam module needs a list of users, roles, policies

struct nm_policy;
struct nn_string_set;
struct nm_iam_role;

typedef void (*nm_iam_user_changed)(struct nm_iam* iam, const char* userId, void* userData);

struct nm_iam_change_callbacks {
    // called if a user is inserted, updated or removed.
    nm_iam_user_changed userChanged;
    void* userChangedData;
};


struct nm_iam {
    NabtoDevice* device;
    struct nn_log* logger;
    struct nn_vector users;
    struct nn_vector roles;
    struct nn_vector policies;

    struct nm_iam_coap_handler coapIamUsersGetHandler;
    struct nm_iam_coap_handler coapPairingGetHandler;
    struct nm_iam_coap_handler coapPairingPasswordPostHandler;
    struct nm_iam_coap_handler coapPairingLocalPostHandler;
    struct nm_iam_coap_handler coapPairingIsPairedGetHandler;
    struct nm_iam_coap_handler coapPairingClientSettingsGetHandler;
    struct nm_iam_coap_handler coapIamMeGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserCreateHandler;
    struct nm_iam_coap_handler coapIamUsersUserDeleteHandler;
    struct nm_iam_coap_handler coapIamRolesGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetRoleHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetNameHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetFingerprintHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetSctHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetPasswordHandler;

    struct nm_iam_auth_handler authHandler;
    struct nm_iam_pake_handler pakeHandler;

    struct nm_iam_change_callbacks changeCallbacks;
    char* pairingPassword;
    char* clientServerUrl;
    char* clientServerKey;

    char* firstUserRole;
    char* secondaryUserRole;
    char* unpairedRole;
};

/**
 * Init the iam module
 */
void nm_iam_init(struct nm_iam* iam, NabtoDevice* device, struct nn_log* logger);

bool nm_iam_start(struct nm_iam* iam);

/**
 * Deinit the iam module
 */
void nm_iam_deinit(struct nm_iam* iam);

/**
 * Control how users is paired with the IAM module.
 */

/**
 * Enable password pairing mode for the iam module.
 *
 * @param iam  The iam module,
 * @param pairingPassword  The password which clients needs to specify to pair with the system. The string is copied into the module.
 */
bool nm_iam_enable_password_pairing(struct nm_iam* iam, const char* pairingPassword);

/**
 * Enable remote pairing for the iam module. A client cannot make a
 * remote pairing unless it has a valid server connect token. This
 * sets that server connect token.
 *
 * @param iam  The IAM module.
 * @param pairingServerConnectToken  The server connect token the client needs to use when pairing remotely with the system. The string is copied into the system.
 */
bool nm_iam_enable_remote_pairing(struct nm_iam* iam, const char* pairingServerConnectToken);

/**
 * Set the role for the first paired user. If no role is added the
 * system will probably not work.
 *
 * @param iam  The IAM module
 * @param role  Set the role of first user role to pair. The string is copied into the module.
 * @return false iff the role was not set.
 */
bool nm_iam_set_first_user_role(struct nm_iam* iam, const char* role);

/**
 * Set the role for the secondary users on the system. If no role is
 * set, the system will probably not work.
 *
 * @param iam  The iam module
 * @param role  Set the role of the secondary users. The string is copied into the module.
 * @return false iff the role was not set.
 */
bool nm_iam_set_secondary_user_role(struct nm_iam* iam, const char* role);

/**
 * Set the role for unpaired connections on the system. The unpaired
 * connections should probably be allowed to do pairings and get some
 * public information.
 *
 * @param iam  The iam module.
 * @param role The role to set as the unpaired role. The string is copied into the module.
 * @return false iff the role was not set.
 */
bool nm_iam_set_unpaired_role(struct nm_iam* iam, const char* role);



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
bool nm_iam_get_users(struct nm_iam* iam, struct nn_string_set* ids);

/**
 * Delete an user.
 */
void nm_iam_delete_user(struct nm_iam* iam, const char* userId);

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
bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct nn_string_map* attributes);

/**
 * Set a role to a user
 */
bool nm_iam_set_user_role(struct nm_iam* iam, const char* userId, const char* roleId);


#ifdef __cplusplus
} //extern "C"
#endif

#endif
