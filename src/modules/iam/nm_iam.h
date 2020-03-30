#ifndef _NM_IAM_H_
#define _NM_IAM_H_


#include "nm_iam_coap_handler.h"
#include "nm_iam_auth_handler.h"

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
    struct nm_iam_coap_handler coapPairingIsPairedGetHandler;
    struct nm_iam_coap_handler coapPairingClientSettingsGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserDeleteHandler;
    struct nm_iam_coap_handler coapIamRolesGetHandler;

    struct nm_iam_auth_handler authHandler;

    struct nm_iam_change_callbacks changeCallbacks;
    char* pairingPassword;
    char* clientServerUrl;
    char* clientServerKey;
};

/**
 * Init the iam module
 */
void nm_iam_init(struct nm_iam* iam, NabtoDevice* device, struct nn_log* logger);

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
 * Enable client settings.
 *
 * This allows client settings to be provisioned by a coap request to the device
 */
void nm_iam_enable_client_settings(struct nm_iam* iam, const char* clientServerUrl, const char* clientServerKey);

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

#ifdef __cplusplus
} //extern "C"
#endif

#endif
