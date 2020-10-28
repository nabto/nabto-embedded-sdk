#ifndef _NM_IAM_H_
#define _NM_IAM_H_

#include "nm_iam_configuration.h"
#include "nm_iam_state.h"

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
    struct nm_iam_configuration conf;
    struct nm_iam_state state;
};

/**
 * Init the iam module
 */
void nm_iam_init(struct nm_iam* iam, NabtoDevice* device, struct nn_log* logger);


/**
 * Load a configuration into an IAM module. Must be called before
 * nabto_device_start() to avoid concurrency issues. The configuration
 * cannot be changed after device start.
 *
 * @param iam [in]           IAM module to load configuration into
 * @param configuration [in] Configuration to load. The IAM module takes ownership of the configuration.
 * @return false iff the configuration could not be loaded
 */
bool nm_iam_load_configuration(struct nm_iam* iam, struct nm_iam_configuration* configuration);

/**
 * Load a state into an IAM module. Must be called before
 * nabto_device_start() to avoid concurrency issues. The state can
 * only be modified by CoAP calls from the client after device start.
 *
 * @param iam [in]     IAM module to load state into
 * @param state [in]   State to load. The IAM module takes ownership of the state.
 * @return false iff the state could not be loaded
 */
bool nm_iam_load_state(struct nm_iam* iam, struct nm_iam_state* state);

bool nm_iam_start(struct nm_iam* iam);

/**
 * Deinit the iam module
 */
void nm_iam_deinit(struct nm_iam* iam);

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
 * Get a list of all users in the system.
 */
bool nm_iam_get_users(struct nm_iam* iam, struct nn_string_set* ids);

/**
 * Delete an user.
 */
void nm_iam_delete_user(struct nm_iam* iam, const char* userId);

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
