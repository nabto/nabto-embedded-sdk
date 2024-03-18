#ifndef _NM_IAM_H_
#define _NM_IAM_H_

/*
 * Nabto Devce IAM Module.
 *
 * This header defines module life cycle functions to be used from applications and runtime
 * functions to enable pairing modes and manage users in the IAM state.
 */


#include "nm_iam_configuration.h"
#include "nm_iam_state.h"

#include "coap_handler/nm_iam_coap_handler.h"
#include "nm_iam_auth_handler.h"
#include "nm_iam_pake_handler.h"
#include "nm_iam_connection_events.h"

#include <nn/log.h>

#include <nn/vector.h>

#include <nn/string_map.h>
#include <nn/string_set.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Module implementation notice: Functions in this header must only be called from places which do
 * not hold the state mutex
 */

struct nm_iam;
struct nm_iam_policy;
struct nn_string_set;
struct nm_iam_role;
struct nabto_device_mutex;

/**
 * @intro Life Cycle and Types
 *
 * Manage the IAM module's life cycle: Initialize, deinitialize, load configuration, load full state,
 * dump full state.
 *
 * The load/dump functions can either be used with JSON serializers. Or a state object can be built
 * from scratch programmatically using the State Builder API, starting with `nm_iam_state_new()`.
 *
 * Granular manipulation of an existing state at runtime is possible using the Runtime State API to
 * e.g. enable pairing modes or add a user.
 *
 * Header: `src/modules/iam/nm_iam.h`
 */

/**
 * Callback to notify the application that state has been updated.
 *
 * This callback is set with nm_iam_set_state_changed_callback.
 *
 * This callback is always invoked without holding the state mutex: The application can read the IAM
 * state using nm_iam_dump_state which atomically creates a full copy of the state.
 */
typedef void (*nm_iam_state_changed)(struct nm_iam* iam, void* userData);

/**
 * IAM error codes.
 */
enum nm_iam_error {
    NM_IAM_ERROR_OK,
    NM_IAM_ERROR_NO_SUCH_USER,
    NM_IAM_ERROR_NO_SUCH_ROLE,
    NM_IAM_ERROR_USER_EXISTS,
    NM_IAM_ERROR_INVALID_FINGERPRINT,
    NM_IAM_ERROR_NO_SUCH_CATEGORY,
    NM_IAM_ERROR_INVALID_ARGUMENT,
    NM_IAM_ERROR_INTERNAL
};

/**
 * Initialize the IAM module, must be called before the IAM module is
 * used in any other functions.
 *
 * @param iam [in]    IAM module to initialize
 * @param device [in] Nabto device used with the IAM module
 * @param logger [in] Logging module to print log messages. Can be NULL.
 * @return true iff initialization was ok.
 */
bool nm_iam_init(struct nm_iam* iam, NabtoDevice* device, struct nn_log* logger);

/**
 * Stop the IAM module. This stops the NabtoDeviceListeners owned by
 * the IAM module. These listeners can also be implicitly stopped
 * using nabto_device_stop().
 *
 * @param iam [in]  IAM module to stop.
 */
void nm_iam_stop(struct nm_iam* iam);

/**
 * Deinitialize the IAM module. This must be called after
 * nabto_device_stop() to ensure the NabtoDeviceListeners are not in
 * use.
 *
 * @param iam [in]  IAM module to deinitialize.
 */
void nm_iam_deinit(struct nm_iam* iam);

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
 * Load a state into an IAM module.
 *
 * @param iam [in]     IAM module to load state into
 * @param state [in]   State to load. The IAM module takes ownership of the state.
 * @return false iff the state could not be loaded
 */
bool nm_iam_load_state(struct nm_iam* iam, struct nm_iam_state* state);

/**
 * Set change callbacks such that state can be persisted.
 * @param iam [in] IAM module to get notifications on state changes on.
 * @param userChange [in] the callback function
 * @param data [in] data passed to the callback function when invoked by the IAM module
 */
void nm_iam_set_state_changed_callback(struct nm_iam* iam, nm_iam_state_changed userChange, void* data);

/**
 * Create a copy of the state.
 * @param iam [in] IAM module to copy.
 * @return a deep copy of the input IAM state (or NULL if allocation fails)
 */
struct nm_iam_state* nm_iam_dump_state(struct nm_iam* iam);

/**
 * Set the list of notification categories users can subscribe
 * to. Trying to set a notification category that is not included in
 * this set will result in an error. The categories are copied into
 * IAM.
 *
 * @param iam [in]        IAM module to set categories in
 * @param categories [in] Set of notification categories to set
 * @return NM_IAM_ERROR_OK if the categories was set.
 */
enum nm_iam_error nm_iam_set_notification_categories(struct nm_iam* iam, struct nn_string_set* categories);

/*
 * Set the max lengths of strings stored by the IAM module to limit the size of storage needed to
 * store the IAM state and configuration. These must be called before nm_iam_load_state(). The
 * limits are enforced when updating state through the Runtime State API.
 *
 * Note: SCTs created automatically by the IAM module has length 12 which its limit must
 * allow.
 *
 * Default lengths are: username: 64, display name: 64, password: 64, fcm token: 1024, fcm project
 * id: 256, sct: 64, friendly name: 64.
 *
 * @param iam [in]  IAM module to set length in
 * @param len [in]  Length to set
 */
void nm_iam_set_username_max_length(struct nm_iam* iam, size_t len);
void nm_iam_set_display_name_max_length(struct nm_iam* iam, size_t len);
void nm_iam_set_password_min_length(struct nm_iam* iam, size_t len);
void nm_iam_set_password_max_length(struct nm_iam* iam, size_t len);
void nm_iam_set_fcm_token_max_length(struct nm_iam* iam, size_t len);
void nm_iam_set_fcm_project_id_max_length(struct nm_iam* iam, size_t len);
void nm_iam_set_oauth_subject_max_length(struct nm_iam* iam, size_t len);
void nm_iam_set_sct_max_length(struct nm_iam* iam, size_t len);
void nm_iam_set_friendly_name_max_length(struct nm_iam* iam, size_t len);

/*
 * Set the max number of users allowed in the IAM module.
 *
 * @param iam [in]  IAM module to set length in
 * @param n [in]    Max number of users to set. Default: SIZE_MAX
 */
void nm_iam_set_max_users(struct nm_iam* iam, size_t n);

/*
 * Set the max number of fingerprints allowed on a single user in the IAM module.
 *
 * @param iam [in]  IAM module to set length in
 * @param n [in]    Max number of fingerprints to set. Default: SIZE_MAX
 */
void nm_iam_set_max_user_fingerprints(struct nm_iam* iam, size_t n);

/**
 * @intro Runtime State
 *
 * Query and manage the IAM state while the system is running.
 *
 * These functions manipulate the IAM state in a thread safe manner. Note that when state has been
 * manipulated the state changed callback is invoked.
 *
 * Header: `src/modules/iam/nm_iam.h`
 */

/**
 * Check if the given connection has access to do the given action. Configured IAM polices are
 * evaluated in context of the connection and optional specified attributes.
 *
 * In addition to the specified attributes, the IAM module add the `Connection:IsLocal` as `true` or `false` based on `nabto_device_connection_is_local()` as well as the `Connection:Username` if the connection is authorized as a specific IAM user. Some CoAP requests and TCP Tunnels may call this function. In those cases, the action and any additional attributes are documented there.
 *
 * @param iam [in] IAM module to query
 * @param ref [in] the connection to check
 * @param action [in] the action to check if it is allowed
 * @param attributes [in] optional attributes to reference from policies (can be NULL)
 * @return true if the requested action is allowed, false if not
 */
bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct nn_string_map* attributes);

/**
 * Enable/disable the local open pairing mode.
 *
 * To allow the client to perform local open pairing, the mode must be enabled with this function
 * AND the client must be allowed to perform the `IAM:PairingLocalOpen` IAM action. That is, the
 * client must in a role associated with a policy associated with this action.
 *
 * See https://docs.nabto.com/developer/guides/iam/pairing.html#open-local for more information.
 *
 * @param iam [in] IAM module to enable pairing mode on
 * @param enabled [in] is the pairing mode enabled
 */
void nm_iam_set_local_open_pairing(struct nm_iam* iam, bool enabled);

/**
 * Enable/disable the password open pairing mode.
 *
 * To allow the client to perform password open pairing, the mode must be enabled with this function
 * AND the client must be allowed to perform the `IAM:PairingPasswordOpen` IAM action. That is, the
 * client must in a role associated with a policy associated with this action.
 *
 * See https://docs.nabto.com/developer/guides/iam/pairing.html#open-password for more information.
 *
 * @param iam [in] IAM module to enable pairing mode on
 * @param enabled [in] is the pairing mode enabled
 */
void nm_iam_set_password_open_pairing(struct nm_iam* iam, bool enabled);

/**
 * Enable/disable the password invite pairing mode.
 *
 * To allow the client to perform password invite pairing, the mode must be enabled with this function
 * AND the client must be allowed to perform the `IAM:PairingPasswordInvite` IAM action. That is, the
 * client must have a role associated with a policy associated with this action.
 *
 * See https://docs.nabto.com/developer/guides/iam/pairing.html#invite-password for more information.
 *
 * @param iam [in] IAM module to enable pairing mode on
 * @param enabled [in] is the pairing mode enabled
 */
void nm_iam_set_password_invite_pairing(struct nm_iam* iam, bool enabled);

/**
 * Enable/disable the local initial pairing mode.
 *
 * To allow the client to perform local initial pairing, the mode must be enabled with this function
 * AND the client must be allowed to perform the `IAM:PairingLocalInitial` IAM action. That is, the
 * client must in a role associated with a policy associated with this action.
 *
 * See https://docs.nabto.com/developer/guides/iam/pairing.html#initial-local for more information.
 *
 * @param iam [in] IAM module to enable pairing mode on
 * @param enabled [in] is the pairing mode enabled
 */
void nm_iam_set_local_initial_pairing(struct nm_iam* iam, bool enabled);

/**
 * Create a user in the IAM state while the system is running.
 *
 * @param iam [in] IAM module to manipulate
 * @param username [in] the username of the new user
 * @retval NM_IAM_ERROR_USER_EXISTS if the specified user already exists.
 * @retval NM_IAM_ERROR_OK if the user was created successfully.
 * @retval NM_IAM_ERROR_INVALID_ARGUMENT if the username was too long or invalid.
 * @retval NM_IAM_ERROR_INTERNAL if allocation failed
 */
enum nm_iam_error nm_iam_create_user(struct nm_iam* iam, const char* username);

/**
 * @deprecated use nm_iam_add_user_fingerprint()
 * Set the public key fingerprint for an existing user while the system is running.
 *
 * @param iam [in] IAM module to manipulate
 * @param username [in] the username of the user
 * @param fingerprint [in] hex encoded public key fingerprint
 * @retval NM_IAM_ERROR_INVALID_FINGERPRINT if the specified fingerprint is invalid.
 * @retval NM_IAM_ERROR_NO_SUCH_USER if the specified user does not exist.
 * @retval NM_IAM_ERROR_INVALID_ARGUMENT if the fingerprint length was not 64.
 * @retval NM_IAM_ERROR_OK if the fingerprint was set successfully for the user.
 */
enum nm_iam_error nm_iam_set_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint);

/**
 * Add a public key fingerprint to an existing user while the system is running.
 *
 * The fingerprint can be assigned a name to help identify which client device it belongs to. The name can be NULL.
 *
 * @param iam [in] IAM module to manipulate
 * @param username [in] the username of the user
 * @param fingerprint [in] hex encoded public key fingerprint
 * @param name [in] name to assign to the fingerprint
 * @retval NM_IAM_ERROR_INVALID_FINGERPRINT if the specified fingerprint is invalid.
 * @retval NM_IAM_ERROR_NO_SUCH_USER if the specified user does not exist.
 * @retval NM_IAM_ERROR_INVALID_ARGUMENT if the fingerprint length was not 64.
 * @retval NM_IAM_ERROR_OK if the fingerprint was set successfully for the user.
 */
enum nm_iam_error nm_iam_add_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint, const char* name);

/**
 * Remove a public key fingerprint from an existing user while the system is running.
 *
 * @param iam [in] IAM module to manipulate
 * @param username [in] the username of the user
 * @param fingerprint [in] hex encoded public key fingerprint
 * @retval NM_IAM_ERROR_INVALID_FINGERPRINT if the specified fingerprint is invalid.
 * @retval NM_IAM_ERROR_NO_SUCH_USER if the specified user does not exist.
 * @retval NM_IAM_ERROR_INVALID_ARGUMENT if the fingerprint length was not 64.
 * @retval NM_IAM_ERROR_OK if the fingerprint was set successfully for the user.
 */
enum nm_iam_error nm_iam_remove_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint);

/**
 * Set an SCT for the specified user while the system is running.
 *
 * See https://docs.nabto.com/developer/guides/security/token_based_access_control.html#sct-intro
 * for more information.
 *
 * @param iam [in] IAM module to manipulate
 * @param username [in] the username of the user
 * @param sct [in] the sct to set for the user
 * @retval NM_IAM_ERROR_OK if the SCT was set successfully for the user.
 * @retval NM_IAM_ERROR_NO_SUCH_USER if the specified user does not exist.
 * @retval NM_IAM_ERROR_INVALID_ARGUMENT if the sct was too long.
 */
enum nm_iam_error nm_iam_set_user_sct(struct nm_iam* iam, const char* username, const char* sct);

/**
 * Set password for the specified user.
 *
 * @param iam [in] IAM module to manipulate
 * @param username [in] the username of the user
 * @param password [in] the password to set for the user
 * @retval NM_IAM_ERROR_OK if password was set successfully for the user.
 * @retval NM_IAM_ERROR_NO_SUCH_USER if the specified user does not exist.
 * @retval NM_IAM_ERROR_INVALID_ARGUMENT if the password was too long.
 */
enum nm_iam_error nm_iam_set_user_password(struct nm_iam* iam, const char* username, const char* password);

/**
 * Set role for the specified user.
 *
 * @param iam [in] IAM module to manipulate
 * @param username [in] the username of the user
 * @param role [in] the role id to set for the user
 * @retval NM_IAM_ERROR_OK if role was set successfully for the user.
 * @retval NM_IAM_ERROR_NO_SUCH_USER if the specified user does not exist.
 * @retval NM_IAM_ERROR_NO_SUCH_ROLE if the role does not exist.
 */
enum nm_iam_error nm_iam_set_user_role(struct nm_iam* iam, const char* username, const char* role);

/**
 * Set display name for the specified user.
 *
 * @param iam [in] IAM module to manipulate
 * @param username [in] the username of the user
 * @param displayName [in] the display name to set for the user
 * @retval NM_IAM_ERROR_OK if display name was set successfully for the user.
 * @retval NM_IAM_ERROR_NO_SUCH_USER if the specified user does not exist.
 * @retval NM_IAM_ERROR_INVALID_ARGUMENT if the display name was too long.
 */
enum nm_iam_error nm_iam_set_user_display_name(struct nm_iam* iam, const char* username, const char* displayName);

enum nm_iam_error nm_iam_set_user_fcm_token(struct nm_iam* iam, const char* username, const char* token);
enum nm_iam_error nm_iam_set_user_fcm_project_id(struct nm_iam* iam, const char* username, const char* id);
enum nm_iam_error nm_iam_set_user_notification_categories(struct nm_iam* iam, const char* username, struct nn_string_set* categories);
enum nm_iam_error nm_iam_set_user_oauth_subject(struct nm_iam* iam, const char* username, const char* subject);

/**
 * Set display name for the specified user.
 *
 * @param iam [in] IAM module to manipulate
 * @param username [in] the username of the user to delete
 * @retval NM_IAM_ERROR_OK if the user was successfully deleted
 * @retval NM_IAM_ERROR_NO_SUCH_USER if the specified user does not exist.
 */
enum nm_iam_error nm_iam_delete_user(struct nm_iam* iam, const char* username);

/**
 * Authorize a NabtoDeviceConnectionRef as a specified user.
 *
 * This can be used if the application has authorized a connection eg. using Oauth.
 *
 * @param iam [in] IAM module to manipulate
 * @param ref [in] Connection ref to authorize
 * @param username [in] The username to authorize the connection as
 * @retval NM_IAM_ERROR_OK if the connection was authorized
 * @retval NM_IAM_ERROR_NO_SUCH_USER if the specified user does not exist.
 */
enum nm_iam_error nm_iam_authorize_connection(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* username);


/************************************************************
 * Module internal definitions, do not use from applications
 ************************************************************/

void nm_iam_lock(struct nm_iam* iam);
void nm_iam_unlock(struct nm_iam* iam);

struct nm_iam_change_callback {
    // called if a user is inserted, updated or removed.
    nm_iam_state_changed stateChanged;
    void* stateChangedData;
};

struct nm_iam_authorized_connection {
    NabtoDeviceConnectionRef ref;
    struct nm_iam_user* user;
};

struct nm_iam {
    /*
     * The mutex is provided such that the iam module can both be manipulated
     * from the nabto device coap endpoints and from the nm_iam_* api.
     */
    struct nabto_device_mutex* mutex;

    NabtoDevice* device;
    struct nn_log* logger;
    struct nm_iam_coap_handler coapIamUsersGetHandler;
    struct nm_iam_coap_handler coapPairingGetHandler;
    struct nm_iam_coap_handler coapPairingPasswordOpenPostHandler;
    struct nm_iam_coap_handler coapPairingPasswordInvitePostHandler;
    struct nm_iam_coap_handler coapPairingLocalOpenPostHandler;
    struct nm_iam_coap_handler coapPairingLocalInitialPostHandler;
    struct nm_iam_coap_handler coapIamNotificationCategoriesGetHandler;
    struct nm_iam_coap_handler coapIamSendFcmTestPostHandler;
    struct nm_iam_coap_handler coapIamMeGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserCreateHandler;
    struct nm_iam_coap_handler coapIamUsersUserDeleteHandler;
    struct nm_iam_coap_handler coapIamRolesGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetRoleHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetUsernameHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetDisplayNameHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetFingerprintHandler;
    struct nm_iam_coap_handler coapIamUsersUserAddFingerprintHandler;
    struct nm_iam_coap_handler coapIamUsersUserDeleteFingerprintHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetSctHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetPasswordHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetFcmTokenHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetNotificationCategoriesHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetOauthSubjectHandler;
    struct nm_iam_coap_handler coapIamSettingsSetHandler;
    struct nm_iam_coap_handler coapIamSettingsGetHandler;
    struct nm_iam_coap_handler coapIamDeviceInfoSetHandler;


    struct nm_iam_auth_handler authHandler;
    struct nm_iam_pake_handler pakeHandler;
    struct nm_iam_connection_events_ctx connEvents;

    struct nm_iam_change_callback changeCallback;
    struct nm_iam_configuration* conf;
    struct nm_iam_state* state;
    struct nn_string_set notificationCategories;

    size_t usernameMaxLength;
    size_t displayNameMaxLength;
    size_t passwordMinLength;
    size_t passwordMaxLength;
    size_t fcmTokenMaxLength;
    size_t fcmProjectIdMaxLength;
    size_t oauthSubjectMaxLength;
    size_t sctMaxLength;
    size_t maxUsers;
    size_t friendlyNameMaxLength;
    size_t maxUserFingerprints;

    struct nn_vector authorizedConnections;

    // if set to true the state has changed and the state has changed callback has to be invoked outside of the mutex.
    bool stateHasChanged;
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
