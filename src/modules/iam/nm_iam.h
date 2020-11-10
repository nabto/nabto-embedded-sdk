#ifndef _NM_IAM_H_
#define _NM_IAM_H_

#include <api/nabto_device_threads.h>

#include "nm_iam_configuration.h"
#include "nm_iam_state.h"

#include "coap_handler/nm_iam_coap_handler.h"
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

/**
 * Functions in this header must only be called from the places which does not hold the mutex
 */

struct nm_iam_policy;
struct nn_string_set;
struct nm_iam_role;

/**
 * This callback is always invoked without holding the mutex
 */
typedef void (*nm_iam_state_changed)(struct nm_iam* iam, void* userData);

struct nm_iam_change_callback {
    // called if a user is inserted, updated or removed.
    nm_iam_state_changed stateChanged;
    void* stateChangedData;
};

enum nm_iam_error {
    NM_IAM_ERROR_OK,
    NM_IAM_ERROR_NO_SUCH_USER,
    NM_IAM_ERROR_NO_SUCH_ROLE,
    NM_IAM_ERROR_USER_EXISTS,
    NM_IAM_ERROR_INVALID_FINGERPRINT,
    NM_IAM_ERROR_INTERNAL
};

struct nm_iam {
    /**
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
    struct nm_iam_coap_handler coapIamMeGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserCreateHandler;
    struct nm_iam_coap_handler coapIamUsersUserDeleteHandler;
    struct nm_iam_coap_handler coapIamRolesGetHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetRoleHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetUsernameHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetDisplayNameHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetFingerprintHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetSctHandler;
    struct nm_iam_coap_handler coapIamUsersUserSetPasswordHandler;
    struct nm_iam_coap_handler coapIamSettingsSetHandler;
    struct nm_iam_coap_handler coapIamSettingsGetHandler;


    struct nm_iam_auth_handler authHandler;
    struct nm_iam_pake_handler pakeHandler;

    struct nm_iam_change_callback changeCallback;
    struct nm_iam_configuration* conf;
    struct nm_iam_state* state;

    // if set to true the state has changed and the state has changed callback has to be invoked outside of the mutex.
    bool stateHasChanged;
};

void nm_iam_lock(struct nm_iam* iam);
void nm_iam_unlock(struct nm_iam* iam);

/**
 * Initialize the IAM module, must be called before the IAM module is
 * used in any other functions.
 *
 * @param iam [in]    IAM module to initialize
 * @param device [in] Nabto device used with the IAM module
 * @param logger [in] Logging module to print log messages. Can be NULL.
 */
void nm_iam_init(struct nm_iam* iam, NabtoDevice* device, struct nn_log* logger);

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
 * Set change callbacks such that state can be persisted
 */
void nm_iam_set_state_changed_callback(struct nm_iam* iam, nm_iam_state_changed userChange, void* data);

/**
 * Dump a copy of the state
 */
struct nm_iam_state* nm_iam_dump_state(struct nm_iam* iam);

/**
 * Check if the given connection has access to do the given action
 * provided the given attributes.
 */
bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct nn_string_map* attributes);

/*********
 * Manage the IAM state while the system is running
 *
 * These function takes the lock and manipulates the state, When the state has
 * been manipulated the state changed callback is invoked.
 *********/

/**
 * Enable/disalbe open pairing.
 */
void nm_iam_set_local_open_pairing(struct nm_iam* iam, bool enabled);
void nm_iam_set_password_open_pairing(struct nm_iam* iam, bool enabled);
void nm_iam_set_local_intiial_pairing(struct nm_iam* iam, bool enabled);

/**
 * Manage the user database at runtime from the application
 */
enum nm_iam_error nm_iam_create_user(struct nm_iam* iam, const char* username);

enum nm_iam_error nm_iam_set_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint);
enum nm_iam_error nm_iam_set_user_sct(struct nm_iam* iam, const char* username, const char* sct);
enum nm_iam_error nm_iam_set_user_password(struct nm_iam* iam, const char* username, const char* password);
enum nm_iam_error nm_iam_set_user_role(struct nm_iam* iam, const char* username, const char* role);
enum nm_iam_error nm_iam_set_user_display_name(struct nm_iam* iam, const char* username, const char* displayName);

enum nm_iam_error nm_iam_delete_user(struct nm_iam* iam, const char* username);


#ifdef __cplusplus
} //extern "C"
#endif

#endif
