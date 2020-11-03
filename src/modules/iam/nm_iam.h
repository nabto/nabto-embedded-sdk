#ifndef _NM_IAM_H_
#define _NM_IAM_H_

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

struct nm_iam_policy;
struct nn_string_set;
struct nm_iam_role;

typedef void (*nm_iam_user_changed)(struct nm_iam* iam, const char* username, void* userData);

struct nm_iam_change_callback {
    // called if a user is inserted, updated or removed.
    nm_iam_user_changed userChanged;
    void* userChangedData;
};


struct nm_iam {
    NabtoDevice* device;
    struct nn_log* logger;

    struct nm_iam_coap_handler coapIamUsersGetHandler;
    struct nm_iam_coap_handler coapPairingGetHandler;
    struct nm_iam_coap_handler coapPairingPasswordOpenPostHandler;
    struct nm_iam_coap_handler coapPairingPasswordInvitePostHandler;
    struct nm_iam_coap_handler coapPairingLocalOpenPostHandler;
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

    struct nm_iam_auth_handler authHandler;
    struct nm_iam_pake_handler pakeHandler;

    struct nm_iam_change_callback changeCallback;
    struct nm_iam_configuration* conf;
    struct nm_iam_state* state;
};

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
 * Load a state into an IAM module. Must be called before
 * nabto_device_start() to avoid concurrency issues. The state can
 * only be modified by CoAP calls from the client after device start.
 *
 * @param iam [in]     IAM module to load state into
 * @param state [in]   State to load. The IAM module takes ownership of the state.
 * @return false iff the state could not be loaded
 */
bool nm_iam_load_state(struct nm_iam* iam, struct nm_iam_state* state);

/**
 * Set change callbacks such that state can be persisted
 */
void nm_iam_set_user_changed_callback(struct nm_iam* iam, nm_iam_user_changed userChange, void* data);

/**
 * Check if the given connection has access to do the given action
 * provided the given attributes.
 */
bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct nn_string_map* attributes);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
