#ifndef _NM_IAM_STATE_H_
#define _NM_IAM_STATE_H_

#include <nn/llist.h>
#include <nn/string_set.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_iam_user {
    char* username;
    char* displayName;
    char* role;
    char* password;
    char* fingerprint;
    char* sct;
    char* fcmToken;
    char* fcmProjectId;
    struct nn_string_set notificationCategories;

    struct nn_llist_node listNode;
};

struct nm_iam_state {
    struct nn_llist users;
    char* passwordOpenPassword;
    char* passwordOpenSct;
    bool passwordOpenPairing;
    bool localOpenPairing;
    bool passwordInvitePairing;
    bool localInitialPairing;
    char* openPairingRole;
    char* initialPairingUsername;
};

/*****************
 * State Builder *
 *****************/

/**
 * Create IAM state
 *
 * @return NULL iff the state could not be created
 */
struct nm_iam_state* nm_iam_state_new();

/**
 * Free IAM state if the ownership was not transfered to an
 * IAM module instance with nm_iam_load_state()
 *
 * @param state [in]  State to free
 */
void nm_iam_state_free(struct nm_iam_state* state);

/**
 * Set pairing password in the IAM state.
 *
 * @param state [in]     The IAM state,
 * @param password [in]  The password which clients needs to specify to pair with the system. The string is copied into the module. Password pairing can be disabled with the NULL password.
 * @return false iff the password was not set
 */
bool nm_iam_state_set_password_open_password(struct nm_iam_state* state, const char* password);

/**
 * Set remote pairing server connect token in the IAM state. A client
 * cannot make a remote pairing unless it has a valid server connect
 * token. This sets that server connect token when the state is
 * loaded.
 *
 * @param state [in]               The IAM state
 * @param sct [in]  The server connect token the client needs to use when pairing remotely with the system. The string is copied into the system.
 * @return false iff the server connect token was not set
 */
bool nm_iam_state_set_password_open_sct(struct nm_iam_state* state, const char* sct);

/**
 * Enable/disable password open pairing mode. Disabled per default.
 *
 * @param state [in]  The IAM state
 * @param b [in]      The boolean value to set
 */
void nm_iam_state_set_password_open_pairing(struct nm_iam_state* state, bool b);

/**
 * Enable/disable local open pairing modes. Disabled per default.
 *
 * @param state [in]  The IAM state
 * @param b [in]      The boolean value to set
 */
void nm_iam_state_set_local_open_pairing(struct nm_iam_state* state, bool b);

/**
 * Enable/disable password invite pairing mode. Disabled per default.
 *
 * @param state [in]  The IAM state
 * @param b [in]      The boolean value to set
 */
void nm_iam_state_set_password_invite_pairing(struct nm_iam_state* state, bool b);

/**
 * Enable/disable local initial pairing mode. Disabled per default.
 *
 * @param state [in]  The IAM state
 * @param b [in]      The boolean value to set
 */
void nm_iam_state_set_local_initial_pairing(struct nm_iam_state* state, bool b);

/**
 * Set the role to assign to new users paired through an open pairing
 * mode. The role ID string is copied into the state.
 *
 * @param state [in]            The IAM state
 * @param openPairingRole [in]  ID of the role to use.
 * @return true iff the role was set.
 */
bool nm_iam_state_set_open_pairing_role(struct nm_iam_state* state, const char* openPairingRole);

/**
 * Set the username to pair as during local initial pairing. The role
 * ID string is copied into the state.
 *
 * @param state [in]                   The IAM state
 * @param initialPairingUsername [in]  ID of the role to use.
 * @return true iff the username was set.
 */
bool nm_iam_state_set_initial_pairing_username(struct nm_iam_state* state, const char* initialPairingUsername);

/**
 * Add a user to the IAM state. The state takes ownership of the user
 * pointer.
 *
 * @param state [in]  State to add user to
 * @param user [in]   User to add
 * @return false iff the user could not be added
 */
bool nm_iam_state_add_user(struct nm_iam_state* state, struct nm_iam_user* user);


/****************
 * User Builder *
 ****************/

/**
 * Create a new user with the specified username. The username must
 * only use the character set: ['a-z', '0-9','_','-','.'].
 *
 * @param username [in]  The username. The string is copied into the user.
 * @return NULL iff the username was invalid or allocation failed
 */
struct nm_iam_user* nm_iam_state_user_new(const char* username);

/**
 * Free user created with nm_iam_state_user_new() if the ownership was
 * has not been transferred to the state using
 * nm_iam_state_add_user().
 *
 * @param user [in]  User to free
 */
void nm_iam_state_user_free(struct nm_iam_user* user);

/**
 * Set the public key fingerprint for user.
 *
 * @param user [in] the user to set fingerprint on
 * @param fingerprint [in] hex encoded public key fingerprint
 * @return true iff operation completed successfully
 */
bool nm_iam_state_user_set_fingerprint(struct nm_iam_user* user, const char* fingerprint);

/**
 * Set an SCT for the specified user while the system is running.
 *
 * @param user [in] the user to set SCT on
 * @param sct [in] the sct to set for the user
 * @return true iff operation completed successfully
 */
bool nm_iam_state_user_set_sct(struct nm_iam_user* user, const char* sct);

/**
 * Set display name for the specified user.
 *
 * @param user [in] the username of the user
 * @param displayName [in] the display name to set for the user
 * @return true iff operation completed successfully
 */
bool nm_iam_state_user_set_display_name(struct nm_iam_user* user, const char* displayName);

/**
 * Set role for the specified user.
 *
 * @param user [in] the username of the user
 * @param role [in] the role id to set for the user
 * @return true iff operation completed successfully
 */
bool nm_iam_state_user_set_role(struct nm_iam_user* user, const char* roleId);

/**
 * Set password for the specified user.
 *
 * @param user [in] the username of the user
 * @param password [in] the password to set for the user
 * @return NM_IAM_ERROR_OK if password was set successfully for the user.
 *         NM_IAM_ERROR_NO_SUCH_USER if the specified user does not exist.
 */
bool nm_iam_state_user_set_password(struct nm_iam_user* user, const char* password);
bool nm_iam_state_user_set_fcm_token(struct nm_iam_user* user, const char* token);
bool nm_iam_state_user_set_fcm_project_id(struct nm_iam_user* user, const char* id);


/**
 * Set notification categories in a user. Categories set on a user
 * must exist in the IAM module, since this function only builds the
 * state structure, setting an invalid category will not fail untill
 * the state is loaded into the IAM module. The contents of the string
 * set is copied into the string set of the user leaving ownership of
 * the provided string set to the caller.
 *
 * @param user [in]       User to set notification categories in
 * @param categories [in] Set of categories to copy into the user
 */
bool nm_iam_state_user_set_notification_categories(struct nm_iam_user* user, struct nn_string_set* categories);

/**
 * Find a user with a given username in a state structure.
 *
 * @param state [in]     The state to look for the user in
 * @param username [in]  The username to look for
 * @return NULL iff the user could not be found
 */
struct nm_iam_user* nm_iam_state_find_user_by_username(struct nm_iam_state* state, const char* username);

/**
 * Copy a state object. The received copy must be freed with
 * nm_iam_state_free() or the ownership must be transferred to an IAM
 * module instance.
 *
 * @param state [in]  The state to copy
 * @return NULL iff the state could not be copied
 */
struct nm_iam_state* nm_iam_state_copy(struct nm_iam_state* state);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
