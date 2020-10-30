#ifndef _NM_IAM_STATE_H_
#define _NM_IAM_STATE_H_

#include <nn/llist.h>
#include <nn/string_set.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_iam_user {
    char* id;
    char* name;
    char* role;
    char* password;
    char* fingerprint;
    char* serverConnectToken;
    struct nn_llist_node listNode;
};

struct nm_iam_state {
    struct nn_llist users;
    char* globalPairingPassword;
    char* globalSct;
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
 * IAM module with nm_iam_load_state()
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
bool nm_iam_state_set_pairing_password(struct nm_iam_state* state, const char* password);

/**
 * Set remote pairing server connect token in the IAM state. A client
 * cannot make a remote pairing unless it has a valid server connect
 * token. This sets that server connect token when the state is
 * loaded.
 *
 * @param state [in]               The IAM state
 * @param serverConnectToken [in]  The server connect token the client needs to use when pairing remotely with the system. The string is copied into the system.
 * @return false iff the server connect token was not set
 */
bool nm_iam_state_set_pairing_server_connect_token(struct nm_iam_state* state, const char* serverConnectToken);

/**
 * Add a user to the IAM state. The state takes ownership of the user
 * pointer.
 *
 * @param state [in]  State to add user to
 * @param user [in]   User to add
 * @return false iff the user could not be added
 */
bool nm_iam_state_add_user(struct nm_iam_state* state, struct nm_iam_user* user);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
