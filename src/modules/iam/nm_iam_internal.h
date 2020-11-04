#ifndef _NM_IAM_INTERNAL_H_
#define _NM_IAM_INTERNAL_H_

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
void nm_iam_delete_user(struct nm_iam* iam, const char* username);

/**
 * Set a role to a user
 */
bool nm_iam_set_user_role(struct nm_iam* iam, const char* username, const char* roleId);


bool nm_iam_add_user(struct nm_iam* iam, struct nm_iam_user* user);
struct nm_iam_user* nm_iam_find_user_by_fingerprint(struct nm_iam* iam, const char* fingerprint);
struct nm_iam_user* nm_iam_find_user_by_username(struct nm_iam* iam, const char* username);
struct nm_iam_role* nm_iam_find_role(struct nm_iam* iam, const char* roleStr);
struct nm_iam_policy* nm_iam_find_policy(struct nm_iam* iam, const char* policyStr);

struct nm_iam_user* nm_iam_pair_new_client(struct nm_iam* iam, NabtoDeviceCoapRequest* request, const char* username);
struct nm_iam_user* nm_iam_find_user_by_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request);

void nm_iam_user_has_changed(struct nm_iam* iam, const char* username);

#endif
