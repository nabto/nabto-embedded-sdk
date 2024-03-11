#ifndef _NM_IAM_INTERNAL_H_
#define _NM_IAM_INTERNAL_H_

#include "nm_iam.h"


bool nm_iam_internal_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct nn_string_map* attributesIn);

char* nm_iam_internal_get_fingerprint_from_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request);
struct nm_iam_user* nm_iam_internal_find_user_by_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request);
struct nm_iam_user* nm_iam_internal_find_user(struct nm_iam* iam, const char* username);

bool nm_iam_internal_load_state(struct nm_iam* iam, struct nm_iam_state* state);
bool nm_iam_internal_load_configuration(struct nm_iam* iam, struct nm_iam_configuration* conf);
void nm_iam_internal_init_coap_handlers(struct nm_iam* iam);
void nm_iam_internal_deinit_coap_handlers(struct nm_iam* iam);
void nm_iam_internal_stop(struct nm_iam* iam);

enum nm_iam_effect nm_iam_internal_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct nn_string_map* attributes);

struct nm_iam_role* nm_iam_internal_find_role(struct nm_iam* iam, const char* role);
struct nm_iam_user* nm_iam_internal_find_user(struct nm_iam* iam, const char* username);
void nm_iam_internal_do_callbacks(struct nm_iam* iam);


enum nm_iam_error nm_iam_internal_pair_new_client(struct nm_iam* iam, const char* username, const char* fingerprint, const char* fpName);

/**
 * Find a user by the user id.
 *
 * @return NULL if no such user exists.
 */
struct nm_iam_user* nm_iam_internal_find_user(struct nm_iam* iam, const char* id);

/**
 * Get a list of all users in the system.
 */
bool nm_iam_internal_get_users(struct nm_iam* iam, struct nn_string_set* ids);

bool nm_iam_internal_add_user(struct nm_iam* iam, struct nm_iam_user* user);
struct nm_iam_user* nm_iam_internal_find_user_by_fingerprint(struct nm_iam* iam, const char* fingerprint);
struct nm_iam_user* nm_iam_internal_find_user_by_username(struct nm_iam* iam, const char* username);
struct nm_iam_role* nm_iam_internal_find_role(struct nm_iam* iam, const char* roleStr);
struct nm_iam_policy* nm_iam_internal_find_policy(struct nm_iam* iam, const char* policyStr);

struct nm_iam_user* nm_iam_pinternal_air_new_client(struct nm_iam* iam, NabtoDeviceCoapRequest* request, const char* username);
struct nm_iam_user* nm_iam_internal_find_user_by_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request);

void nm_iam_internal_state_has_changed(struct nm_iam* iam);

enum nm_iam_error nm_iam_internal_create_user(struct nm_iam* iam, const char* username);
enum nm_iam_error nm_iam_internal_set_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint);
enum nm_iam_error nm_iam_internal_add_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint, const char* fpName);
enum nm_iam_error nm_iam_internal_remove_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint);
enum nm_iam_error nm_iam_internal_set_user_sct(struct nm_iam* iam, const char* username, const char* sct);
enum nm_iam_error nm_iam_internal_set_user_password(struct nm_iam* iam, const char* username, const char* password);
enum nm_iam_error nm_iam_internal_set_user_role(struct nm_iam* iam, const char* username, const char* role);
enum nm_iam_error nm_iam_internal_set_user_display_name(struct nm_iam* iam, const char* username, const char* displayName);
enum nm_iam_error nm_iam_internal_set_user_fcm_token(struct nm_iam* iam, const char* username, const char* token);
enum nm_iam_error nm_iam_internal_set_user_fcm_project_id(struct nm_iam* iam, const char* username, const char* id);
enum nm_iam_error nm_iam_internal_set_user_notification_categories(struct nm_iam* iam, const char* username, struct nn_string_set* categories);
enum nm_iam_error nm_iam_internal_set_user_oauth_subject(struct nm_iam* iam, const char* username, const char* subject);

enum nm_iam_error nm_iam_internal_delete_user(struct nm_iam* iam, const char* username);

enum nm_iam_error nm_iam_internal_authorize_connection(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* username);
#endif
