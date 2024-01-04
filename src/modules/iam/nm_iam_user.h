#ifndef _NM_IAM_USER_H_
#define _NM_IAM_USER_H_

#include "nm_iam_state.h"

#include <nn/string_set.h>
#include <nn/string_map.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_iam_user* nm_iam_user_new(const char* username);
void nm_iam_user_free(struct nm_iam_user* user);

bool nm_iam_user_validate_username(const char* username);

bool nm_iam_user_set_fingerprint(struct nm_iam_user* user, const char* fingerprint);
bool nm_iam_user_set_sct(struct nm_iam_user* user, const char* sct);
bool nm_iam_user_set_username(struct nm_iam_user* user, const char* username);
bool nm_iam_user_set_display_name(struct nm_iam_user* user, const char* displayName);
bool nm_iam_user_set_role(struct nm_iam_user* user, const char* roleId);
bool nm_iam_user_set_password(struct nm_iam_user* user, const char* password);
bool nm_iam_user_set_fcm_token(struct nm_iam_user* user, const char* fcmToken);
bool nm_iam_user_set_fcm_project_id(struct nm_iam_user* user, const char* fcmProjectId);
bool nm_iam_user_set_notification_categories(struct nm_iam_user* user, struct nn_string_set* categories);
bool nm_iam_user_set_oauth_subject(struct nm_iam_user* user, const char* subject);

struct nm_iam_user* nm_iam_user_copy(struct nm_iam_user* user);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
