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
bool nm_iam_user_set_server_connect_token(struct nm_iam_user* user, const char* serverConnectToken);
bool nm_iam_user_set_username(struct nm_iam_user* user, const char* username);
bool nm_iam_user_set_role(struct nm_iam_user* user, const char* roleId);
bool nm_iam_user_set_password(struct nm_iam_user* user, const char* password);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
