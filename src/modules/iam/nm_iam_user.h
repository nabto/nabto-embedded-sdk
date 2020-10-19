#ifndef _NM_IAM_USER_H_
#define _NM_IAM_USER_H_

#include <nn/string_set.h>
#include <nn/string_map.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_iam_user {
    char* id;
    char* name;
    char* role;
    char* fingerprint;
    char* serverConnectToken;
    struct nn_string_map attributes;
};

void nm_iam_user_init(struct nm_iam_user* user);
void nm_iam_user_deinit(struct nm_iam_user* user);

struct nm_iam_user* nm_iam_user_new(const char* id);
void nm_iam_user_free(struct nm_iam_user* user);

bool nm_iam_user_set_fingerprint(struct nm_iam_user* user, const char* fingerprint);
bool nm_iam_user_set_server_connect_token(struct nm_iam_user* user, const char* serverConnectToken);
bool nm_iam_user_set_name(struct nm_iam_user* user, const char* name);
bool nm_iam_user_set_role(struct nm_iam_user* user, const char* roleId);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
