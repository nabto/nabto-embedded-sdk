#ifndef _NM_IAM_USER_H_
#define _NM_IAM_USER_H_

#include <platform/np_string_set.h>
#include <platform/np_string_map.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_iam_user {
    char* id;
    struct np_string_set roles;
    char* fingerprint;
    char* serverConnectToken;
    struct np_string_map attributes;
};

void nm_iam_user_init(struct nm_iam_user* user);
void nm_iam_user_deinit(struct nm_iam_user* user);

struct nm_iam_user* nm_iam_user_new(const char* id);
void nm_iam_user_free(struct nm_iam_user* user);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
