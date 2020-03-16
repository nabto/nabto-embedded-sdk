#ifndef _NM_IAM_ROLE_H_
#define _NM_IAM_ROLE_H_

#include <platform/np_string_set.h>

struct nm_iam_role {
    char* id;
    struct np_string_set policies;
};

struct nm_iam_role* nm_iam_role_new(const char* id);
void nm_iam_role_free(struct nm_iam_role* role);

np_error_code nm_iam_role_add_policy(struct nm_iam_role* role, const char* policy);

#endif
