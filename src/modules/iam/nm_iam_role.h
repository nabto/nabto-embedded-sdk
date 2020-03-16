#ifndef _NM_IAM_ROLE_H_
#define _NM_IAM_ROLE_H_

struct nm_iam_role {
    char* id;
    struct np_string_set policies;
};

#endif
