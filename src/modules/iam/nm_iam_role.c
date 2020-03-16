#include "nm_iam_role.h"

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

struct nm_iam_role* nm_iam_role_new(const char* idIn)
{
    struct nm_iam_role* role = NULL;
    char* id = NULL;


    id = strdup(idIn);

    role = calloc(1, sizeof(struct nm_iam_role));
    if (role == NULL ||
        id == NULL)
    {
        free(id);
        free(role);
        return NULL;
    }
    np_string_set_init(&role->policies);
    role->id = id;
    return role;
}

void nm_iam_role_free(struct nm_iam_role* role)
{
    np_string_set_deinit(&role->policies);
    free(role->id);
    free(role);
}

np_error_code nm_iam_role_add_policy(struct nm_iam_role* role, const char* policy)
{
    return np_string_set_add(&role->policies, policy);
}
