#include "nm_iam_role.h"

#include <platform/np_heap.h>

#include <nn/llist.h>

#include <stddef.h>
#include <string.h>


struct nm_iam_role* nm_iam_role_new(const char* idIn)
{
    struct nm_iam_role* role = NULL;
    char* id = NULL;


    id = strdup(idIn);

    role = np_calloc(1, sizeof(struct nm_iam_role));
    if (role == NULL ||
        id == NULL)
    {
        np_free(id);
        np_free(role);
        return NULL;
    }
    nn_string_set_init(&role->policies);
    nn_llist_node_init(&role->listNode);
    role->id = id;
    return role;
}

void nm_iam_role_free(struct nm_iam_role* role)
{
    nn_string_set_deinit(&role->policies);
    np_free(role->id);
    np_free(role);
}

bool nm_iam_role_add_policy(struct nm_iam_role* role, const char* policy)
{
    return nn_string_set_insert(&role->policies, policy);
}
