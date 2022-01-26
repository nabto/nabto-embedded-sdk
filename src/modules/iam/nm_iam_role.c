#include "nm_iam_role.h"

#include "nm_iam_allocator.h"

#include <nn/llist.h>
#include <nn/string.h>

#include <stddef.h>
#include <string.h>


struct nm_iam_role* nm_iam_role_new(const char* idIn)
{
    struct nm_iam_role* role = NULL;
    char* id = NULL;


    id = nn_strdup(idIn, nm_iam_allocator_get());

    role = nm_iam_calloc(1, sizeof(struct nm_iam_role));
    if (role == NULL ||
        id == NULL)
    {
        nm_iam_free(id);
        nm_iam_free(role);
        return NULL;
    }
    nn_string_set_init(&role->policies, nm_iam_allocator_get());
    nn_llist_node_init(&role->listNode);
    role->id = id;
    return role;
}

void nm_iam_role_free(struct nm_iam_role* role)
{
    nn_string_set_deinit(&role->policies);
    nm_iam_free(role->id);
    nm_iam_free(role);
}

bool nm_iam_role_add_policy(struct nm_iam_role* role, const char* policy)
{
    return nn_string_set_insert(&role->policies, policy);
}
