#include "nm_iam_user.h"

#include <stdlib.h>
#include <string.h>

void nm_iam_user_init(struct nm_iam_user* user)
{
    memset(user, 0, sizeof(struct nm_iam_user));
    nn_string_set_init(&user->roles);
    nn_string_map_init(&user->attributes);
}

void nm_iam_user_deinit(struct nm_iam_user* user)
{
    nn_string_set_deinit(&user->roles);
    nn_string_map_deinit(&user->attributes);
}


struct nm_iam_user* nm_iam_user_new(const char* idIn)
{
    char* id = strdup(idIn);
    struct nm_iam_user* user = calloc(1, sizeof(struct nm_iam_user));
    if (id == NULL || user == NULL) {
        free(id);
        free(user);
        return NULL;
    }

    nn_string_map_init(&user->attributes);
    nn_string_set_init(&user->roles);
    user->id = id;

    return user;
}

void nm_iam_user_free(struct nm_iam_user* user)
{
    free(user->id);
    free(user->fingerprint);
    free(user->serverConnectToken);
    nn_string_map_deinit(&user->attributes);
    nn_string_set_deinit(&user->roles);
    free(user);
}

bool nm_iam_user_add_role(struct nm_iam_user* user, const char* roleId)
{
    return nn_string_set_insert(&user->roles, roleId);
}

void nm_iam_user_remove_role(struct nm_iam_user* user, const char* roleId)
{
    nn_string_set_erase(&user->roles, roleId);
}
