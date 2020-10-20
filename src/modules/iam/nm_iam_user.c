#include "nm_iam_user.h"

#include <stdlib.h>
#include <string.h>

void nm_iam_user_init(struct nm_iam_user* user)
{
    memset(user, 0, sizeof(struct nm_iam_user));
    nn_string_map_init(&user->attributes);
}

void nm_iam_user_deinit(struct nm_iam_user* user)
{
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
    user->id = id;

    return user;
}

void nm_iam_user_free(struct nm_iam_user* user)
{
    free(user->id);
    free(user->name);
    free(user->fingerprint);
    free(user->serverConnectToken);
    free(user->role);
    nn_string_map_deinit(&user->attributes);
    free(user);
}

bool nm_iam_user_set_fingerprint(struct nm_iam_user* user, const char* fingerprint)
{
    if (user->fingerprint != NULL) {
        free(user->fingerprint);
    }
    user->fingerprint = strdup(fingerprint);
    return (user->fingerprint != NULL);
}

bool nm_iam_user_set_server_connect_token(struct nm_iam_user* user, const char* serverConnectToken)
{
    if (user->serverConnectToken != NULL) {
        free(user->serverConnectToken);
    }
    user->serverConnectToken = strdup(serverConnectToken);
    return (user->serverConnectToken != NULL);
}

bool nm_iam_user_set_name(struct nm_iam_user* user, const char* name)
{
    if (name == NULL) {
        return false; // A user must have a name
    }
    char* tmp = strdup(name);
    if (tmp == NULL) {
        return false;
    }
    free(user->name);
    user->name = tmp;
    return true;
}

bool nm_iam_user_set_role(struct nm_iam_user* user, const char* roleId)
{
    if (roleId == NULL) {
        return false; // A user must have a role
    }
    char* tmp = strdup(roleId);
    if (tmp == NULL) {
        return false;
    }
    free(user->role);
    user->role = tmp;
    return true;
}
