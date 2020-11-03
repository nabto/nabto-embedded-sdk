#include "nm_iam_user.h"

#include <stdlib.h>
#include <string.h>

bool nm_iam_user_validate_username(const char* username)
{
    for (int i = 0; i < strlen(username); i++) {
        if ( (username[i] <= 'a' && username[i] >= 'z') &&
             (username[i] <= '0' && username[i] >= '9') &&
             (username[i] != '_') &&
             (username[i] != '.') &&
             (username[i] != '-') )
        {
            return false;
        }
    }
    return true;
}


struct nm_iam_user* nm_iam_user_new(const char* usernameIn)
{
    char* username = strdup(usernameIn);
    struct nm_iam_user* user = calloc(1, sizeof(struct nm_iam_user));
    if (username == NULL || user == NULL || !nm_iam_user_validate_username(username)) {
        free(username);
        free(user);
        return NULL;
    }

    nn_llist_node_init(&user->listNode);
    user->username = username;

    return user;
}

void nm_iam_user_free(struct nm_iam_user* user)
{
    free(user->username);
    free(user->fingerprint);
    free(user->serverConnectToken);
    free(user->role);
    free(user->password);
    free(user);
}

bool nm_iam_user_set_fingerprint(struct nm_iam_user* user, const char* fingerprint)
{
    if (fingerprint == NULL) {
        free(user->fingerprint);
        user->fingerprint = NULL;
        return true;
    }
    char* tmp = strdup(fingerprint);
    if (tmp != NULL) {
        free(user->fingerprint);
        user->fingerprint = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_password(struct nm_iam_user* user, const char* password)
{
    if (password == NULL) {
        free(user->password);
        user->password = NULL;
        return true;
    }
    char* tmp = strdup(password);
    if (tmp != NULL) {
        free(user->password);
        user->password = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_server_connect_token(struct nm_iam_user* user, const char* sct)
{
    if (sct == NULL) {
        free(user->serverConnectToken);
        user->serverConnectToken = NULL;
        return true;
    }
    char* tmp = strdup(sct);
    if (tmp != NULL) {
        free(user->serverConnectToken);
        user->serverConnectToken = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_username(struct nm_iam_user* user, const char* username)
{
    if (username == NULL || !nm_iam_user_validate_username(username)) {
        return false; // A user must have a valid username
    }
    char* tmp = strdup(username);
    if (tmp == NULL) {
        return false;
    }
    free(user->username);
    user->username = tmp;
    return true;
}

bool nm_iam_user_set_display_name(struct nm_iam_user* user, const char* displayName)
{
    if (displayName == NULL) {
        free(user->displayName);
        user->displayName = NULL;
        return true;
    }
    char* tmp = strdup(displayName);
    if (tmp == NULL) {
        return false;
    }
    free(user->displayName);
    user->displayName = tmp;
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
