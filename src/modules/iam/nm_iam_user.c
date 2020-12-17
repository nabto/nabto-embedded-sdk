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
    free(user->displayName);
    free(user->fingerprint);
    free(user->sct);
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

bool nm_iam_user_set_fcm_token(struct nm_iam_user* user, const char* fcmToken)
{
    if (fcmToken == NULL) {
        free(user->fcmToken);
        user->fcmToken = NULL;
        return true;
    }
    char* tmp = strdup(fcmToken);
    if (tmp != NULL) {
        free(user->fcmToken);
        user->fcmToken = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_notification_categories(struct nm_iam_user* user, struct nn_string_set* categories)
{
    nn_string_set_clear(&user->notificationCategories);
    const char* s;
    NN_STRING_SET_FOREACH(s, categories) {
        nn_string_set_insert(&user->notificationCategories, s);
    }
    return true;
}

bool nm_iam_user_set_sct(struct nm_iam_user* user, const char* sct)
{
    if (sct == NULL) {
        free(user->sct);
        user->sct = NULL;
        return true;
    }
    char* tmp = strdup(sct);
    if (tmp != NULL) {
        free(user->sct);
        user->sct = tmp;
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

struct nm_iam_user* nm_iam_user_copy(struct nm_iam_user* user)
{
    struct nm_iam_user* copy = nm_iam_user_new(user->username);
    if(copy == NULL) {
        return NULL;
    }
    bool failed = false;
    if (user->displayName != NULL) {
        copy->displayName = strdup(user->displayName);
        if (copy->displayName == NULL) {
            failed = true;
        }
    }

    if (user->fingerprint != NULL) {
        copy->fingerprint = strdup(user->fingerprint);
        if(copy->fingerprint == NULL) {
            failed = true;
        }
    }

    if (user->password != NULL) {
        copy->password = strdup(user->password);
        if(copy->password == NULL) {
            failed = true;
        }
    }

    if(user->role != NULL) {
        copy->role = strdup(user->role);
        if(copy->role == NULL) {
            failed = true;
        }
    }

    if(user->sct != NULL) {
        copy->sct = strdup(user->sct);
        if(copy->sct == NULL) {
            failed = true;
        }
    }

    if (failed) {
        nm_iam_user_free(copy);
        return NULL;
    }
    return copy;
}
