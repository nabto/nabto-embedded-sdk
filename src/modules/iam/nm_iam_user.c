#include "nm_iam_user.h"

#include <platform/np_heap.h>

#include <nn/string.h>
#include <string.h>

bool nm_iam_user_validate_username(const char* username)
{
    if (strcmp(username, "") == 0) {
        // empty username is not allowed as it is used for open password pairing
        return false;
    }

    for (size_t i = 0; i < strlen(username); i++) {
        if ( (username[i] < 'a' || username[i] > 'z') &&
             (username[i] < '0' || username[i] > '9') &&
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
    char* username = nn_strdup(usernameIn, np_get_default_allocator());
    struct nm_iam_user* user = np_calloc(1, sizeof(struct nm_iam_user));
    // TODO: new should not validate, ensure validate is called everywhere new is used, and remove from here
    if (username == NULL || user == NULL || !nm_iam_user_validate_username(username)) {
        np_free(username);
        np_free(user);
        return NULL;
    }

    nn_llist_node_init(&user->listNode);
    user->username = username;
    nn_string_set_init(&user->notificationCategories, np_get_default_allocator());
    return user;
}

void nm_iam_user_free(struct nm_iam_user* user)
{
    if (user != NULL) {
        np_free(user->username);
        np_free(user->displayName);
        np_free(user->fingerprint);
        np_free(user->sct);
        np_free(user->role);
        np_free(user->password);
        np_free(user->fcmToken);
        np_free(user->fcmProjectId);
        nn_string_set_deinit(&user->notificationCategories);
        np_free(user);
    }
}

bool nm_iam_user_set_fingerprint(struct nm_iam_user* user, const char* fingerprint)
{
    if (fingerprint == NULL) {
        np_free(user->fingerprint);
        user->fingerprint = NULL;
        return true;
    }
    char* tmp = nn_strdup(fingerprint, np_get_default_allocator());
    if (tmp != NULL) {
        np_free(user->fingerprint);
        user->fingerprint = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_password(struct nm_iam_user* user, const char* password)
{
    if (password == NULL) {
        np_free(user->password);
        user->password = NULL;
        return true;
    }
    char* tmp = nn_strdup(password, np_get_default_allocator());
    if (tmp != NULL) {
        np_free(user->password);
        user->password = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_fcm_token(struct nm_iam_user* user, const char* fcmToken)
{
    if (fcmToken == NULL) {
        np_free(user->fcmToken);
        user->fcmToken = NULL;
        return true;
    }
    char* tmp = nn_strdup(fcmToken, np_get_default_allocator());
    if (tmp != NULL) {
        np_free(user->fcmToken);
        user->fcmToken = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_fcm_project_id(struct nm_iam_user* user, const char* projectId)
{
    if (projectId == NULL) {
        np_free(user->fcmProjectId);
        user->fcmProjectId = NULL;
        return true;
    }
    char* tmp = nn_strdup(projectId, np_get_default_allocator());
    if (tmp != NULL) {
        np_free(user->fcmProjectId);
        user->fcmProjectId = tmp;
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
        np_free(user->sct);
        user->sct = NULL;
        return true;
    }
    char* tmp = nn_strdup(sct, np_get_default_allocator());
    if (tmp != NULL) {
        np_free(user->sct);
        user->sct = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_username(struct nm_iam_user* user, const char* username)
{
    if (username == NULL || !nm_iam_user_validate_username(username)) {
        return false; // A user must have a valid username
    }
    char* tmp = nn_strdup(username, np_get_default_allocator());
    if (tmp == NULL) {
        return false;
    }
    np_free(user->username);
    user->username = tmp;
    return true;
}

bool nm_iam_user_set_display_name(struct nm_iam_user* user, const char* displayName)
{
    if (displayName == NULL) {
        np_free(user->displayName);
        user->displayName = NULL;
        return true;
    }
    char* tmp = nn_strdup(displayName, np_get_default_allocator());
    if (tmp == NULL) {
        return false;
    }
    np_free(user->displayName);
    user->displayName = tmp;
    return true;
}

bool nm_iam_user_set_role(struct nm_iam_user* user, const char* roleId)
{
    if (roleId == NULL) {
        return false; // A user must have a role
    }
    char* tmp = nn_strdup(roleId, np_get_default_allocator());
    if (tmp == NULL) {
        return false;
    }
    np_free(user->role);
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
        copy->displayName = nn_strdup(user->displayName, np_get_default_allocator());
        if (copy->displayName == NULL) {
            failed = true;
        }
    }

    if (user->fingerprint != NULL) {
        copy->fingerprint = nn_strdup(user->fingerprint, np_get_default_allocator());
        if(copy->fingerprint == NULL) {
            failed = true;
        }
    }

    if (user->password != NULL) {
        copy->password = nn_strdup(user->password, np_get_default_allocator());
        if(copy->password == NULL) {
            failed = true;
        }
    }

    if(user->role != NULL) {
        copy->role = nn_strdup(user->role, np_get_default_allocator());
        if(copy->role == NULL) {
            failed = true;
        }
    }

    if(user->sct != NULL) {
        copy->sct = nn_strdup(user->sct, np_get_default_allocator());
        if(copy->sct == NULL) {
            failed = true;
        }
    }

    if(user->fcmToken != NULL) {
        copy->fcmToken = nn_strdup(user->fcmToken, np_get_default_allocator());
        if(copy->fcmToken == NULL) {
            failed = true;
        }
    }

    if(user->fcmProjectId != NULL) {
        copy->fcmProjectId = nn_strdup(user->fcmProjectId, np_get_default_allocator());
        if(copy->fcmProjectId == NULL) {
            failed = true;
        }
    }

    const char* p;
    NN_STRING_SET_FOREACH(p, &user->notificationCategories) {
        if (!nn_string_set_insert(&copy->notificationCategories, p)) {
            failed = true;
        }
    }

    if (failed) {
        nm_iam_user_free(copy);
        return NULL;
    }
    return copy;
}
