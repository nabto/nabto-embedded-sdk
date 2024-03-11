#include "nm_iam_user.h"

#include "nm_iam_allocator.h"

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
    char* username = nn_strdup(usernameIn, nm_iam_allocator_get());
    struct nm_iam_user* user = nm_iam_calloc(1, sizeof(struct nm_iam_user));
    // TODO: new should not validate, ensure validate is called everywhere new is used, and remove from here
    if (username == NULL || user == NULL || !nm_iam_user_validate_username(username)) {
        nm_iam_free(username);
        nm_iam_free(user);
        return NULL;
    }

    nn_llist_node_init(&user->listNode);
    user->username = username;
    nn_string_set_init(&user->notificationCategories, nm_iam_allocator_get());
    nn_llist_init(&user->fingerprints);
    return user;
}

void nm_iam_user_free(struct nm_iam_user* user)
{
    if (user != NULL) {
        nm_iam_free(user->username);
        nm_iam_free(user->displayName);

        struct nn_llist_iterator it = nn_llist_begin(&user->fingerprints);
        while(!nn_llist_is_end(&it))
        {
            struct nm_iam_user_fingerprint* fp = nn_llist_get_item(&it);
            nn_llist_erase_node(&fp->listNode);
            nm_iam_free(fp->name);
            nm_iam_free(fp->fingerprint);
            nm_iam_free(fp);
            it = nn_llist_begin(&user->fingerprints);
        }

        nn_llist_deinit(&user->fingerprints);
        nm_iam_free(user->sct);
        nm_iam_free(user->role);
        nm_iam_free(user->password);
        nm_iam_free(user->fcmToken);
        nm_iam_free(user->fcmProjectId);
        nn_string_set_deinit(&user->notificationCategories);
        nm_iam_free(user->oauthSubject);
        nm_iam_free(user);
    }
}

bool nm_iam_user_set_fingerprint(struct nm_iam_user* user, const char* fingerprint)
{
    if (fingerprint == NULL && !nn_llist_empty(&user->fingerprints)) {
        struct nn_llist_iterator it = nn_llist_begin(&user->fingerprints);
        struct nm_iam_user_fingerprint* fp = nn_llist_get_item(&it);
        nn_llist_erase_node(&fp->listNode);
        nm_iam_free(fp->fingerprint);
        nm_iam_free(fp->name);
        return true;
    }
    if (nn_llist_empty(&user->fingerprints)) {
        return nm_iam_user_add_fingerprint(user, fingerprint, NULL);
    } else {
        struct nn_llist_iterator it = nn_llist_begin(&user->fingerprints);
        struct nm_iam_user_fingerprint* fp = nn_llist_get_item(&it);
        char* tmp = nn_strdup(fingerprint, nm_iam_allocator_get());
        if (tmp != NULL) {
            nm_iam_free(fp->fingerprint);
            fp->fingerprint = tmp;
        }
        return (tmp != NULL);
    }
}

bool nm_iam_user_add_fingerprint(struct nm_iam_user* user, const char* fingerprint, const char* fpName)
{
    if (fingerprint == NULL) {
        return false;
    }
    struct nm_iam_user_fingerprint* fp = nm_iam_calloc(1, sizeof(struct nm_iam_user_fingerprint));
    if (fp == NULL) {
        return false;
    }

    if (fpName != NULL) {
        fp->name = nn_strdup(fpName, nm_iam_allocator_get());
    }

    fp->fingerprint = nn_strdup(fingerprint, nm_iam_allocator_get());

    if (fp->fingerprint == NULL || (fpName != NULL && fp->name == NULL)) {
        nm_iam_free(fp->fingerprint);
        nm_iam_free(fp->name);
        nm_iam_free(fp);
        return false;
    }
    nn_llist_append(&user->fingerprints, &fp->listNode, fp);
    return true;
}

bool nm_iam_user_remove_fingerprint(struct nm_iam_user* user, const char* fingerprint)
{
    if (user == NULL || fingerprint == NULL) {
        return false;
    }
    struct nn_llist_iterator it = nn_llist_begin(&user->fingerprints);
    while(!nn_llist_is_end(&it))
    {
        struct nm_iam_user_fingerprint* fp = nn_llist_get_item(&it);
        if (strcmp(fp->fingerprint, fingerprint) == 0) {
            nn_llist_erase_node(&fp->listNode);
            nm_iam_free(fp->fingerprint);
            nm_iam_free(fp->name);
            return true;
        }
        nn_llist_next(&it);
    }
    return false;
}


bool nm_iam_user_set_password(struct nm_iam_user* user, const char* password)
{
    if (password == NULL) {
        nm_iam_free(user->password);
        user->password = NULL;
        return true;
    }
    char* tmp = nn_strdup(password, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(user->password);
        user->password = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_fcm_token(struct nm_iam_user* user, const char* fcmToken)
{
    if (fcmToken == NULL) {
        nm_iam_free(user->fcmToken);
        user->fcmToken = NULL;
        return true;
    }
    char* tmp = nn_strdup(fcmToken, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(user->fcmToken);
        user->fcmToken = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_fcm_project_id(struct nm_iam_user* user, const char* projectId)
{
    if (projectId == NULL) {
        nm_iam_free(user->fcmProjectId);
        user->fcmProjectId = NULL;
        return true;
    }
    char* tmp = nn_strdup(projectId, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(user->fcmProjectId);
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

bool nm_iam_user_set_oauth_subject(struct nm_iam_user* user, const char* subject)
{
    if (subject == NULL) {
        nm_iam_free(user->oauthSubject);
        user->oauthSubject = NULL;
        return true;
    }
    char* tmp = nn_strdup(subject, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(user->oauthSubject);
        user->oauthSubject = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_sct(struct nm_iam_user* user, const char* sct)
{
    if (sct == NULL) {
        nm_iam_free(user->sct);
        user->sct = NULL;
        return true;
    }
    char* tmp = nn_strdup(sct, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(user->sct);
        user->sct = tmp;
    }
    return (tmp != NULL);
}

bool nm_iam_user_set_username(struct nm_iam_user* user, const char* username)
{
    if (username == NULL || !nm_iam_user_validate_username(username)) {
        return false; // A user must have a valid username
    }
    char* tmp = nn_strdup(username, nm_iam_allocator_get());
    if (tmp == NULL) {
        return false;
    }
    nm_iam_free(user->username);
    user->username = tmp;
    return true;
}

bool nm_iam_user_set_display_name(struct nm_iam_user* user, const char* displayName)
{
    if (displayName == NULL) {
        nm_iam_free(user->displayName);
        user->displayName = NULL;
        return true;
    }
    char* tmp = nn_strdup(displayName, nm_iam_allocator_get());
    if (tmp == NULL) {
        return false;
    }
    nm_iam_free(user->displayName);
    user->displayName = tmp;
    return true;
}

bool nm_iam_user_set_role(struct nm_iam_user* user, const char* roleId)
{
    if (roleId == NULL) {
        return false; // A user must have a role
    }
    char* tmp = nn_strdup(roleId, nm_iam_allocator_get());
    if (tmp == NULL) {
        return false;
    }
    nm_iam_free(user->role);
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
        copy->displayName = nn_strdup(user->displayName, nm_iam_allocator_get());
        if (copy->displayName == NULL) {
            failed = true;
        }
    }

    struct nm_iam_user_fingerprint* fp = NULL;
    NN_LLIST_FOREACH(fp, &user->fingerprints) {
        if (!nm_iam_user_add_fingerprint(copy, fp->fingerprint, fp->name)) {
            failed = true;
        }
    }

    if (user->password != NULL) {
        copy->password = nn_strdup(user->password, nm_iam_allocator_get());
        if(copy->password == NULL) {
            failed = true;
        }
    }

    if(user->role != NULL) {
        copy->role = nn_strdup(user->role, nm_iam_allocator_get());
        if(copy->role == NULL) {
            failed = true;
        }
    }

    if(user->sct != NULL) {
        copy->sct = nn_strdup(user->sct, nm_iam_allocator_get());
        if(copy->sct == NULL) {
            failed = true;
        }
    }

    if(user->fcmToken != NULL) {
        copy->fcmToken = nn_strdup(user->fcmToken, nm_iam_allocator_get());
        if(copy->fcmToken == NULL) {
            failed = true;
        }
    }

    if(user->fcmProjectId != NULL) {
        copy->fcmProjectId = nn_strdup(user->fcmProjectId, nm_iam_allocator_get());
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

    if(user->oauthSubject != NULL) {
        copy->oauthSubject = nn_strdup(user->oauthSubject, nm_iam_allocator_get());
        if(copy->oauthSubject == NULL) {
            failed = true;
        }
    }

    if (failed) {
        nm_iam_user_free(copy);
        return NULL;
    }
    return copy;
}
