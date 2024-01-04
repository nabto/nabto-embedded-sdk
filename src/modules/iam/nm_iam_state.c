#include "nm_iam_state.h"
#include "nm_iam_user.h"

#include "nm_iam_allocator.h"
#include <nn/string.h>
#include <string.h>

struct nm_iam_state* nm_iam_state_new()
{
    struct nm_iam_state* s = nm_iam_calloc(1, sizeof(struct nm_iam_state));
    if (s == NULL) {
        return NULL;
    }
    nn_llist_init(&s->users);
    return s;

}

void nm_iam_state_free(struct nm_iam_state* state)
{
    if (state == NULL) {
        return;
    }
    struct nn_llist_iterator it = nn_llist_begin(&state->users);
    while(!nn_llist_is_end(&it))
    {
        struct nm_iam_user* u = nn_llist_get_item(&it);
        nn_llist_erase_node(&u->listNode);
        nm_iam_user_free(u);
        it = nn_llist_begin(&state->users);
    }

    nn_llist_deinit(&state->users);
    nm_iam_free(state->passwordOpenPassword);
    nm_iam_free(state->passwordOpenSct);
    nm_iam_free(state->openPairingRole);
    nm_iam_free(state->initialPairingUsername);
    nm_iam_free(state->friendlyName);
    nm_iam_free(state);
}

bool nm_iam_state_set_password_open_password(struct nm_iam_state* state, const char* password)
{
    if (password == NULL) {
        nm_iam_free(state->passwordOpenPassword);
        state->passwordOpenPassword = NULL;
        return true;
    }
    char* tmp = nn_strdup(password, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(state->passwordOpenPassword);
        state->passwordOpenPassword = tmp;
    }
    return (tmp != 0);
}


bool nm_iam_state_set_password_open_sct(struct nm_iam_state* state, const char* sct)
{
    if (sct == NULL) {
        nm_iam_free(state->passwordOpenSct);
        state->passwordOpenSct = NULL;
        return true;
    }
    char* tmp = nn_strdup(sct, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(state->passwordOpenSct);
        state->passwordOpenSct = tmp;
    }
    return (tmp != 0);
}

void nm_iam_state_set_password_open_pairing(struct nm_iam_state* state, bool b)
{
    state->passwordOpenPairing = b;
}

void nm_iam_state_set_local_open_pairing(struct nm_iam_state* state, bool b)
{
    state->localOpenPairing = b;
}

void nm_iam_state_set_password_invite_pairing(struct nm_iam_state* state, bool b)
{
    state->passwordInvitePairing = b;
}

void nm_iam_state_set_local_initial_pairing(struct nm_iam_state* state, bool b)
{
    state->localInitialPairing = b;
}

bool nm_iam_state_set_initial_pairing_username(struct nm_iam_state* state, const char* username)
{
    if (username == NULL) {
        nm_iam_free(state->initialPairingUsername);
        state->initialPairingUsername = NULL;
        return true;
    }
    char* tmp = nn_strdup(username, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(state->initialPairingUsername);
        state->initialPairingUsername = tmp;
    }
    return (tmp != 0);
}

bool nm_iam_state_set_friendly_name(struct nm_iam_state* state, const char* friendlyName)
{
    if (friendlyName == NULL) {
        nm_iam_free(state->friendlyName);
        state->friendlyName = NULL;
        return true;
    }
    char* tmp = nn_strdup(friendlyName, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(state->friendlyName);
        state->friendlyName = tmp;
    }
    return (tmp != 0);
}

bool nm_iam_state_set_open_pairing_role(struct nm_iam_state* state, const char* role)
{
    if (role == NULL) {
        nm_iam_free(state->openPairingRole);
        state->openPairingRole = NULL;
        return true;
    }
    char* tmp = nn_strdup(role, nm_iam_allocator_get());
    if (tmp != NULL) {
        nm_iam_free(state->openPairingRole);
        state->openPairingRole = tmp;
    }
    return (tmp != 0);
}

bool nm_iam_state_add_user(struct nm_iam_state* state, struct nm_iam_user* user)
{
    nn_llist_append(&state->users, &user->listNode, user);
    return true;
}

struct nm_iam_user* nm_iam_state_user_new(const char* username)
{
    return nm_iam_user_new(username);
}

void nm_iam_state_user_free(struct nm_iam_user* user)
{
    nm_iam_user_free(user);
}

bool nm_iam_state_user_set_fingerprint(struct nm_iam_user* user, const char* fingerprint)
{
    return nm_iam_user_set_fingerprint(user, fingerprint);
}

bool nm_iam_state_user_set_sct(struct nm_iam_user* user, const char* sct)
{
    return nm_iam_user_set_sct(user, sct);
}

bool nm_iam_state_user_set_display_name(struct nm_iam_user* user, const char* displayName)
{
    return nm_iam_user_set_display_name(user, displayName);
}

bool nm_iam_state_user_set_role(struct nm_iam_user* user, const char* roleId)
{
    return nm_iam_user_set_role(user, roleId);
}

bool nm_iam_state_user_set_password(struct nm_iam_user* user, const char* password)
{
    return nm_iam_user_set_password(user, password);
}

bool nm_iam_state_user_set_fcm_token(struct nm_iam_user* user, const char* token)
{
    return nm_iam_user_set_fcm_token(user, token);
}

bool nm_iam_state_user_set_fcm_project_id(struct nm_iam_user* user, const char* id)
{
    return nm_iam_user_set_fcm_project_id(user, id);
}

bool nm_iam_state_user_set_notification_categories(struct nm_iam_user* user, struct nn_string_set* categories)
{
    return nm_iam_user_set_notification_categories(user, categories);
}

bool nm_iam_state_user_set_oauth_subject(struct nm_iam_user* user, const char* subject)
{
    return nm_iam_user_set_oauth_subject(user, subject);
}

struct nm_iam_state* nm_iam_state_copy(struct nm_iam_state* state)
{
    struct nm_iam_state* copy = nm_iam_state_new();
    if (copy == NULL) {
        return NULL;
    }

    bool failed = false;

    if (state->passwordOpenPassword != NULL) {
        copy->passwordOpenPassword = nn_strdup(state->passwordOpenPassword, nm_iam_allocator_get());
        if (copy->passwordOpenPassword == NULL) {
            failed = true;
        }
    }

    if (state->passwordOpenSct != NULL) {
        copy->passwordOpenSct = nn_strdup(state->passwordOpenSct, nm_iam_allocator_get());
        if (copy->passwordOpenSct == NULL) {
            failed = true;
        }
    }

    copy->passwordOpenPairing = state->passwordOpenPairing;
    copy->localOpenPairing = state->localOpenPairing;
    copy->passwordInvitePairing = state->passwordInvitePairing;
    copy->localInitialPairing = state->localInitialPairing;

    if(state->openPairingRole != NULL) {
        copy->openPairingRole = nn_strdup(state->openPairingRole, nm_iam_allocator_get());
        if (copy->openPairingRole == NULL) {
            failed = true;
        }
    }

    if(state->initialPairingUsername != NULL) {
        copy->initialPairingUsername = nn_strdup(state->initialPairingUsername, nm_iam_allocator_get());
        if (copy->initialPairingUsername == NULL) {
            failed = true;
        }
    }

    if(state->friendlyName != NULL) {
        copy->friendlyName = nn_strdup(state->friendlyName, nm_iam_allocator_get());
        if (copy->friendlyName == NULL) {
            failed = true;
        }
    }

    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &state->users) {
        struct nm_iam_user* userCopy = nm_iam_user_copy(user);
        if (userCopy == NULL) {
            failed = true;
        } else {
            nn_llist_append(&copy->users, &userCopy->listNode, userCopy);
        }
    }
    if (failed) {
        nm_iam_state_free(copy);
        return NULL;
    } else {
        return copy;
    }
}


struct nm_iam_user* nm_iam_state_find_user_by_username(struct nm_iam_state* state, const char* username)
{
    if (username == NULL) {
        return NULL;
    }
    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &state->users) {
        if (user->username != NULL && strcmp(user->username, username) == 0) {
            return user;
        }
    }
    return NULL;
}

struct nm_iam_user* nm_iam_state_find_user_by_oauth_subject(struct nm_iam_state* state, const char* subject)
{
    if (subject == NULL) {
        return NULL;
    }
    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &state->users) {
        if (user->oauthSubject != NULL && strcmp(user->oauthSubject, subject) == 0) {
            return user;
        }
    }
    return NULL;
}
