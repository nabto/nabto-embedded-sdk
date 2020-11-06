#include "nm_iam_state.h"
#include "nm_iam_user.h"

#include <string.h>

struct nm_iam_state* nm_iam_state_new()
{
    struct nm_iam_state* s = calloc(1, sizeof(struct nm_iam_state));
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
    free(state->globalPairingPassword);
    free(state->globalSct);
    free(state);
}

bool nm_iam_state_set_pairing_password(struct nm_iam_state* state, const char* password)
{
    if (password == NULL) {
        free(state->globalPairingPassword);
        state->globalPairingPassword = NULL;
        return true;
    }
    char* tmp = strdup(password);
    if (tmp != NULL) {
        free(state->globalPairingPassword);
        state->globalPairingPassword = tmp;
    }
    return (tmp != 0);
}


bool nm_iam_state_set_pairing_server_connect_token(struct nm_iam_state* state, const char* serverConnectToken)
{
    if (serverConnectToken == NULL) {
        free(state->globalSct);
        state->globalSct = NULL;
        return true;
    }
    char* tmp = strdup(serverConnectToken);
    if (tmp != NULL) {
        free(state->globalSct);
        state->globalSct = tmp;
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
        free(state->initialPairingUsername);
        state->initialPairingUsername = NULL;
        return true;
    }
    char* tmp = strdup(username);
    if (tmp != NULL) {
        free(state->initialPairingUsername);
        state->initialPairingUsername = tmp;
    }
    return (tmp != 0);
}
bool nm_iam_state_set_open_pairing_role(struct nm_iam_state* state, const char* role)
{
    if (role == NULL) {
        free(state->openPairingRole);
        state->openPairingRole = NULL;
        return true;
    }
    char* tmp = strdup(role);
    if (tmp != NULL) {
        free(state->openPairingRole);
        state->openPairingRole = tmp;
    }
    return (tmp != 0);
}

bool nm_iam_state_add_user(struct nm_iam_state* state, struct nm_iam_user* user)
{
    nn_llist_append(&state->users, &user->listNode, user);
    return true;
}
