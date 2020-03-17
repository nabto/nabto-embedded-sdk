#include "tcp_tunnel_state.h"

#include <modules/iam/nm_iam_to_json.h>
#include <modules/iam/nm_iam_from_json.h>

#include <apps/common/json_config.h>

#include <cjson/cJSON.h>

#include <stdio.h>
#include <stdlib.h>

#define NEWLINE "\n"

static bool write_state_to_file(const char* stateFile, struct tcp_tunnel_state* state);
static bool create_default_tcp_tunnel_state(const char* stateFile);

void tcp_tunnel_state_init(struct tcp_tunnel_state* state)
{
    memset(state, 0, sizeof(struct tcp_tunnel_state));
    np_vector_init(&state->users, NULL);
}

void tcp_tunnel_state_deinit(struct tcp_tunnel_state* state)
{
    np_vector_deinit(&state->users);
    free(state->pairingPassword);
    free(state->pairingServerConnectToken);
}


bool load_tcp_tunnel_state(struct tcp_tunnel_state* state, const char* stateFile, const char** errorText)
{
    if (!json_config_exists(stateFile)) {
        printf("State file does not exists (%s), creating a new default file" NEWLINE, stateFile);
        create_default_tcp_tunnel_state(stateFile);
    }

    cJSON* json;

    json_config_load(stateFile, &json);

    cJSON* pairingPassword = cJSON_GetObjectItem(json, "PairingPassword");
    cJSON* pairingServerConnectToken = cJSON_GetObjectItem(json, "PairingServerConnectToken");
    cJSON* users = cJSON_GetObjectItem(json, "Users");

    if (cJSON_IsString(pairingPassword)) {
        state->pairingPassword = strdup(pairingPassword->valuestring);
    }

    if (cJSON_IsString(pairingServerConnectToken)) {
        state->pairingServerConnectToken = strdup(pairingServerConnectToken->valuestring);
    }

    if (users != NULL && cJSON_IsArray(users)) {

        size_t usersSize = cJSON_GetArraySize(users);
        for (size_t i = 0; i < usersSize; i++) {
            cJSON* item = cJSON_GetArrayItem(users, i);
            struct nm_iam_user* user = nm_iam_user_from_json(item);
            if (user != NULL) {
                np_vector_push_back(&state->users, user);
            }
        }
    }
    return true;
}


bool create_default_tcp_tunnel_state(const char* stateFile)
{
    struct tcp_tunnel_state state;
    tcp_tunnel_state_init(&state);
    state.pairingPassword = strdup("TODOPairingPassword");
    state.pairingServerConnectToken = strdup("TODOPairingServerConnectToken");

    bool status = write_state_to_file(stateFile, &state);


    tcp_tunnel_state_deinit(&state);

    return status;
}

bool write_state_to_file(const char* stateFile, struct tcp_tunnel_state* state)
{
    cJSON* json = cJSON_CreateObject();
    cJSON_AddItemToObject(json, "PairingPassword", cJSON_CreateString(state->pairingPassword));
    cJSON_AddItemToObject(json, "PairingServerConnectToken", cJSON_CreateString(state->pairingServerConnectToken));

    cJSON* usersArray = cJSON_CreateArray();

    struct np_vector_iterator it;
    for (np_vector_front(&state->users, &it);
         !np_vector_end(&it);
         np_vector_next(&it))
    {
        struct nm_iam_user* user = np_vector_get_element(&it);
        cJSON* encodedUser = nm_iam_user_to_json(user);
        cJSON_AddItemToArray(usersArray, encodedUser);
    }
    cJSON_AddItemToObject(json, "Users", usersArray);
    json_config_save(stateFile, json);

    cJSON_Delete(json);
    return true;
}
