#include "tcp_tunnel_state.h"

#include <modules/iam/nm_iam_serializer.h>
#include <modules/iam/nm_iam_user.h>

#include <apps/common/string_file.h>
#include <apps/common/random_string.h>

#include <nn/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

static const char* LOGM = "tcp_tunnel_state";


static bool write_state_to_file(const char* stateFile, struct nm_iam_state* state);
static bool create_default_tcp_tunnel_state(const char* stateFile);

bool load_tcp_tunnel_state(struct nm_iam_state* state, const char* stateFile, struct nn_log* logger)
{
    if (!string_file_exists(stateFile)) {
        NN_LOG_INFO(logger, LOGM, "State file does not exists (%s), creating a new default file", stateFile);
        create_default_tcp_tunnel_state(stateFile);
    }

    char* str;
    if (!string_file_load(stateFile, &str)) {
        return false;
    }

    if (!nm_iam_serializer_state_load_json(state, str, logger)) {
        NN_LOG_ERROR(logger, LOGM, "Loading state failed, try to delete %s to make a new default file", stateFile);
        free(str);
        return false;
    }
    free(str);
    return true;
}

bool create_default_tcp_tunnel_state(const char* stateFile)
{
    struct nm_iam_state* state = nm_iam_state_new();
    
    struct nm_iam_user* admin = nm_iam_user_new("admin");

    nm_iam_user_set_role(admin, "Administrator");
    nm_iam_user_set_password(admin, random_password(12));
    nm_iam_user_set_server_connect_token(admin, random_password(12));

    nm_iam_state_add_user(state, admin);

    return write_state_to_file(stateFile, state);
}

bool write_state_to_file(const char* stateFile, struct nm_iam_state* state)
{
    char* str;
    if (!nm_iam_serializer_state_dump_json(state, &str)) {
        //nm_iam_state_free(state);
        return false;
    }

    if(!string_file_save(stateFile, str)) {
        nm_iam_serializer_string_free(str);
        //nm_iam_state_free(state);
        return false;
    }

    nm_iam_serializer_string_free(str);
    //nm_iam_state_free(state);
    return true;
}

bool reset_tcp_tunnel_state(const char* stateFile)
{
    return create_default_tcp_tunnel_state(stateFile);
}

bool save_tcp_tunnel_state(const char* stateFile, struct nm_iam_state* state)
{
    return write_state_to_file(stateFile, state);
}
