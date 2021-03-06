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

bool load_tcp_tunnel_state(struct nm_iam_state* state, const char* stateFile, struct nn_log* logger)
{
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

bool save_tcp_tunnel_state(const char* stateFile, struct nm_iam_state* state)
{
    return write_state_to_file(stateFile, state);
}
