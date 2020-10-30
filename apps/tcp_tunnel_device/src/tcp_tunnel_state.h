#ifndef _TCP_TUNNEL_STATE_H_
#define _TCP_TUNNEL_STATE_H_

#include <modules/iam/nm_iam_state.h>

struct nn_log;

bool load_tcp_tunnel_state(struct nm_iam_state* state, const char* stateFile, struct nn_log* logger);

bool save_tcp_tunnel_state(const char* stateFile, struct nm_iam_state* state);

bool reset_tcp_tunnel_state(const char* stateFile);

#endif
