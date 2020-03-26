#ifndef _TCP_TUNNEL_STATE_H_
#define _TCP_TUNNEL_STATE_H_

#include <platform/np_vector.h>

struct tcp_tunnel_state {
    struct np_vector users;
    char* pairingPassword;
    char* pairingServerConnectToken;
};

struct nn_log;

void tcp_tunnel_state_init(struct tcp_tunnel_state* state);
void tcp_tunnel_state_deinit(struct tcp_tunnel_state* state);

bool load_tcp_tunnel_state(struct tcp_tunnel_state* state, const char* stateFile, struct nn_log* logger);


bool save_tcp_tunnel_state(const char* stateFile, struct tcp_tunnel_state* state);

#endif
