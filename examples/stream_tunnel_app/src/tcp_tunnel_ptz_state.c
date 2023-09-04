#include "tcp_tunnel_ptz_state.h"

#include <stdbool.h>

void ptz_state_init(struct ptz_state* state) {
    state->pan = 87;
    state->tilt = 0;
    state->zoom = 0;
    state->moving = false;
}
