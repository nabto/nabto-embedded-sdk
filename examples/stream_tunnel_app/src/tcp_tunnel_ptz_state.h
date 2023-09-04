#ifndef __TCP_TUNNEL_PTZ_STATE_H__
#define __TCP_TUNNEL_PTZ_STATE_H__

#include <stdbool.h>

struct ptz_state {
    double pan;
    double tilt;
    double zoom;
    bool moving;
};

void ptz_state_init(struct ptz_state* state);

#endif
