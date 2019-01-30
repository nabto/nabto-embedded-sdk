#ifndef NP_ACCESS_CONTROL_H
#define NP_ACCESS_CONTROL_H

#include <nabto_types.h>

enum np_access_control_permission {
    NP_CONNECT_PERMISSION,
    NP_STREAMING_PERMISSION
};

struct np_platform;

void np_access_control_init(struct np_platform* pl);

struct np_access_control_module {
    bool (*can_access)(uint8_t* fingerprint, enum np_access_control_permission feature);
};

#endif
