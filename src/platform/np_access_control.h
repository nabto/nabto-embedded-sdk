#ifndef NP_ACCESS_CONTROL_H
#define NP_ACCESS_CONTROL_H

enum np_access_control_permission {
    NP_CONNECT_PERMISSION,
    NP_STREAMING_PERMISSION
};

struct np_access_control_module {
    bool (*can_access)(uint8_t* fingerprint, enum np_access_control_permission feature);
};

#endif
