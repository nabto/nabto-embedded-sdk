#ifndef NM_ACCESS_CONTROL_H
#define NM_ACCESS_CONTROL_H

#include <platform/np_access_control.h>

bool nm_access_control_can_access(uint8_t* fingerprint, enum np_access_control_permission feature);

#endif
