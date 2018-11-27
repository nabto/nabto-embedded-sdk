#ifndef NM_ACCESS_CONTROL_H
#define NM_ACCESS_CONTROL_H

#include <platform/np_access_control.h>

void nm_access_control_init(struct np_platform* pl)
{
    pl->accCtrl.can_access = &nm_access_control_can_access;
}

bool nm_access_control_can_access(uint8_t fingerprint, enum np_access_control_permission feature)
{
    return true;
}

#endif
