#include "nm_access_control.h"

#include <platform/np_platform.h>

bool nm_access_control_can_access(uint8_t* fingerprint, enum np_access_control_permission feature)
{
    return true;
}

void np_access_control_init(struct np_platform* pl)
{
    pl->accCtrl.can_access = &nm_access_control_can_access;
}


