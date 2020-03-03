#include "np_platform.h"

#include "string.h"

void np_platform_init(struct np_platform* pl)
{
    memset(pl, 0, sizeof(struct np_platform));
}

void np_platform_deinit(struct np_platform* pl)
{
}
