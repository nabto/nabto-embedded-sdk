#include "platform.h"

#include "string.h"

void nabto_platform_init(struct nabto_platform* pl)
{
    memset(pl, 0, sizeof(struct nabto_platform));
}
