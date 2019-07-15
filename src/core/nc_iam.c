#include "nc_iam.h"

#include <string.h>

struct nc_iam_user* nc_iam_find_user(struct nc_iam* iam, uint8_t fingerprint[16])
{
    return iam->defaultUser;
}
