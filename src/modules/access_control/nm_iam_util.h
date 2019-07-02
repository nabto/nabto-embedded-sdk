#ifndef _NM_IAM_UTIL_H_
#define _NM_IAM_UTIL_H_

#include <stdbool.h>
#include "nm_access_control.h"

bool nm_iam_find_action_in_list(struct nm_iam_list* actions, struct nm_iam_action* action);

#endif
