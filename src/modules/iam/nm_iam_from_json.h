#ifndef _NM_IAM_FROM_JSON_H_
#define _NM_IAM_FROM_JSON_H_

#include "nm_iam_role.h"
#include <cjson/cJSON.h>

struct nm_iam_role* nm_iam_role_from_json(cJSON* role);

#endif
