#ifndef _NM_IAM_TO_JSON_H_
#define _NM_IAM_TO_JSON_H_

#include <cjson/cJSON.h>

struct nm_iam_role;

cJSON* nm_iam_role_to_json(struct nm_iam_role* role);

#endif
