#ifndef _NM_POLICIES_TO_JSON_H_
#define _NM_POLICIES_TO_JSON_H_

struct nm_iam_policy;

#include <cjson/cJSON.h>

cJSON* nm_policy_to_json(const struct nm_iam_policy* policy);

#endif
