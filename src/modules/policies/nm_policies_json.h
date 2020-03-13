#ifndef _NM_POLICIES_JSON_H_
#define _NM_POLICIES_JSON_H_

#include <cjson/cJSON.h>

struct nm_policy* nm_policy_from_json(const cJSON* policy);

struct nm_condition* nm_condition_from_json(const cJSON* condition);

#endif
