#ifndef _NM_IAM_TO_JSON_H_
#define _NM_IAM_TO_JSON_H_

#include <cjson/cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_iam_role;
struct nm_iam_user;

cJSON* nm_iam_role_to_json(struct nm_iam_role* role);

cJSON* nm_iam_user_to_json(struct nm_iam_user* user);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
