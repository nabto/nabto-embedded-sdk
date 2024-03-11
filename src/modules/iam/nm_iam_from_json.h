#ifndef _NM_IAM_FROM_JSON_H_
#define _NM_IAM_FROM_JSON_H_

#include <cjson/cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_iam_role;
struct nm_iam_user;

struct nm_iam_role* nm_iam_role_from_json(const cJSON* role);
struct nm_iam_user* nm_iam_user_from_json(const cJSON* user, int version);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
