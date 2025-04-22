#ifndef NM_POLICIES_FROM_JSON_H_
#define NM_POLICIES_FROM_JSON_H_

#include <cjson/cJSON.h>
#include <nn/log.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_iam_policy;
struct nm_iam_condition;
struct nm_iam_statement;

struct nm_iam_policy* nm_policy_from_json(const cJSON* json, struct nn_log* logger);

struct nm_iam_condition* nm_condition_from_json(const cJSON* json, struct nn_log* logger);

struct nm_iam_statement* nm_statement_from_json(const cJSON* json, struct nn_log* logger);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
