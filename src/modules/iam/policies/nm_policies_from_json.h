#ifndef _NM_POLICIES_FROM_JSON_H_
#define _NM_POLICIES_FROM_JSON_H_

#include <cjson/cJSON.h>
#include <nn/log.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_policy;
struct nm_condition;
struct nm_statement;

struct nm_policy* nm_policy_from_json(const cJSON* json, struct nn_log* logger);

struct nm_condition* nm_condition_from_json(const cJSON* json, struct nn_log* logger);

struct nm_statement* nm_statement_from_json(const cJSON* json, struct nn_log* logger);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
