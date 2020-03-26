#ifndef _NM_POLICY_H_
#define _NM_POLICY_H_

#include "nm_effect.h"
#include "nm_statement.h"

#include <platform/np_vector.h>
#include <platform/np_string_map.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_policy {
    char* id;
    struct np_vector statements;
};

struct nm_policy* nm_policy_new(const char* id);

void nm_policy_free(struct nm_policy* poilicy);

// Add statement to a policy, this takes ownership over the statement.
np_error_code nm_policy_add_statement(struct nm_policy* policy, struct nm_statement* stmt);

enum nm_effect nm_policy_eval(struct nm_policy* policy, const char* action, const struct np_string_map* attributes);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
