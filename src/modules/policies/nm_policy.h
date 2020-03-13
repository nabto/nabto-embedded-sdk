#ifndef _NM_POLICY_H_
#define _NM_POLICY_H_

#include "nm_effect.h"

#include <platform/np_vector.h>
#include <platform/np_string_map.h>

struct nm_policy {
    char* id;
    struct np_vector statements;
};

struct nm_policy* nm_policy_new();

void nm_policy_free(struct nm_policy* poilicy);

// Add statement to a policy, this takes ownership over the statement.
np_error_code nm_policy_add_statement(struct nm_policy* policy);

enum nm_effect nm_policy_eval(struct nm_policy* policy, const char* action, struct np_string_map* attributes);

#endif
