#ifndef _NM_POLICY_H_
#define _NM_POLICY_H_

#include "nm_effect.h"
#include "nm_statement.h"

#include <nn/vector.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nn_string_map;

struct nm_policy_eval_state {
    enum nm_effect effect;
};

struct nm_policy* nm_policy_new(const char* id);

void nm_policy_free(struct nm_policy* poilicy);

// Add statement to a policy, this takes ownership over the statement.
bool nm_policy_add_statement(struct nm_policy* policy, struct nm_statement* stmt);

void nm_policy_eval_init(struct nm_policy_eval_state* state);

enum nm_effect nm_policy_eval_get_effect(struct nm_policy_eval_state* state);

// Chainable policy evaluation.
void nm_policy_eval(struct nm_policy_eval_state* state, struct nm_policy* policy, const char* action, const struct nn_string_map* attributes);

void nm_policy_statement_eval(struct nm_policy_eval_state* state, struct nm_statement* statement, const char* action, const struct nn_string_map* attributes);

// simple policy eval which cannot be chained.
enum nm_effect nm_policy_eval_simple(struct nm_policy* policy, const char* action, const struct nn_string_map* attributes);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
