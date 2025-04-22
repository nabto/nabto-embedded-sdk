#ifndef NM_IAM_ROLE_H_
#define NM_IAM_ROLE_H_

#include "nm_iam_configuration.h"
#include <nn/string_set.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a new role with the specified name.
 */
struct nm_iam_role* nm_iam_role_new(const char* id);

/**
 * Free a role.
 */
void nm_iam_role_free(struct nm_iam_role* role);

/**
 * Add a policy reference to a role.
 * @param policy is the identifier of an `nm_policy`.
 */
bool nm_iam_role_add_policy(struct nm_iam_role* role, const char* policy);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
