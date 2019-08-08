#ifndef _NC_IAM_POLICY_H_
#define _NC_IAM_POLICY_H_

#include "nc_iam.h"

#include <platform/np_error_code.h>

// create a new policy and add it to the iam module
struct nc_iam_policy* nc_iam_policy_new(struct nc_iam* iam, const char* name);
void nc_iam_policy_free(struct nc_iam_policy* policy);
np_error_code nc_iam_policy_delete(struct nc_iam* iam, const char* name);

np_error_code nc_iam_list_policies(struct nc_iam* iam, void* buffer, size_t bufferLength, size_t* used);

np_error_code nc_iam_cbor_policy_create(struct nc_iam* iam, const char* name, const void* cbor, size_t cborLength);
np_error_code nc_iam_policy_get(struct nc_iam* iam, const char* name, void* buffer, size_t bufferLength, size_t* used);

struct nc_iam_policy* nc_iam_find_policy_by_name(struct nc_iam* iam, const char* name);

#endif
