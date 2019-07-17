#ifndef _NC_IAM_POLICY_H_
#define _NC_IAM_POLICY_H_

#include "nc_iam.h"

// create a new policy and add it to the iam module
struct nc_iam_policy* nc_iam_policy_new(struct nc_iam* iam, const char* name);
void nc_iam_policy_free(struct nc_iam_policy* policy);
void nc_iam_policy_delete(struct nc_iam* iam, const char* name);

struct nc_iam_policy* nc_iam_find_policy(struct nc_iam* iam, const char* policy);

void nc_iam_list_policies(struct nc_iam* iam, void** cbor, size_t* cborLength);

bool nc_iam_cbor_policy_create(struct nc_device_context* device, const char* name, void* cbor, size_t cborLength);

struct nc_iam_policy* nc_iam_find_policy_by_name(struct nc_iam* iam, const char* name);

#endif
