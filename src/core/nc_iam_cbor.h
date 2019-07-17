#ifndef _NC_IAM_CBOR_H_
#define _NC_IAM_CBOR_H_

#include "nc_device.h"

#include "cbor.h"

#include <stdlib.h>


bool nc_iam_cbor_policy_create(struct nc_device_context* device, const char* name, void* cbor, size_t cborLength);

bool nc_iam_cbor_users_get(struct nc_device_context* device, const char* name, void** cbor, size_t* cborLength);

#endif
