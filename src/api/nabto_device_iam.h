#ifndef _NABTO_DEVICE_IAM_H_
#define _NABTO_DEVICE_IAM_H_

#include <nabto/nabto_device_experimental.h>

struct nabto_device_iam_env {
    int dummy;
};

struct nabto_device_iam_env* nabto_device_iam_env_new_internal();

void nabto_device_iam_env_free_internal(struct nabto_device_iam_env* env);

#endif
