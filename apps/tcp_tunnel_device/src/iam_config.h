#ifndef _IAM_CONFIG_H_
#define _IAM_CONFIG_H_

#include <platform/np_vector.h>

struct nn_log;

struct iam_config {
    struct np_vector roles;
    struct np_vector policies;
};

void iam_config_init(struct iam_config* iamConfig);
void iam_config_deinit(struct iam_config* iamConfig);

bool load_iam_config(struct iam_config* iamConfig, const char* iamConfigFile, struct nn_log* logger);


#endif
