#ifndef _IAM_CONFIG_H_
#define _IAM_CONFIG_H_

#include <nn/vector.h>
#include <nn/string_set.h>

struct nn_log;

struct iam_config {
    struct nn_vector roles;
    struct nn_vector policies;
    char* unpairedRole;
    char* firstUserRole;
    char* secondaryUserRole ;
};

void iam_config_init(struct iam_config* iamConfig);
void iam_config_deinit(struct iam_config* iamConfig);

bool load_iam_config(struct iam_config* iamConfig, const char* iamConfigFile, struct nn_log* logger);


#endif
