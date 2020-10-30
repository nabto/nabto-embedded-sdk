#ifndef _IAM_CONFIG_H_
#define _IAM_CONFIG_H_

#include <modules/iam/nm_iam_configuration.h>
#include <stdbool.h>

struct nn_log;

bool load_iam_config(struct nm_iam_configuration* iamConfig, const char* iamConfigFile, struct nn_log* logger);


#endif
