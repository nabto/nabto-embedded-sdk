#ifndef _IAM_CONFIG_H_
#define _IAM_CONFIG_H_

#include <modules/iam/nm_iam_configuration.h>
#include <stdbool.h>

struct nn_log;
struct nm_fs;

bool iam_config_exists(struct nm_fs* fsImpl, const char* iamConfigFile);
bool iam_config_load(struct nm_iam_configuration* iamConfig, struct nm_fs* fsImpl, const char* iamConfigFile, struct nn_log* logger);
bool iam_config_create_default(struct nm_fs* fsImpl, const char* iamConfigFile);


#endif
