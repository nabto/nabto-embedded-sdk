#ifndef THERMOSTAT_IAM_H_
#define THERMOSTAT_IAM_H_

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_state.h>
#include <nabto/nabto_device.h>
#include <nn/log.h>

struct thermostat_iam {
    struct nn_log* logger;
    struct nm_iam iam;
    NabtoDevice* device;
    char* iamStateFile;
    struct nm_fs* file;
};

void thermostat_iam_init(struct thermostat_iam* thermostatIam, NabtoDevice* device, struct nm_fs* file, const char* iamStateFile, struct nn_log* logger);
void thermostat_iam_deinit(struct thermostat_iam* thermostatIam);

void thermostat_iam_create_default_state(NabtoDevice* device, struct nm_fs* file, const char* iamStateFile, struct nn_log* logger);

bool thermostat_iam_load_state(struct thermostat_iam* thermostatIam);

char* thermostat_iam_create_pairing_string(struct nm_iam* iam, const char* productId, const char* deviceId);

#endif
