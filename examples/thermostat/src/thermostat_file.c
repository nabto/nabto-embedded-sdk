#include "thermostat_file.h"
#include "thermostat.h"
#include <apps/common/json_config.h>
#include <cjson/cJSON.h>

#include "string.h"

void thermostat_file_deinit(struct thermostat_file* tf)
{
    free(tf->thermostatStateFile);
    free(tf->iamStateFile);
    free(tf->deviceKeyFile);
    free(tf->deviceConfigFile);
}

void thermostat_file_init(struct thermostat_file* tf, const char* homeDir)
{
    char buffer[512];
    memset(buffer, 0, 512);

    snprintf(buffer, 511, "%s/config/device.json", homeDir);
    tf->deviceConfigFile = strdup(buffer);
    snprintf(buffer, 511, "%s/keys/device.key", homeDir);
    tf->deviceKeyFile = strdup(buffer);
    snprintf(buffer, 511, "%s/state/thermostat_device_iam_state.json", homeDir);
    tf->iamStateFile = strdup(buffer);
    snprintf(buffer, 511, "%s/state/thermostat_device_state.json", homeDir);
    tf->thermostatStateFile = strdup(buffer);
}
