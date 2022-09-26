#include "thermostat.h"

#include "thermostat_coap_handler.h"
#include "thermostat_iam.h"

#include <apps/common/logging.h>
#include <apps/common/json_config.h>
#include <apps/common/string_file.h>

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>
#include <modules/iam/nm_iam_configuration.h>
#include <modules/iam/nm_iam_state.h>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <cjson/cJSON.h>

//static const char* LOGM = "thermostat";

static NabtoDeviceError thermostat_init_coap_handlers(struct thermostat* thermostat);


// Initialize the thermostat
void thermostat_init(struct thermostat* thermostat, NabtoDevice* device, struct thermostat_state* state, struct nn_log* logger)
{
    memset(thermostat, 0, sizeof(struct thermostat));
    thermostat->device = device;
    thermostat->logger = logger;
    thermostat->state = state;
    thermostat_init_coap_handlers(thermostat);
}

// Deinitialize the thermostat
void thermostat_deinit(struct thermostat* thermostat)
{
    thermostat_coap_handler_deinit(&thermostat->coapGet);
    thermostat_coap_handler_deinit(&thermostat->coapSetMode);
    thermostat_coap_handler_deinit(&thermostat->coapSetPower);
    thermostat_coap_handler_deinit(&thermostat->coapSetTarget);

    thermostat_coap_handler_deinit(&thermostat->coapGetLegacy);
    thermostat_coap_handler_deinit(&thermostat->coapSetModeLegacy);
    thermostat_coap_handler_deinit(&thermostat->coapSetPowerLegacy);
    thermostat_coap_handler_deinit(&thermostat->coapSetTargetLegacy);
    //thermostat_iam_deinit(thermostat);
}

// stop the thermostat
void thermostat_stop(struct thermostat* thermostat)
{
    nm_iam_stop(&thermostat->iam);
    thermostat_coap_handler_stop(&thermostat->coapGet);
    thermostat_coap_handler_stop(&thermostat->coapSetMode);
    thermostat_coap_handler_stop(&thermostat->coapSetPower);
    thermostat_coap_handler_stop(&thermostat->coapSetTarget);

    thermostat_coap_handler_stop(&thermostat->coapGetLegacy);
    thermostat_coap_handler_stop(&thermostat->coapSetModeLegacy);
    thermostat_coap_handler_stop(&thermostat->coapSetPowerLegacy);
    thermostat_coap_handler_stop(&thermostat->coapSetTargetLegacy);
}


NabtoDeviceError thermostat_init_coap_handlers(struct thermostat* thermostat)
{
    NabtoDeviceError ec;
    ec = thermostat_get_init(&thermostat->coapGet, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_mode_init(&thermostat->coapSetMode, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_power_init(&thermostat->coapSetPower, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_target_init(&thermostat->coapSetTarget, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }

    ec = thermostat_get_legacy_init(&thermostat->coapGetLegacy, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_mode_legacy_init(&thermostat->coapSetModeLegacy, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_power_legacy_init(&thermostat->coapSetPowerLegacy, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_target_legacy_init(&thermostat->coapSetTargetLegacy, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }

    return NABTO_DEVICE_EC_OK;
}

bool thermostat_check_access(struct thermostat* thermostat, NabtoDeviceCoapRequest* request, const char* action)
{
    if (!nm_iam_check_access(&thermostat->iam, nabto_device_coap_request_get_connection_ref(request), action, NULL)) {
        return false;
    }
    return true;
}
