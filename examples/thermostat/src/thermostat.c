#include "thermostat.h"

#include "thermostat_coap_handler.h"
#include "thermostat_iam.h"

#include <apps/common/json_config.h>
#include <apps/common/logging.h>
#include <apps/common/string_file.h>

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_configuration.h>
#include <modules/iam/nm_iam_serializer.h>
#include <modules/iam/nm_iam_state.h>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <cjson/cJSON.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char* LOGM = "thermostat";

static NabtoDeviceError thermostat_init_coap_handlers(struct thermostat* thermostat);
static void state_changed(void* userData);
static void check_schedule(struct thermostat* thermostat);

// Initialize the thermostat
void thermostat_init(struct thermostat* thermostat, NabtoDevice* device, struct nm_iam* iam, struct thermostat_state* state, struct nn_log* logger)
{
    memset(thermostat, 0, sizeof(struct thermostat));
    thermostat->device = device;
    thermostat->iam = iam;
    thermostat->logger = logger;
    thermostat->state = state;
    thermostat->lastScheduleMinute = -1;
    thermostat_init_coap_handlers(thermostat);

    thermostat_history_init(&thermostat->history);
    double temperature = thermostat_state_get_temperature(state);
    thermostat->lastTickTemperature = temperature;
    thermostat_history_seed(&thermostat->history, thermostat_state_get_target(state), temperature, THERMOSTAT_HISTORY_SEED_SAMPLES);

    if (thermostat_stream_manager_init(&thermostat->streamManager, device, thermostat) != NABTO_DEVICE_EC_OK) {
        NN_LOG_ERROR(logger, LOGM, "Cannot initialize the state stream listener");
    }
    thermostat_state_set_changed_callback(state, state_changed, thermostat);
}

// Deinitialize the thermostat
void thermostat_deinit(struct thermostat* thermostat)
{
    thermostat_coap_handler_deinit(&thermostat->coapGet);
    thermostat_coap_handler_deinit(&thermostat->coapSetMode);
    thermostat_coap_handler_deinit(&thermostat->coapSetPower);
    thermostat_coap_handler_deinit(&thermostat->coapSetTarget);
    thermostat_coap_handler_deinit(&thermostat->coapGetHistory);
    thermostat_coap_handler_deinit(&thermostat->coapSetSchedule);

    thermostat_coap_handler_deinit(&thermostat->coapGetLegacy);
    thermostat_coap_handler_deinit(&thermostat->coapSetModeLegacy);
    thermostat_coap_handler_deinit(&thermostat->coapSetPowerLegacy);
    thermostat_coap_handler_deinit(&thermostat->coapSetTargetLegacy);
    //thermostat_iam_deinit(thermostat);

    thermostat_state_set_changed_callback(thermostat->state, NULL, NULL);
    thermostat_stream_manager_deinit(&thermostat->streamManager);
    thermostat_history_deinit(&thermostat->history);
}

// stop the thermostat
void thermostat_stop(struct thermostat* thermostat)
{
    thermostat_coap_handler_stop(&thermostat->coapGet);
    thermostat_coap_handler_stop(&thermostat->coapSetMode);
    thermostat_coap_handler_stop(&thermostat->coapSetPower);
    thermostat_coap_handler_stop(&thermostat->coapSetTarget);
    thermostat_coap_handler_stop(&thermostat->coapGetHistory);
    thermostat_coap_handler_stop(&thermostat->coapSetSchedule);

    thermostat_coap_handler_stop(&thermostat->coapGetLegacy);
    thermostat_coap_handler_stop(&thermostat->coapSetModeLegacy);
    thermostat_coap_handler_stop(&thermostat->coapSetPowerLegacy);
    thermostat_coap_handler_stop(&thermostat->coapSetTargetLegacy);

    thermostat_stream_manager_stop(&thermostat->streamManager);
}

// state changed observer, registered on the thermostat state, invoked from
// every state setter.
void state_changed(void* userData)
{
    struct thermostat* thermostat = userData;
    thermostat_stream_manager_notify_state_changed(&thermostat->streamManager);
}

// Called from the tick loop on the main thread.
void thermostat_update(struct thermostat* thermostat, double deltaTime)
{
    // sample the room temperature each 5 minutes of accumulated tick time.
    thermostat->historySampleAccumulator += deltaTime;
    if (thermostat->historySampleAccumulator >= (double)THERMOSTAT_HISTORY_INTERVAL_SECONDS) {
        thermostat->historySampleAccumulator -= (double)THERMOSTAT_HISTORY_INTERVAL_SECONDS;
        thermostat_history_push(&thermostat->history, thermostat_state_get_temperature(thermostat->state));
    }

    // evaluate the schedule once per minute of wall clock time. The check
    // itself runs about once per second.
    thermostat->scheduleCheckAccumulator += deltaTime;
    if (thermostat->scheduleCheckAccumulator >= 1.0) {
        thermostat->scheduleCheckAccumulator = 0;
        check_schedule(thermostat);
    }

    // notify the state stream when the simulation has changed the temperature
    // and retry throttled stream sends.
    double temperature = thermostat_state_get_temperature(thermostat->state);
    if (temperature != thermostat->lastTickTemperature) {
        thermostat->lastTickTemperature = temperature;
        thermostat_stream_manager_notify_state_changed(&thermostat->streamManager);
    }
    thermostat_stream_manager_flush(&thermostat->streamManager);
}

void check_schedule(struct thermostat* thermostat)
{
    time_t now = time(NULL);
    struct tm* tm = localtime(&now);
    if (tm == NULL) {
        return;
    }
    int minuteOfDay = (tm->tm_hour * 60) + tm->tm_min;
    if (minuteOfDay == thermostat->lastScheduleMinute) {
        return;
    }
    thermostat->lastScheduleMinute = minuteOfDay;

    char current[16];
    snprintf(current, sizeof(current), "%02d:%02d", tm->tm_hour, tm->tm_min);

    struct thermostat_schedule schedule;
    thermostat_state_get_schedule(thermostat->state, &schedule);
    if (schedule.day.enabled && strcmp(schedule.day.time, current) == 0) {
        thermostat_state_set_target(thermostat->state, schedule.day.target);
    }
    if (schedule.night.enabled && strcmp(schedule.night.time, current) == 0) {
        thermostat_state_set_target(thermostat->state, schedule.night.target);
    }
}

NabtoDeviceError thermostat_init_coap_handlers(struct thermostat* thermostat)
{
    NabtoDeviceError ec = 0;
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
    ec = thermostat_get_history_init(&thermostat->coapGetHistory, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_schedule_init(&thermostat->coapSetSchedule, thermostat->device, thermostat);
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
    if (!nm_iam_check_access(thermostat->iam, nabto_device_coap_request_get_connection_ref(request), action, NULL)) {
        return false;
    }
    return true;
}
