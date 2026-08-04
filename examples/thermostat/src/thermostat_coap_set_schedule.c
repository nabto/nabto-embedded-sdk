#include "thermostat_coap_handler.h"
#include "thermostat.h"

#include "cbor_extra.h"
#include <string.h>
#include <tinycbor/cbor.h>

static void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError thermostat_set_schedule_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat)
{
    const char* paths[] = { "thermostat", "schedule", "{id}", NULL };
    return thermostat_coap_handler_init(handler, device, thermostat, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

// Update entry with the keys present in the request map. Missing keys leave
// the corresponding field unchanged. Returns false on invalid input.
static bool update_entry(CborValue* map, struct thermostat_schedule_entry* entry)
{
    CborValue target;
    CborValue time;
    CborValue enabled;
    if (cbor_value_map_find_value(map, "Target", &target) != CborNoError ||
        cbor_value_map_find_value(map, "Time", &time) != CborNoError ||
        cbor_value_map_find_value(map, "Enabled", &enabled) != CborNoError)
    {
        return false;
    }

    if (cbor_value_is_valid(&target)) {
        if (!cbor_value_is_floating_point(&target) ||
            cbor_value_get_floating_point(&target, &entry->target) != CborNoError)
        {
            return false;
        }
    }

    if (cbor_value_is_valid(&time)) {
        if (!cbor_value_is_text_string(&time)) {
            return false;
        }
        char timeBuffer[6];
        size_t length = 0;
        if (cbor_value_calculate_string_length(&time, &length) != CborNoError ||
            length != 5)
        {
            return false;
        }
        length = sizeof(timeBuffer);
        if (cbor_value_copy_text_string(&time, timeBuffer, &length, NULL) != CborNoError) {
            return false;
        }
        if (!thermostat_schedule_time_is_valid(timeBuffer)) {
            return false;
        }
        memcpy(entry->time, timeBuffer, sizeof(entry->time));
    }

    if (cbor_value_is_valid(&enabled)) {
        if (!cbor_value_is_boolean(&enabled) ||
            cbor_value_get_boolean(&enabled, &entry->enabled) != CborNoError)
        {
            return false;
        }
    }

    return true;
}

void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct thermostat* thermostat = handler->thermostat;
    struct thermostat_state* state = thermostat->state;
    if (!thermostat_check_access(thermostat, request, "Thermostat:Set")) {
        nabto_device_coap_error_response(request, 403, "Access denied");
        return;
    }

    const char* id = nabto_device_coap_request_get_parameter(request, "id");
    bool isDay = (id != NULL && strcmp(id, "day") == 0);
    bool isNight = (id != NULL && strcmp(id, "night") == 0);
    if (!isDay && !isNight) {
        nabto_device_coap_error_response(request, 404, "No such schedule");
        return;
    }

    CborParser parser;
    CborValue value;
    if (!thermostat_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    if (!cbor_value_is_map(&value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    struct thermostat_schedule schedule;
    thermostat_state_get_schedule(state, &schedule);
    struct thermostat_schedule_entry* entry = isDay ? &schedule.day : &schedule.night;

    if (!update_entry(&value, entry)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    thermostat_state_set_schedule(state, &schedule);

    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}
