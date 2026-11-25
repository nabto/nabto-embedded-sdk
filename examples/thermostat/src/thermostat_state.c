#include "thermostat_state.h"

#include <tinycbor/cbor.h>

#include <ctype.h>
#include <string.h>

static void notify_changed(struct thermostat_state* state)
{
    if (state->changedCallback != NULL) {
        state->changedCallback(state->changedCallbackUserData);
    }
}

bool thermostat_state_get_power(struct thermostat_state* state) {
    return state->get_power(state->impl);
}

void thermostat_state_set_power(struct thermostat_state* state, bool power)
{
    state->set_power(state->impl, power);
    notify_changed(state);
}

double thermostat_state_get_target(struct thermostat_state* state) {
    return state->get_target(state->impl);
}

void thermostat_state_set_target(struct thermostat_state* state, double target)
{
    state->set_target(state->impl, target);
    notify_changed(state);
}

double thermostat_state_get_temperature(struct thermostat_state* state)
{
    return state->get_temperature(state->impl);
}

void thermostat_state_set_mode(struct thermostat_state* state, enum thermostat_mode mode)
{
    state->set_mode(state->impl, mode);
    notify_changed(state);
}

enum thermostat_mode thermostat_state_get_mode(struct thermostat_state* state)
{
    return state->get_mode(state->impl);
}

void thermostat_state_get_schedule(struct thermostat_state* state, struct thermostat_schedule* schedule)
{
    state->get_schedule(state->impl, schedule);
}

void thermostat_state_set_schedule(struct thermostat_state* state, const struct thermostat_schedule* schedule)
{
    state->set_schedule(state->impl, schedule);
    notify_changed(state);
}

void thermostat_state_set_changed_callback(struct thermostat_state* state, thermostat_state_changed callback, void* userData)
{
    state->changedCallback = callback;
    state->changedCallbackUserData = userData;
}

const char* thermostat_state_mode_as_string(enum thermostat_mode mode)
{
    switch (mode) {
        case THERMOSTAT_MODE_COOL: return "COOL";
        case THERMOSTAT_MODE_HEAT: return "HEAT";
        case THERMOSTAT_MODE_DRY: return "DRY";
        case THERMOSTAT_MODE_FAN: return "FAN";
    }
    return "UNKNOWN";
}

const char* thermostat_state_power_as_string(bool power)
{
    if (power) {
        return "ON";
    }
    return "OFF";
}

bool thermostat_schedule_time_is_valid(const char* time)
{
    if (time == NULL || strlen(time) != 5) {
        return false;
    }
    if (!isdigit((unsigned char)time[0]) || !isdigit((unsigned char)time[1]) ||
        time[2] != ':' ||
        !isdigit((unsigned char)time[3]) || !isdigit((unsigned char)time[4]))
    {
        return false;
    }
    int hours = ((time[0] - '0') * 10) + (time[1] - '0');
    int minutes = ((time[3] - '0') * 10) + (time[4] - '0');
    return hours <= 23 && minutes <= 59;
}

static void encode_schedule_entry(CborEncoder* map, const char* key, const struct thermostat_schedule_entry* entry)
{
    cbor_encode_text_stringz(map, key);
    CborEncoder entryMap;
    cbor_encoder_create_map(map, &entryMap, CborIndefiniteLength);

    cbor_encode_text_stringz(&entryMap, "Target");
    cbor_encode_double(&entryMap, entry->target);

    cbor_encode_text_stringz(&entryMap, "Time");
    cbor_encode_text_stringz(&entryMap, entry->time);

    cbor_encode_text_stringz(&entryMap, "Enabled");
    cbor_encode_boolean(&entryMap, entry->enabled);

    cbor_encoder_close_container(map, &entryMap);
}

size_t thermostat_state_encode(struct thermostat_state* state, void* buffer, size_t bufferSize)
{
    struct thermostat_schedule schedule;
    thermostat_state_get_schedule(state, &schedule);

    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "Mode");
    cbor_encode_text_stringz(&map, thermostat_state_mode_as_string(thermostat_state_get_mode(state)));

    cbor_encode_text_stringz(&map, "Target");
    cbor_encode_double(&map, thermostat_state_get_target(state));

    cbor_encode_text_stringz(&map, "Power");
    cbor_encode_boolean(&map, thermostat_state_get_power(state));

    cbor_encode_text_stringz(&map, "Temperature");
    cbor_encode_double(&map, thermostat_state_get_temperature(state));

    cbor_encode_text_stringz(&map, "Schedule");
    CborEncoder scheduleMap;
    cbor_encoder_create_map(&map, &scheduleMap, CborIndefiniteLength);
    encode_schedule_entry(&scheduleMap, "Day", &schedule.day);
    encode_schedule_entry(&scheduleMap, "Night", &schedule.night);
    cbor_encoder_close_container(&map, &scheduleMap);

    cbor_encoder_close_container(&encoder, &map);

    if (buffer == NULL) {
        return cbor_encoder_get_extra_bytes_needed(&encoder);
    }
    if (cbor_encoder_get_extra_bytes_needed(&encoder) != 0) {
        return 0;
    }
    return cbor_encoder_get_buffer_size(&encoder, buffer);
}
