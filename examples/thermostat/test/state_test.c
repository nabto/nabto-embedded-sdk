#include "thermostat_state.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <tinycbor/cbor.h>

static bool power(void* impl) { (void)impl; return true; }
static double target(void* impl) { (void)impl; return 21.0; }
static double temperature(void* impl) { (void)impl; return 22.5; }
static enum thermostat_mode mode(void* impl) { return *(enum thermostat_mode*)impl; }
static void schedule(void* impl, struct thermostat_schedule* out) {
    (void)impl;
    *out = (struct thermostat_schedule){ {21.0, "06:30", true}, {18.0, "22:00", false} };
}
int main(void) {
    enum thermostat_mode current = THERMOSTAT_MODE_HEAT;
    struct thermostat_state state = { .impl = &current, .get_power = power,
        .get_target = target, .get_temperature = temperature, .get_mode = mode,
        .get_schedule = schedule };
    unsigned char buffer[THERMOSTAT_STATE_CBOR_CAPACITY];
    size_t length = thermostat_state_encode(&state, buffer, sizeof(buffer));
    assert(length > 0 && length == thermostat_state_encode(&state, NULL, 0));
    assert(thermostat_state_encode(&state, buffer, 1) == 0);
    for (int m = THERMOSTAT_MODE_COOL; m <= THERMOSTAT_MODE_FAN; m++) {
        current = m;
        length = thermostat_state_encode(&state, buffer, sizeof(buffer));
        CborParser parser;
        CborValue value, field;
        assert(cbor_parser_init(buffer, length, 0, &parser, &value) == CborNoError);
        assert(cbor_value_validate_basic(&value) == CborNoError);
        CborValue end = value;
        assert(cbor_value_advance(&end) == CborNoError);
        assert(cbor_value_get_next_byte(&end) == buffer + length);
        assert(cbor_value_map_find_value(&value, "Mode", &field) == CborNoError);
        char decoded[16]; size_t size = sizeof(decoded);
        assert(cbor_value_copy_text_string(&field, decoded, &size, NULL) == CborNoError);
        assert(strcmp(decoded, thermostat_state_mode_as_string(current)) == 0);
    }
    assert(thermostat_schedule_time_is_valid("23:59"));
    assert(!thermostat_schedule_time_is_valid("24:00"));
    assert(!thermostat_schedule_time_is_valid("06:60"));
    assert(!thermostat_schedule_time_is_valid("6:30"));
    current = THERMOSTAT_MODE_HEAT;
    length = thermostat_state_encode(&state, buffer, sizeof(buffer));
    for (size_t i = 0; i < length; i++) printf("%02x", buffer[i]);
    puts("");
    return 0;
}
