#include "nm_mbedtls_spake2.h"

static np_error_code mbedtls_spake2_create(struct np_platform* pl,
                                           struct np_spake2_context** spake);
static void mbedtls_spake2_destroy(struct np_spake2_context* spake);
static np_error_code mbedtls_spake2_calculate_key(
    struct np_spake2_context* spake, const char* password,
    uint8_t* fingerprintClient, uint8_t* fingerprintDevice);
static np_error_code mbedtls_spake2_key_confirmation(
    struct np_spake2_context* spake, uint8_t* payload, size_t payloadLength);

np_error_code nm_mbedtls_spake2_init(struct np_platform* pl)
{
    pl->spake2.create = &mbedtls_spake2_create;
    pl->spake2.destroy = &mbedtls_spake2_destroy;
    pl->spake2.calculate_key = &mbedtls_spake2_calculate_key;
    pl->spake2.key_confirmation = &mbedtls_spake2_key_confirmation;
    return NABTO_EC_OK;
}

void nm_mbedtls_spake2_deinit(struct np_platform* pl)
{

}

static np_error_code mbedtls_spake2_create(struct np_platform* pl, struct np_spake2_context** spake)
{
    return NABTO_EC_NOT_IMPLEMENTED;
}

static void mbedtls_spake2_destroy(struct np_spake2_context* spake)
{

}


static np_error_code mbedtls_spake2_calculate_key(
    struct np_spake2_context* spake, const char* password,
    uint8_t* fingerprintClient, uint8_t* fingerprintDevice)
{
    return NABTO_EC_NOT_IMPLEMENTED;

}

static np_error_code mbedtls_spake2_key_confirmation(
    struct np_spake2_context* spake, uint8_t* payload, size_t payloadLength)
{
    return NABTO_EC_NOT_IMPLEMENTED;

}
