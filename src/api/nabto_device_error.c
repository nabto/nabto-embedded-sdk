#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include "nabto_device_error.h"
#include <platform/np_error_code.h>

#define XX_ERROR(name) const NabtoDeviceError NABTO_DEVICE_EC_##name = NABTO_EC_##name;
NABTO_DEVICE_ERROR_CODE_MAPPING(XX_ERROR)
#undef XX_ERROR

const char* NABTO_DEVICE_API nabto_device_error_get_message(NabtoDeviceError ec)
{
// NOLINTNEXTLINE(readability-else-after-return)
#define XX_ERROR(name) if (ec == NABTO_DEVICE_EC_##name) { return np_error_code_to_string(NABTO_EC_##name); } else
    NABTO_DEVICE_ERROR_CODE_MAPPING(XX_ERROR)
#undef XX_ERROR
    {
        return "Unknown error code, this should not happen";
    }
}

const char* NABTO_DEVICE_API nabto_device_error_get_string(NabtoDeviceError ec)
{
    switch (ec) {
#define XX_ERROR(name) case NABTO_EC_##name: return "NABTO_DEVICE_"#name;
        NABTO_DEVICE_ERROR_CODE_MAPPING(XX_ERROR)
#undef XX_ERROR
    }
    return "Unknown error code, this should not happen";
}

NabtoDeviceError nabto_device_error_core_to_api(np_error_code ec)
{
    switch (ec) {
#define XX_ERROR(name) case NABTO_EC_##name: return NABTO_DEVICE_EC_##name;
    NABTO_DEVICE_ERROR_CODE_MAPPING(XX_ERROR)
#undef XX_ERROR
        default: return NABTO_DEVICE_EC_UNKNOWN;
    }
}
