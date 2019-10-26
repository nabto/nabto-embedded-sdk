#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <platform/np_error_code.h>

#define XX_ERROR(name, _) const NabtoDeviceError NABTO_DEVICE_EC_##name = NABTO_EC_##name;
NP_ERROR_CODE_MAPPING(XX_ERROR)
#undef XX_ERROR

const char* NABTO_DEVICE_API nabto_device_error_get_message(NabtoDeviceError ec)
{
#define XX_ERROR(name, message) if (ec == NABTO_DEVICE_EC_##name) { return message; } else
    NP_ERROR_CODE_MAPPING(XX_ERROR)
#undef XX_ERROR
    {
        return "Unknown error code, this should not happen";
    }
}

NabtoDeviceError nabto_device_error_core_to_api(np_error_code ec)
{
    switch (ec) {
#define XX_ERROR(name, message) case NABTO_EC_##name: return NABTO_DEVICE_EC_##name;
    NP_ERROR_CODE_MAPPING(XX_ERROR)
#undef XX_ERROR
        default: return NABTO_DEVICE_EC_UNKNOWN;
    }
}
