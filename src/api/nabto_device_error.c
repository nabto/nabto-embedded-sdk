#include <nabto/nabto_device.h>


#define NABTO_DEVICE_ERROR_MAPPING(XX) \
    XX(NABTO_DEVICE_EC_OK, 0, "Ok") \
    XX(NABTO_DEVICE_EC_FAILED, 1000, "Failed") \
    XX(NABTO_DEVICE_EC_NOT_IMPLEMENTED, 1001, "Not implemented") \
    XX(NABTO_DEVICE_EC_INVALID_LOG_LEVEL, 1002, "Invalid log level") \
    XX(NABTO_DEVICE_EC_IAM_DENY, 2000, "Action denied")

#define XX_ERROR(name, value, _) const NabtoDeviceError name = value;
NABTO_DEVICE_ERROR_MAPPING(XX_ERROR)
#undef XX_ERROR

const char* NABTO_DEVICE_API nabto_device_error_get_message(NabtoDeviceError ec)
{
#define XX_ERROR(name, _, message) if (ec == name) { return message; } else
    NABTO_DEVICE_ERROR_MAPPING(XX_ERROR)
#undef XX_ERROR
    {
        return "Unknown error code, this should not happen";
    }
}
