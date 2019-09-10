#include <platform/np_error_code.h>

const char* np_error_code_to_string(np_error_code ec)
{
#define XX_ERROR(name, message) if (ec == NABTO_EC_##name) { return message; } else
    NP_ERROR_CODE_MAPPING(XX_ERROR)
#undef XX_ERROR
    {
        return "Unknown error code, this should not happen";
    }
}
