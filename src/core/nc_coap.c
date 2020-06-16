#include "nc_coap.h"


np_error_code nc_coap_error_to_core(nabto_coap_error ec) {
    switch(ec) {
        case NABTO_COAP_ERROR_OK: return NABTO_EC_OK;
        case NABTO_COAP_ERROR_OUT_OF_MEMORY: return NABTO_EC_OUT_OF_MEMORY;
        case NABTO_COAP_ERROR_NO_CONNECTION: return NABTO_EC_ABORTED;
        case NABTO_COAP_ERROR_INVALID_PARAMETER: return NABTO_EC_INVALID_ARGUMENT;
        default: return NABTO_EC_UNKNOWN;
    }
}

bool nc_coap_is_status_ok(uint16_t code)
{

    return ((code >= 200) && (code < 300));
}
