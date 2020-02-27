#ifndef _NC_COAP_H_
#define _NC_COAP_H_

#include <platform/np_error_code.h>
#include <coap/nabto_coap.h>

// translate nabto_coap_error to np_error_code, coap errors are common
// for server and client
np_error_code nc_coap_error_to_core(nabto_coap_error ec);

bool nc_coap_is_status_ok(uint16_t code);

#endif
