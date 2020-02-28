#ifndef _NC_COAP_REST_ERROR_H_
#define _NC_COAP_REST_ERROR_H_

#include <core/nc_coap_client.h>

/**
 * Handle coap response error messages from the basestation
 */


enum nc_coap_rest_error {
    NC_COAP_REST_ERROR_UNKNOWN,
    NC_COAP_REST_ERROR_UNKNOWN_DEVICE_FINGERPRINT
    // add specific errors which needs to be handled programmatically here.
};

enum nc_coap_rest_error nc_coap_rest_error_handle_response(struct nabto_coap_client_response* response);


#endif
