#ifndef _NC_COAP_REST_ERROR_H_
#define _NC_COAP_REST_ERROR_H_

#include <core/nc_coap_client.h>

/**
 * Handle coap response error messages from the basestation
 *
 * The error response has this format:
 * {
 * Error: {
 *   "Message": "Description",
 *   "Code": integer
 * }
 * }
 */

#ifdef __cplusplus
extern "C" {
#endif

struct nc_coap_rest_error {
    char* message;
    int nabtoErrorCode;
    int coapResponseCode;
};

enum nabto_protocol_error_codes {
    NABTO_PROTOCOL_INVALID_JWT_TOKEN = 1,
    NABTO_PROTOCOL_DEVICE_NOT_ATTACHED = 2,
    NABTO_PROTOCOL_UNKNOWN_PRODUCT_ID = 3,
    NABTO_PROTOCOL_UNKNOWN_DEVICE_ID = 4,
    NABTO_PROTOCOL_UNKNOWN_DEVICE_FINGERPRINT = 5,
    NABTO_PROTOCOL_REJECTED_SERVER_CONNECT_TOKEN = 6,
    NABTO_PROTOCOL_WRONG_PRODUCT_ID = 7,
    NABTO_PROTOCOL_WRONG_DEVICE_ID = 8
};

void nc_coap_rest_error_deinit(struct nc_coap_rest_error* response);

/**
 * @param response  the coap response.
 * @param error  the error struct to fill parse the result to.
 * @return true iff the error response is decoded.
 *
 * nc_coap_rest_error_deinit needs to be called on the error afterwards to free memory allocated in it.
 */
bool nc_coap_rest_error_decode_response(struct nabto_coap_client_response* response, struct nc_coap_rest_error* error);

#ifdef __cplusplus
} // extern c
#endif

#endif
