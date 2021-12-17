#include "nc_coap_rest_error.h"

#include <platform/np_logging_defines.h>
#include <platform/np_logging.h>

#include <cbor.h>
#include "nc_cbor.h"

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

bool nc_coap_rest_error_decode_response(struct nabto_coap_client_response* response, struct nc_coap_rest_error* error)
{
    uint16_t contentFormat;
    error->message = NULL;
    error->nabtoErrorCode = 0; // not a valid nabto error code
    error->coapResponseCode = nabto_coap_client_response_get_code(response);

    if (nabto_coap_client_response_get_content_format(response, &contentFormat)) {
        if (contentFormat == NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
            const uint8_t* payload;
            size_t payloadLength;
            if (nabto_coap_client_response_get_payload(response, &payload,
                                                       &payloadLength)) {
                CborParser parser;
                CborValue root;
                CborValue cborError;
                CborValue cborCode;
                CborValue message;
                cbor_parser_init(payload, payloadLength, 0, &parser, &root);
                if (cbor_value_is_map(&root)) {
                    cbor_value_map_find_value(&root, "Error", &cborError);
                    if (cbor_value_is_map(&cborError)) {
                        cbor_value_map_find_value(&cborError, "Code", &cborCode);
                        cbor_value_map_find_value(&cborError, "Message", &message);

                        nc_cbor_copy_text_string(&message, &error->message, 1024);
                        if (cbor_value_is_integer(&cborCode)) {
                            cbor_value_get_int(&cborCode, &error->nabtoErrorCode);
                        }
                    }
                }
            }
        }
    } else {
        // no content format if there is a body it should be treated as an utf8 string.
        const uint8_t* payload;
        size_t payloadLength;
        if(nabto_coap_client_response_get_payload(response, &payload, &payloadLength)) {
            if (payloadLength < 1024) {
                error->message = calloc(1, payloadLength+1);
                memcpy(error->message, payload, payloadLength);
            }
        }
    }
    if (error->message == NULL) {
        error->message = strdup(""); // make the message well defined.
    }
    return true;
}

void nc_coap_rest_error_deinit(struct nc_coap_rest_error* error)
{
    free(error->message);
}
