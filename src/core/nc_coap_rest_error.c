#include "nc_coap_rest_error.h"

#include <platform/np_logging_defines.h>
#include <platform/np_logging.h>

#include <cbor.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

enum nabto_protocol_error_codes {
    INVALID_JWT_TOKEN = 1,
    DEVICE_NOT_ATTACHED = 2,
    UNKNOWN_PRODUCT_ID = 3,
    UNKNOWN_DEVICE_ID = 4,
    UNKNOWN_DEVICE_FINGERPRINT = 5,
    REJECTED_SERVER_CONNECT_TOKEN = 6,
    WRONG_PRODUCT_ID = 7,
    WRONG_DEVICE_ID = 8
};

enum nc_coap_rest_error nc_coap_rest_error_handle_response(struct nabto_coap_client_response* response)
{
    uint16_t contentFormat;
    if (nabto_coap_client_response_get_content_format(response, &contentFormat)) {
        if (contentFormat == NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
            const uint8_t* payload;
            size_t payloadLength;
            if(nabto_coap_client_response_get_payload(response, &payload, &payloadLength)) {
                CborParser parser;
                CborValue root;
                CborValue error;
                CborValue cborCode;
                CborValue message;
                cbor_parser_init(payload, payloadLength, 0, &parser, &root);
                if (!cbor_value_is_map(&root)) {
                    return NC_COAP_REST_ERROR_UNKNOWN;
                }
                cbor_value_map_find_value(&root, "Error", &error);
                if (!cbor_value_is_map(&error)) {
                    return NC_COAP_REST_ERROR_UNKNOWN;
                }
                cbor_value_map_find_value(&error, "Code", &cborCode);
                cbor_value_map_find_value(&error, "Message", &message);

                int code = 0;
                char messageBuffer[128];
                size_t messageSize = 128;
                memset(messageBuffer, 0, 128);
                if (cbor_value_is_text_string(&message)) {
                    cbor_value_copy_text_string(&message, messageBuffer, &messageSize, NULL);
                } else {
                    messageSize = 0;
                }
                if (cbor_value_is_integer(&cborCode)) {
                    cbor_value_get_int(&cborCode, &code);
                }
                NABTO_LOG_TRACE(LOG, "CoAP response, code: %d, message: %.*s", code, messageSize, messageBuffer);
                if (code == UNKNOWN_DEVICE_FINGERPRINT) {
                    return NC_COAP_REST_ERROR_UNKNOWN_DEVICE_FINGERPRINT;
                } else if (code == WRONG_PRODUCT_ID) {
                    return NC_COAP_REST_ERROR_WRONG_PRODUCT_ID;
                } else if (code == WRONG_DEVICE_ID) {
                    return NC_COAP_REST_ERROR_WRONG_DEVICE_ID;
                }
            }
        } else {
            // unrecognized content format.
        }
    } else {
        // no content format if there is a body it should be treated as an utf8 string.
        const uint8_t* payload;
        size_t payloadLength;
        if(nabto_coap_client_response_get_payload(response, &payload, &payloadLength)) {
            NABTO_LOG_TRACE(LOG, "Coap Response: %.*s", payloadLength, payload);
        }
    }

    return NC_COAP_REST_ERROR_UNKNOWN;
}
