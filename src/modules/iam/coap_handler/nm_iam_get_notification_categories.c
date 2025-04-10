#include "nm_iam_coap_handler.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"

#include "../nm_iam_allocator.h"

#include <tinycbor/cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_get_notification_categories_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "notification-categories", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

static CborError encode_categories(struct nm_iam* iam, CborEncoder* encoder)
{
    CborEncoder array;

    NM_IAM_CBOR_ERROR_RETURN_EXCEPT_OOM(cbor_encoder_create_array(encoder, &array, CborIndefiniteLength));

    const char* s;
    NN_STRING_SET_FOREACH(s, &iam->notificationCategories) {
        NM_IAM_CBOR_ERROR_RETURN_EXCEPT_OOM(cbor_encode_text_stringz(&array, s));
    }

    return cbor_encoder_close_container(encoder, &array);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    if (!nm_iam_internal_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:ListNotificationCategories", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    size_t payloadSize;
    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, NULL, 0, 0);

        if (encode_categories(handler->iam, &encoder) != CborErrorOutOfMemory) {
            nabto_device_coap_error_response(request, 500, "Encoding error");
            return;
        }
        payloadSize = cbor_encoder_get_extra_bytes_needed(&encoder);
    }
    uint8_t* payload = nm_iam_calloc(1, payloadSize);
    if (payload == NULL) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        return;
    }

    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, payload, payloadSize, 0);

        if (encode_categories(handler->iam, &encoder) != CborNoError) {
            nabto_device_coap_error_response(request, 500, "Encoding error");
            return;
        }
    }

    nabto_device_coap_response_set_code(request, 205);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, payload, payloadSize);
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
    } else {
        nabto_device_coap_response_ready(request);
    }
    nm_iam_free(payload);
}
