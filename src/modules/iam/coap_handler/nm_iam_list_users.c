#include "nm_iam_coap_handler.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_user.h"

#include "../nm_iam_allocator.h"



#include <tinycbor/cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_list_users_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

static size_t encode_users(struct nm_iam* iam, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder array;
    CborError ec = cbor_encoder_create_array(&encoder, &array, CborIndefiniteLength);
    if (ec != CborNoError) {
        return 0;
    }

    struct nn_llist* users = &iam->state->users;
    struct nm_iam_user* user = NULL;
    NN_LLIST_FOREACH(user, users) {
        ec = cbor_encode_text_stringz(&array, user->username);
        if (ec != CborNoError) {
            return 0;
        }
    }

    ec = cbor_encoder_close_container(&encoder, &array);
    if (ec != CborNoError) {
        return 0;
    }

     return cbor_encoder_get_extra_bytes_needed(&encoder);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    if (!nm_iam_internal_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:ListUsers", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    size_t payloadSize = encode_users(handler->iam, NULL, 0);
    uint8_t* payload = nm_iam_calloc(1, payloadSize);
    if (payload == NULL) {
        return;
    }

    encode_users(handler->iam, payload, payloadSize);

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
