#include "nm_iam_coap_handler.h"
#include "nm_iam_user.h"
#include "nm_iam.h"

#include <nn/vector.h>

#include <stdlib.h>

#include <cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_get_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", "{user}", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

static size_t encode_user(struct nm_iam_user* user, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "Id");
    cbor_encode_text_stringz(&map, user->id);

    if (!nn_string_set_empty(&user->roles)) {
        cbor_encode_text_stringz(&map, "Roles");
        CborEncoder array;
        cbor_encoder_create_array(&map, &array, CborIndefiniteLength);
        const char* r;
        NN_STRING_SET_FOREACH(r, &user->roles) {
            cbor_encode_text_stringz(&array, r);
        }
        cbor_encoder_close_container(&map, &array);
    }
    if (user->fingerprint != NULL) {
        cbor_encode_text_stringz(&map, "Fingerprint");
        cbor_encode_text_stringz(&map, user->fingerprint);
    }

    if (!nn_string_map_empty(&user->attributes)) {
        cbor_encode_text_stringz(&map, "Attributes");
        CborEncoder o;
        cbor_encoder_create_map(&map, &o, CborIndefiniteLength);

        struct nn_string_map_iterator it;
        for (it = nn_string_map_begin(&user->attributes); !nn_string_map_is_end(&it); nn_string_map_next(&it)) {
            cbor_encode_text_stringz(&o, nn_string_map_key(&it));
            cbor_encode_text_stringz(&o, nn_string_map_value(&it));
        }

        cbor_encoder_close_container(&map, &o);
    }

    cbor_encoder_close_container(&encoder, &map);

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    const char* userId = nabto_device_coap_request_get_parameter(request, "user");
    if (userId == NULL) {
        nabto_device_coap_error_response(request, 500, NULL);
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes);
    nn_string_map_insert(&attributes, "IAM:UserId", userId);

    if (!nm_iam_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:GetUser", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    struct nm_iam_user* user = nm_iam_find_user(handler->iam, userId);
    if (user == NULL) {
        nabto_device_coap_error_response(request, 404, NULL);
        return;
    }

    size_t payloadSize = encode_user(user, NULL, 0);
    uint8_t* payload = malloc(payloadSize);
    if (payload == NULL) {
        return;
    }

    encode_user(user, payload, payloadSize);

    nabto_device_coap_response_set_code(request, 205);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, payload, payloadSize);
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
    } else {
        nabto_device_coap_response_ready(request);
    }
    free(payload);
}
