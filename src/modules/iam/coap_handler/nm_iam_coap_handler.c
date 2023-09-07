#include "nm_iam_coap_handler.h"
#include "../nm_iam_user.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include <nn/string_set.h>
#include <api/nabto_device_threads.h>

#include "../nm_iam_allocator.h"



static void start_listen(struct nm_iam_coap_handler* handler);
static void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);


NabtoDeviceError nm_iam_coap_handler_init(
    struct nm_iam_coap_handler* handler,
    NabtoDevice* device,
    struct nm_iam* iam,
    NabtoDeviceCoapMethod method,
    const char** paths,
    nm_iam_coap_request_handler requestHandler)
{
    memset(handler, 0, sizeof(struct nm_iam_coap_handler));
    handler->device = device;
    handler->iam = iam;
    handler->requestHandler = requestHandler;

    handler->future = nabto_device_future_new(device);
    handler->listener = nabto_device_listener_new(device);
    if (handler->future == NULL ||
        handler->listener == NULL)
    {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }

    NabtoDeviceError ec = nabto_device_coap_init_listener(device, handler->listener, method, paths);
    if (ec == NABTO_DEVICE_EC_OK) {
        start_listen(handler);
    }

    return ec;
}

void nm_iam_coap_handler_stop(struct nm_iam_coap_handler* handler)
{
    if (handler->device != NULL) {
        nabto_device_listener_stop(handler->listener);
    }
}

void nm_iam_coap_handler_deinit(struct nm_iam_coap_handler* handler)
{
    if (handler->device != NULL) {
        nabto_device_listener_stop(handler->listener);
        nabto_device_future_free(handler->future);
        nabto_device_listener_free(handler->listener);
        handler->device = NULL;
        handler->iam = NULL;
        handler->listener = NULL;
        handler->future = NULL;
    }
}

void start_listen(struct nm_iam_coap_handler* handler)
{
    nabto_device_listener_new_coap_request(handler->listener, handler->future, &handler->request);
    nabto_device_future_set_callback(handler->future, request_callback, handler);
}

void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    (void)future;
    struct nm_iam_coap_handler* handler = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    } else {
        struct nm_iam* iam = handler->iam;
        nabto_device_threads_mutex_lock(iam->mutex);
        handler->asyncStopped = false;
        handler->locked = true;
        handler->requestHandler(handler, handler->request);
        handler->locked = false;
        nabto_device_threads_mutex_unlock(iam->mutex);
        if (!handler->async || handler->asyncStopped) {
            nabto_device_coap_request_free(handler->request);
            nm_iam_internal_do_callbacks(handler->iam);
            start_listen(handler);
        }
    }
}

void nm_iam_coap_handler_set_async(struct nm_iam_coap_handler* handler, bool async)
{
    handler->async = async;
}

void nm_iam_coap_handler_async_request_end(struct nm_iam_coap_handler* handler)
{
    if (handler->locked) {
        handler->asyncStopped = true;
    } else {
        nabto_device_coap_request_free(handler->request);
        nm_iam_internal_do_callbacks(handler->iam);
        start_listen(handler);
    }
}


bool nm_iam_cbor_init_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
{
    uint16_t contentFormat;
    NabtoDeviceError ec;
    ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        nabto_device_coap_error_response(request, 400, "Invalid Content Format");
        return false;
    }
    void* payload;
    size_t payloadSize;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 400, "Missing payload");
        return false;
    }
    cbor_parser_init((const uint8_t*)payload, payloadSize, 0, parser, cborValue);
    return true;
}


bool nm_iam_cbor_decode_string(CborValue* value, char** str)
{
    if (cbor_value_is_text_string(value)) {
        size_t nameLength;
        cbor_value_calculate_string_length (value, &nameLength);
        if (nameLength < 1024) {
            *str = nm_iam_calloc(1, nameLength+1);
            if (*str == NULL) {
                return false;
            }
            size_t copySize = nameLength;
            if (cbor_value_copy_text_string (value, *str, &copySize, NULL) == CborNoError) {
                return true;
            }
        }
    }
    return false;
}

bool nm_iam_cbor_decode_string_set(CborValue* value, struct nn_string_set* set)
{
    if (!cbor_value_is_array(value)) {
        return false;
    }
    CborValue item;
    cbor_value_enter_container(value, &item);
    while(!cbor_value_at_end(&item)) {
        char* s = NULL;
        if (nm_iam_cbor_decode_string(&item, &s) && nn_string_set_insert(set, s)) {
            nm_iam_free(s);
        } else {
            nm_iam_free(s);
            return false;
        }
        cbor_value_advance(&item);
    }
    return true;
}

bool nm_iam_cbor_decode_bool(CborValue* value, bool* b)
{
    if (cbor_value_is_boolean(value)) {
        CborError ec = cbor_value_get_boolean(value, b);
        if (ec == CborNoError)  {
            return true;
        }
    }
    return false;
}

bool nm_iam_cbor_decode_kv_string(CborValue* map, const char* key, char** str)
{
    if (!cbor_value_is_map(map)) {
        return false;
    }
    CborValue nameValue;
    cbor_value_map_find_value(map, key, &nameValue);
    return nm_iam_cbor_decode_string(&nameValue, str);
}

size_t nm_iam_cbor_encode_user(struct nm_iam_user* user, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "Username");
    cbor_encode_text_stringz(&map, user->username);

    if (user->displayName != NULL) {
        cbor_encode_text_stringz(&map, "DisplayName");
        cbor_encode_text_stringz(&map, user->displayName);
    }

    if (user->role != NULL) {
        cbor_encode_text_stringz(&map, "Role");
        cbor_encode_text_stringz(&map, user->role);
    }

    if (user->fingerprint != NULL) {
        cbor_encode_text_stringz(&map, "Fingerprint");
        cbor_encode_text_stringz(&map, user->fingerprint);
    }

    if (user->sct != NULL) {
        cbor_encode_text_stringz(&map, "Sct");
        cbor_encode_text_stringz(&map, user->sct);
    }

    if (user->fcmToken != NULL || user->fcmProjectId != NULL) {

        cbor_encode_text_stringz(&map, "Fcm");
        CborEncoder fcm;
        cbor_encoder_create_map(&map, &fcm, CborIndefiniteLength);
        if (user->fcmToken != NULL) {
            cbor_encode_text_stringz(&fcm, "Token");
            cbor_encode_text_stringz(&fcm, user->fcmToken);
        }
        if (user->fcmProjectId != NULL) {
            cbor_encode_text_stringz(&fcm, "ProjectId");
            cbor_encode_text_stringz(&fcm, user->fcmProjectId);
        }
        cbor_encoder_close_container(&map, &fcm);
    }

    {
        cbor_encode_text_stringz(&map, "NotificationCategories");
        CborEncoder array;
        cbor_encoder_create_array(&map, &array, CborIndefiniteLength);
        const char* c;
        NN_STRING_SET_FOREACH(c, &user->notificationCategories) {
            cbor_encode_text_stringz(&array, c);
        }
        cbor_encoder_close_container(&map, &array);
    }

    if (user->oauthSubject != NULL) {
        cbor_encode_text_stringz(&map, "OauthSubject");
        cbor_encode_text_stringz(&map, user->oauthSubject);
    }

    cbor_encoder_close_container(&encoder, &map);

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}
