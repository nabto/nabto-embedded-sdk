#include "nm_iam_coap_handler.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_user.h"
#include <api/nabto_device_threads.h>
#include <nn/string_set.h>

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
    handler->iam = iam;
    handler->requestHandler = requestHandler;

    handler->future = nabto_device_future_new(device);
    handler->listener = nabto_device_listener_new(device);
    if (handler->future == NULL ||
        handler->listener == NULL)
    {
        nabto_device_future_free(handler->future);
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }

    NabtoDeviceError ec = nabto_device_coap_init_listener(device, handler->listener, method, paths);
        handler->device = device;
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
    }
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


enum nm_iam_cbor_error nm_iam_cbor_init_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
{
    uint16_t contentFormat = 0;
    NabtoDeviceError ec = 0;
    ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        return IAM_CBOR_INVALID_CONTENT_FORMAT;
    }
    void* payload = NULL;
    size_t payloadSize = 0;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        return IAM_CBOR_MISSING_PAYLOAD;
    }
    {
        CborError err = cbor_parser_init((const uint8_t*)payload, payloadSize, 0, parser, cborValue);
        if (err != CborNoError) {
            return IAM_CBOR_PARSING_ERROR;
        }
    }
    return IAM_CBOR_OK;
}

void nm_iam_cbor_send_error_response(NabtoDeviceCoapRequest* request, enum nm_iam_cbor_error ec)
{
    switch(ec) {
    case IAM_CBOR_INVALID_CONTENT_FORMAT:
        nabto_device_coap_error_response(request, 400, "Invalid Content Format");
    case IAM_CBOR_MISSING_PAYLOAD:
        nabto_device_coap_error_response(request, 400, "Missing payload");
    case IAM_CBOR_PARSING_ERROR:
        nabto_device_coap_error_response(request, 400, "CBOR parsing error");
    default:
        nabto_device_coap_error_response(request, 400, "Bad request");
    }
}


bool nm_iam_cbor_decode_string(CborValue* value, char** str)
{
    if (cbor_value_is_text_string(value)) {
        size_t nameLength = 0;
        CborError err = cbor_value_calculate_string_length(value, &nameLength);
        if (err != CborNoError) {
            return false;
        }
        if (nameLength < 1024) {
            *str = nm_iam_calloc(1, nameLength+1);
            if (*str == NULL) {
                return false;
            }
            size_t copySize = nameLength;
            if (cbor_value_copy_text_string(value, *str, &copySize, NULL) == CborNoError) {
                return true;
            }
            nm_iam_free(*str);
            *str = NULL;
        }
    } else if (cbor_value_is_null(value)) {
        *str = NULL;
        return true;
    }
    return false;
}

bool nm_iam_cbor_decode_string_set(CborValue* value, struct nn_string_set* set)
{
    if (!cbor_value_is_array(value)) {
        return false;
    }
    CborValue item;
    if (cbor_value_enter_container(value, &item) != CborNoError) {
        return false;
    }
    while(!cbor_value_at_end(&item)) {
        char* s = NULL;
        if (nm_iam_cbor_decode_string(&item, &s) && nn_string_set_insert(set, s)) {
            nm_iam_free(s);
        } else {
            nm_iam_free(s);
            return false;
        }
        if (cbor_value_advance(&item) != CborNoError) {
            return false;
        }
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
    if (cbor_value_map_find_value(map, key, &nameValue) != CborNoError) {
        return false;
    }
    return nm_iam_cbor_decode_string(&nameValue, str);
}

size_t nm_iam_cbor_encode_user(struct nm_iam_user* user, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;

    if (nm_iam_cbor_err_not_oom(cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength)) ||
        nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "Username")) ||
        nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, user->username))) {
        return 0;
    }

    if (user->displayName != NULL) {
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "DisplayName")) ||
            nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, user->displayName))) {
            return 0;
        }
    }

    if (user->role != NULL) {
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "Role")) ||
            nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, user->role))) {
            return 0;
        }
    }

    {
        char* legacyFp = NULL;
        CborEncoder array;


        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "Fingerprints")) ||
            nm_iam_cbor_err_not_oom(cbor_encoder_create_array(&map, &array, CborIndefiniteLength))) {
            return 0;
        }
        struct nm_iam_user_fingerprint* fp = NULL;
        NN_LLIST_FOREACH(fp, &user->fingerprints) {
            CborEncoder fpMap;

            if (nm_iam_cbor_err_not_oom(cbor_encoder_create_map(&array, &fpMap, CborIndefiniteLength)) ||
                nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&fpMap, "Fingerprint")) ||
                nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&fpMap, fp->fingerprint))) {
                return 0;
            }

            legacyFp = fp->fingerprint;
            if (fp->name != NULL) {
                if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&fpMap, "Name")) ||
                    nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&fpMap, fp->name))) {
                    return 0;
                }
            }
            if(nm_iam_cbor_err_not_oom(cbor_encoder_close_container(&array, &fpMap))) {
                return 0;
            }
        }
        if(nm_iam_cbor_err_not_oom(cbor_encoder_close_container(&map, &array))) {
            return 0;
        }
        if (legacyFp) {
            if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "Fingerprint")) ||
                nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, legacyFp))) {
                return 0;
            }
        }
    }

    if (user->sct != NULL) {
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "Sct")) ||
            nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, user->sct))) {
            return 0;
        }
    }

    if (user->fcmToken != NULL || user->fcmProjectId != NULL) {

        CborEncoder fcm;
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "Fcm")) ||
            nm_iam_cbor_err_not_oom(cbor_encoder_create_map(&map, &fcm, CborIndefiniteLength))) {
            return 0;
        }
        if (user->fcmToken != NULL) {
            if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&fcm, "Token")) ||
                nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&fcm, user->fcmToken))) {
                return 0;
            }
        }
        if (user->fcmProjectId != NULL) {
            if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&fcm, "ProjectId")) ||
                nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&fcm, user->fcmProjectId))) {
                return 0;
            }
        }
        if(nm_iam_cbor_err_not_oom(cbor_encoder_close_container(&map, &fcm))) {
            return 0;
        }
    }

    {
        CborEncoder array;
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "NotificationCategories")) ||
            nm_iam_cbor_err_not_oom(cbor_encoder_create_array(&map, &array, CborIndefiniteLength))) {
            return 0;
        }
        const char* c = NULL;
        NN_STRING_SET_FOREACH(c, &user->notificationCategories) {
            if(nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&array, c))) {
                return 0;
            }
        }
        if(nm_iam_cbor_err_not_oom(cbor_encoder_close_container(&map, &array))) {
            return 0;
        }
    }

    if (user->oauthSubject != NULL) {
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "OauthSubject")) ||
            nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, user->oauthSubject))) {
            return 0;
        }
    }

    if(nm_iam_cbor_err_not_oom(cbor_encoder_close_container(&encoder, &map))) {
        return 0;
    }

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}


bool nm_iam_cbor_err_not_oom(CborError e) {
    // Cbor errors can be bitwise or'ed with other errors
    return (e & ~CborErrorOutOfMemory) != CborNoError;
}
