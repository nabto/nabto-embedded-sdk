#ifndef _NM_IAM_COAP_HANDLER_H_
#define _NM_IAM_COAP_HANDLER_H_

#include <nabto/nabto_device.h>

#include <cbor.h>

struct nm_iam_coap_handler;
struct nn_string_set;

typedef void (*nm_iam_coap_request_handler)(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

struct nm_iam;
struct nm_iam_user;

struct nm_iam_coap_handler {
    NabtoDevice* device;
    struct nm_iam* iam;
    NabtoDeviceFuture* future;
    NabtoDeviceListener* listener;
    NabtoDeviceCoapRequest* request;
    nm_iam_coap_request_handler requestHandler;
    bool async;
    bool asyncStopped;
    bool locked;
};

NabtoDeviceError nm_iam_coap_handler_init(
    struct nm_iam_coap_handler* handler,
    NabtoDevice* device,
    struct nm_iam* iam,
    NabtoDeviceCoapMethod method,
    const char** paths,
    nm_iam_coap_request_handler requestHandler);

// Async does currently only allow one request at a time. For more serious usage
// than the current POST /iam/users/{user}/fcm-test consider a redesign
void nm_iam_coap_handler_set_async(struct nm_iam_coap_handler* handler, bool async);
void nm_iam_coap_handler_async_request_end(struct nm_iam_coap_handler* handler);

void nm_iam_coap_handler_stop(struct nm_iam_coap_handler* handler);
void nm_iam_coap_handler_deinit(struct nm_iam_coap_handler* handler);

// specific handler init functions
NabtoDeviceError nm_iam_pairing_get_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_pairing_password_open_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_pairing_password_invite_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_pairing_local_open_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_pairing_local_initial_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

NabtoDeviceError nm_iam_get_notification_categories_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_send_fcm_test_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

NabtoDeviceError nm_iam_list_users_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_get_me_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_get_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_create_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

NabtoDeviceError nm_iam_delete_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_list_roles_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_set_user_role_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_set_user_username_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_set_user_display_name_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_set_user_fingerprint_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_set_user_sct_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_set_user_password_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_set_user_fcm_token_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_set_user_notification_categories_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_set_user_oauth_subject_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

NabtoDeviceError nm_iam_settings_set_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_settings_get_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_device_info_set_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

// utility functions
bool nm_iam_cbor_init_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue);

bool nm_iam_cbor_decode_string(CborValue* value, char** str);
bool nm_iam_cbor_decode_string_set(CborValue* value, struct nn_string_set* set);
bool nm_iam_cbor_decode_bool(CborValue* value, bool* b);
bool nm_iam_cbor_decode_kv_string(CborValue* map, const char* key, char** str);

// used from GET /iam/users/:user and GET /iam/me
size_t nm_iam_cbor_encode_user(struct nm_iam_user* user, void* buffer, size_t bufferSize);

#endif
