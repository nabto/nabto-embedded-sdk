#ifndef _NM_IAM_COAP_HANDLER_H_
#define _NM_IAM_COAP_HANDLER_H_

#include <nabto/nabto_device.h>

#include <cbor.h>

struct nm_iam_coap_handler;

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
};

NabtoDeviceError nm_iam_coap_handler_init(
    struct nm_iam_coap_handler* handler,
    NabtoDevice* device,
    struct nm_iam* iam,
    NabtoDeviceCoapMethod method,
    const char** paths,
    nm_iam_coap_request_handler requestHandler);

void nm_iam_coap_handler_deinit(struct nm_iam_coap_handler* handler);

// specific handler init functions
NabtoDeviceError nm_iam_pairing_get_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_pairing_password_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_pairing_local_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_list_users_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_is_paired_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_client_settings_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

NabtoDeviceError nm_iam_get_me_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_get_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

NabtoDeviceError nm_iam_delete_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_list_roles_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);
NabtoDeviceError nm_iam_remove_role_from_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);

NabtoDeviceError nm_iam_add_role_to_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam);


// utility functions
bool nm_iam_cbor_init_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue);

bool nm_iam_cbor_decode_string(CborValue* value, char** str);
bool nm_iam_cbor_decode_kv_string(CborValue* map, const char* key, char** str);

// used from GET /iam/users/:user and GET /iam/me
size_t nm_iam_cbor_encode_user(struct nm_iam_user* user, void* buffer, size_t bufferSize);

#endif
