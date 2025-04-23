#ifndef NC_VIRTUAL_CONNECTION_H
#define NC_VIRTUAL_CONNECTION_H

#include <core/nc_connection_event.h>
#include <core/nc_device.h>
#include <nabto/nabto_device_config.h>
#include <platform/np_platform.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nc_virtual_connection {
    struct nc_connection* parent;
    uint8_t* deviceFingerprint;
    uint8_t* clientFingerprint;
    struct nn_llist coapRequests;
};

struct nc_connection* nc_virtual_connection_new(struct nc_device_context* device);

void nc_virtual_connection_destroy(struct nc_virtual_connection* conn);
void nc_virtual_connection_close(struct nc_virtual_connection* conn);

bool nc_virtual_connection_add_coap_request(struct nc_virtual_connection* conn, struct nc_coap_server_request* request);
bool nc_virtual_connection_remove_coap_request(struct nc_virtual_connection* conn, struct nc_coap_server_request* request);

np_error_code nc_virtual_connection_set_client_fingerprint(struct nc_virtual_connection* conn, uint8_t* fp);
np_error_code nc_virtual_connection_set_device_fingerprint(struct nc_virtual_connection* conn, uint8_t* fp);

bool nc_virtual_connection_get_client_fingerprint(struct nc_virtual_connection* conn, uint8_t* fp);
bool nc_virtual_connection_get_device_fingerprint(struct nc_virtual_connection* conn, uint8_t* fp);


#ifdef __cplusplus
} // extern c
#endif

#endif //_NC_CLIENT_CONNECTION_H_
