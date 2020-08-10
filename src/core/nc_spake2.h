#ifndef _NC_SPAKE2_H_
#define _NC_SPAKE2_H_

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

#include <platform/np_error_code.h>
#include <coap/nabto_coap.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nabto_coap_server_request;
struct nabto_coap_server_resource;
struct nc_coap_server_context;

#define NC_SPAKE2_USERNAME_MAX_LENGTH 64
#define NC_SPAKE2_PASSWORD_MAX_LENGTH 64
#define NC_SPAKE2_MAX_PASSWORD_AUTHENTICATION_REQUESTS 6

/**
 * Coap req for the key exchange. The request comes in, a password is
 * found for the username and a response is generated.
 */
struct nc_spake2_password_request {
    // the username and T comes from the coap request.
    char username[NC_SPAKE2_USERNAME_MAX_LENGTH+1];
    mbedtls_ecp_point T;

    struct nabto_coap_server_request* coapRequest;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point point;
};

typedef np_error_code (*nc_spake2_password_request_handler)(struct nc_spake2_password_request* req, void* data);

struct nc_spake2_module {
    // if this is not set return 404.
    nc_spake2_password_request_handler passwordRequestHandler;
    void* passwordRequestHandlerData;

    struct nabto_coap_server_resource* spake21;
    struct nabto_coap_server_resource* spake22;
};

void nc_spake2_init(struct nc_spake2_module* module);
void nc_spake2_deinit(struct nc_spake2_module* module);

np_error_code nc_spake2_coap_init(struct nc_spake2_module* module, struct nc_coap_server_context* coap);
void nc_spake2_coap_deinit(struct nc_spake2_module* module);

void nc_spake2_clear_password_request_callback(struct nc_spake2_module* module);
np_error_code nc_spake2_set_password_request_callback(struct nc_spake2_module* module, nc_spake2_password_request_handler passwordRequestFunction, void* data);

int nc_spake2_password_to_mpi(const char* password, size_t passwordLength, mbedtls_mpi* w);

void nc_spake2_password_ready(struct nc_spake2_password_request* req, const char* password);

void nc_spake2_password_request_free(struct nc_spake2_password_request* passwordRequest);

struct nc_spake2_password_request* nc_spake2_password_request_new();




#ifdef __cplusplus
} // extern "C"
#endif



#endif
