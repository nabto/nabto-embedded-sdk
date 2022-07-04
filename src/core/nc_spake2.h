#ifndef _NC_SPAKE2_H_
#define _NC_SPAKE2_H_

#if defined(NABTO_DEVICE_ENABLE_PASSWORD_AUTHENTICATION)

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

#include <platform/np_error_code.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_spake2.h>
#include <platform/np_platform.h>
#include <coap/nabto_coap.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nabto_coap_server_request;
struct nabto_coap_server_resource;
struct nc_coap_server_context;

#define NC_SPAKE2_USERNAME_MAX_LENGTH 32
#define NC_SPAKE2_MAX_TOKENS 10
#define NC_SPAKE2_TOKEN_INTERVAL 1000 // ms
typedef np_error_code (*nc_spake2_password_request_handler)(struct nc_spake2_password_request* req, void* data);

struct nc_spake2_module {
    bool initialized;
    // if this is not set return 404.
    nc_spake2_password_request_handler passwordRequestHandler;
    void* passwordRequestHandlerData;

    struct nabto_coap_server_resource* spake21;
    struct nabto_coap_server_resource* spake22;
    size_t tokens;
    struct np_event* tbEvent;
    struct np_platform* pl;
};

void nc_spake2_init(struct nc_spake2_module* module, struct np_platform* pl);
void nc_spake2_deinit(struct nc_spake2_module* module);

np_error_code nc_spake2_coap_init(struct nc_spake2_module* module, struct nc_coap_server_context* coap);
void nc_spake2_coap_deinit(struct nc_spake2_module* module);

void nc_spake2_clear_password_request_callback(struct nc_spake2_module* module);
np_error_code nc_spake2_set_password_request_callback(struct nc_spake2_module* module, nc_spake2_password_request_handler passwordRequestFunction, void* data);

void nc_spake2_password_ready(struct nc_spake2_password_request* req, const char* password);

void nc_spake2_password_request_free(struct nc_spake2_password_request* passwordRequest);

struct nc_spake2_password_request* nc_spake2_password_request_new();

void nc_spake2_spend_token(struct nc_spake2_module* module);

#ifdef __cplusplus
} // extern "C"
#endif

#endif


#endif
