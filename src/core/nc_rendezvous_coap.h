#ifndef NC_RENDEZVOUS_COAP_H_
#define NC_RENDEZVOUS_COAP_H_

#include <platform/np_error_code.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nc_coap_server_context;
struct nc_rendezvous_context;
struct np_platform;


struct nc_rendezvous_coap_context {
    struct nc_coap_server_context* coap;
    struct nc_rendezvous_context* rendezvous;

    struct nc_coap_server_resource* resource;
};


np_error_code nc_rendezvous_coap_init(struct nc_rendezvous_coap_context* context, struct nc_coap_server_context* coap, struct nc_rendezvous_context* rendezvous);

void nc_rendezvous_coap_deinit(struct nc_rendezvous_coap_context* context);
#ifdef __cplusplus
} // extern c
#endif

#endif
