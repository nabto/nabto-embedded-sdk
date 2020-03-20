#ifndef _TCP_TUNNEL_SERVICES_H_
#define _TCP_TUNNEL_SERVICES_H_

#include <platform/np_vector.h>

#include <stdint.h>



struct tcp_tunnel_service {
    char* id;
    char* type;
    char* host;
    uint16_t port;
};

struct tcp_tunnel_service* tcp_tunnel_service_new();
void tcp_tunnel_service_free(struct tcp_tunnel_service* service);

bool load_tcp_tunnel_services(struct np_vector* services, const char* servicesFile, const char** errorText);

#endif
