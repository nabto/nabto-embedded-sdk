#ifndef _TCP_TUNNEL_SERVICES_H_
#define _TCP_TUNNEL_SERVICES_H_

#include <nn/vector.h>
#include <nn/string_map.h>

#include <nn/log.h>

#include <cjson/cJSON.h>

#include <stdint.h>

struct nm_fs;

struct tcp_tunnel_service {
    char* id;
    char* type;
    char* host;
    uint16_t port;
    struct nn_string_map metadata;
};

struct tcp_tunnel_service* tcp_tunnel_service_new();
void tcp_tunnel_service_free(struct tcp_tunnel_service* service);

bool load_tcp_tunnel_services(struct nn_vector* services, struct nm_fs* fsImpl, const char* servicesFile, struct nn_log* logger);
bool tcp_tunnel_create_default_services_file(struct nm_fs* fsImpl, const char* servicesFile);
cJSON* tcp_tunnel_service_as_json(struct tcp_tunnel_service* service);

struct nn_allocator* get_default_allocator();

#endif
