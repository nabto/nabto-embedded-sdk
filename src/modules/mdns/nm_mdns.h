#ifndef _NM_MDNS_H_
#define _NM_MDNS_H_

#include <platform/np_platform.h>
#include <mdns/mdns_server.h>

typedef void (*nm_mdns_started)(const np_error_code ec, void* userData);

struct nm_mdns {
    struct np_platform* pl;
    bool stopped;
    nm_mdns_started cb;
    void* cbUserData;
    const char* productId;
    const char* deviceId;
    uint16_t port;
    struct nabto_mdns_server_context mdnsServer;
    np_udp_socket* socket;
    struct nabto_mdns_ip_address mdnsIps[2];
    struct np_communication_buffer* sendBuffer;
    struct np_udp_send_context sendContext;
};



void nm_mdns_init(struct nm_mdns* mdns, struct np_platform* pl, const char* productId, const char* deviceId, uint16_t port);

void nm_mdns_async_start(struct nm_mdns* mdns, nm_mdns_started cb, void* userData);

void nm_mdns_stop(struct nm_mdns* mdns);

#endif
