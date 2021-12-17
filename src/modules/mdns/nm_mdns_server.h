#ifndef _NM_MDNS_SERVER_H_
#define _NM_MDNS_SERVER_H_

#include "nm_mdns_udp_bind.h"

#include <platform/np_logging.h>
#include <platform/np_completion_event.h>
#include <platform/np_udp_wrapper.h>
#include <platform/np_local_ip_wrapper.h>


#include <platform/interfaces/np_mdns.h>
#include <platform/np_platform.h>

#include <mdns/mdns_server.h>

#define MDNS_MAX_LOCAL_IPS 2

// v4 or v6 server
struct nm_mdns_server_instance {
    struct nm_mdns_server* server;
    bool sending;
    struct np_udp_socket* socket;
    struct np_udp_endpoint sendEp;
    struct np_udp_endpoint recvEp;
    uint8_t sendBuffer[1500];
    uint8_t recvBuffer[1500];
    struct np_completion_event openedCompletionEvent;
    struct np_completion_event recvWaitCompletionEvent;
    struct np_completion_event sendCompletionEvent;
};

struct nm_mdns_server {
    bool running;
    bool stopped;
    uint16_t port;
    struct nabto_mdns_server_context mdnsServer;
    struct nn_ip_address localIps[MDNS_MAX_LOCAL_IPS];
    size_t localIpsSize;

    struct np_event_queue eq;
    struct np_udp udp;
    struct nm_mdns_udp_bind mdnsUdpBind;
    struct np_local_ip localIp;

    struct nm_mdns_server_instance v4;
    struct nm_mdns_server_instance v6;
};

np_error_code nm_mdns_server_init(struct nm_mdns_server* server, struct np_event_queue* eq, struct np_udp* udp, struct nm_mdns_udp_bind* mdnsUdpBind, struct np_local_ip* localIp);

void nm_mdns_server_deinit(struct nm_mdns_server* server);

void nm_mdns_server_stop(struct nm_mdns_server* mdns);

struct np_mdns nm_mdns_server_get_impl(struct nm_mdns_server* server);


#endif
