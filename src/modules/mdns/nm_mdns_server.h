#ifndef _NM_MDNS_SERVER_H_
#define _NM_MDNS_SERVER_H_

#include <platform/np_logging.h>
#include <platform/np_completion_event.h>
#include <platform/np_udp_wrapper.h>
#include <platform/np_local_ip_wrapper.h>
#include <stdlib.h>

#include <platform/interfaces/np_mdns.h>
#include <platform/np_platform.h>

#include <mdns/mdns_server.h>

#define MDNS_MAX_LOCAL_IPS 2

struct nm_mdns_server {
    bool running;
    bool stopped;
    bool v4Done;
    bool v6Done;
    uint16_t port;
    struct nabto_mdns_server_context mdnsServer;
    struct np_udp_socket* socketv4;
    struct np_udp_socket* socketv6;
    struct nabto_mdns_ip_address localIps[MDNS_MAX_LOCAL_IPS];
    size_t localIpsSize;
    uint8_t sendBufferV4[1500];
    uint8_t sendBufferV6[1500];
    uint8_t recvBuffer[1500];

    struct np_event_queue eq;
    struct np_udp udp;
    struct np_local_ip localIp;



    struct np_completion_event v4OpenedCompletionEvent;
    struct np_completion_event v6OpenedCompletionEvent;
    struct np_completion_event v4RecvWaitCompletionEvent;
    struct np_completion_event v6RecvWaitCompletionEvent;
    struct np_completion_event v4SendCompletionEvent;
    struct np_completion_event v6SendCompletionEvent;
};

np_error_code nm_mdns_server_init(struct nm_mdns_server* server, struct np_event_queue* eq, struct np_udp* udp, struct np_local_ip* localIp);
void nm_mdns_server_deinit(struct nm_mdns_server* server);


struct np_mdns nm_mdns_server_get_impl(struct nm_mdns_server* server);


#endif
