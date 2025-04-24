#ifndef NM_MDNS_SERVER_H_
#define NM_MDNS_SERVER_H_

#include "nm_mdns_udp_bind.h"

#include <platform/np_completion_event.h>
#include <platform/np_local_ip_wrapper.h>
#include <platform/np_logging.h>
#include <platform/np_udp_wrapper.h>


#include <platform/interfaces/np_mdns.h>
#include <platform/np_platform.h>

#include <nabto_mdns/nabto_mdns_server.h>

#define MDNS_MAX_LOCAL_IPS 2
#define NM_MDNS_SEND_BUFFER_SIZE 1500

enum nm_mdns_server_state {
    NEW,
    RUNNING,
    CLOSED,
    STOPPED
};

// v4 or v6 server
struct nm_mdns_server_instance {
    struct nm_mdns_server* server;
    struct np_udp_socket* socket;
    struct np_udp_endpoint sendEp;
    struct np_udp_endpoint recvEp;
    uint8_t* sendBuffer; // if non null then we are sending a packet.
    struct np_completion_event openedCompletionEvent;
    struct np_completion_event recvWaitCompletionEvent;
    struct np_completion_event sendCompletionEvent;
    // Set when closing the instance.
    struct np_completion_event* closeCompletionEvent;
};

struct nm_mdns_server {
    enum nm_mdns_server_state state;
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
    // This event is used when calling close on the instances.
    struct np_completion_event instanceCloseCompletionEvent;
    // This event is coming from the application calling close on the mdns
    // server.
    struct np_completion_event* closedCompletionEvent;
};

np_error_code nm_mdns_server_init(struct nm_mdns_server* server, struct np_event_queue* eq, struct np_udp* udp, struct nm_mdns_udp_bind* mdnsUdpBind, struct np_local_ip* localIp);

void nm_mdns_server_deinit(struct nm_mdns_server* server);

void nm_mdns_server_close(struct nm_mdns_server* server, struct np_completion_event* closedEvent);

void nm_mdns_server_stop(struct nm_mdns_server* server);

struct np_mdns nm_mdns_server_get_impl(struct nm_mdns_server* server);


#endif
