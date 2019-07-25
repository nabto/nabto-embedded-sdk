#ifndef _NM_MDNS_H_
#define _NM_MDNS_H_

#include <platform/np_platform.h>
#include <mdns/mdns_server.h>

// callback to the implementer of the module to get the current port
// number for the service. if the port number is 0 the answer is
// invalid.
typedef uint16_t(*nm_mdns_get_port)(void* userData);

struct nm_mdns {
    struct np_platform* pl;
    bool stopped;
    nm_mdns_get_port getPort;
    void* getPortUserData;
    struct nabto_mdns_server_context mdnsServer;
    np_udp_socket* socketv4;
    np_udp_socket* socketv6;
    struct nabto_mdns_ip_address mdnsIps[2];
    struct np_communication_buffer* sendBufferv4;
    struct np_communication_buffer* sendBufferv6;
    struct np_udp_send_context sendContextv4;
    struct np_udp_send_context sendContextv6;
};

void nm_mdns_init(struct nm_mdns* mdns, struct np_platform* pl, const char* productId, const char* deviceId, nm_mdns_get_port getPort, void* userData);

void nm_mdns_deinit(struct nm_mdns* mdns);

#endif
