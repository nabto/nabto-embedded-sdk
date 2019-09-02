#ifndef _NM_TCPTUNNEL_H_
#define _NM_TCPTUNNEL_H_

#define NM_TCPTUNNEL_MAX_HOST_LENGTH 39;

struct nm_tcptunnel_connection {
    np_tcp_socket* socket;
    nabto_stream* stream;
};

struct nm_tcptunnel_connection_list_entry {
    struct nm_tcptunnel_connection_list_entry* next;
    struct nm_tcptunnel_connection_list_entry* prev;
    struct nm_tcptunnel_connection* connection;
};

struct nm_tcptunnel {
    char id[5]; // id to use in the CoAP api paths
    char host[NM_TCPTUNNEL_MAX_HOST_LENGTH+1]; // an ipv6 address is 32+7 long
    uint16_t port;
    struct nm_tcptunnel_connection_list_entry connectionsSentinel;
};

struct nm_tcptunnel_list_entry {
    struct nm_tcptunnel_list_entry* next;
    struct nm_tcptunnel_list_entry* prev;
    struct nm_tcptunnel* tunnel;
};

struct nm_tcptunnels {
    int idCounter;
    char defaultHost[NM_TCPTUNNEL_MAX_HOST_LENGTH+1];
    uint16_t defaultPort;
    struct nm_tcptunnel_list_entry tunnelsSentinel;
};

void nm_tcptunnel_init();

#endif
