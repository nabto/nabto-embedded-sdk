#ifndef _NM_TCPTUNNEL_H_
#define _NM_TCPTUNNEL_H_

struct nm_tcptunnel_connection {
    np_tcp_socket* socket;
    nabto_stream* stream;
};

struct nm_tcptunnel {
    char id[5];
    char host[33];
    uint16_t port;
};

struct nm_tcptunnels {
    int idCounter;
    struct nm_tcptunnel tunnels[]
};

void nm_tcptunnel_init();

#endif
