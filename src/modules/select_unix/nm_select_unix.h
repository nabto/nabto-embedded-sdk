#ifndef NM_SELECT_UNIX_H
#define NM_SELECT_UNIX_H

#include <nabto_types.h>
#include <platform/np_udp.h>
#include <platform/np_platform.h>

#include <sys/select.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_select_unix_created_ctx {
    np_udp_socket_created_callback cb;
    void* data;
    struct np_event event;
    uint16_t port;
};

struct nm_select_unix_destroyed_ctx {
    np_udp_socket_destroyed_callback cb;
    void* data;
    struct np_event event;
};

struct nm_select_unix_received_ctx {
    np_udp_packet_received_callback cb;
    void* data;
    struct np_event event;
};

struct np_udp_socket {
    struct np_platform* pl;
    struct nm_select_unix_udp_sockets* sockets;
    int sock;
    bool isIpv6;
    struct nm_select_unix_created_ctx created;
    struct nm_select_unix_destroyed_ctx des;
    struct nm_select_unix_received_ctx recv;
    struct np_udp_socket* next;
    struct np_udp_socket* prev;
    bool closing;
};

struct nm_select_unix_udp_sockets {
    struct np_platform* pl;
    struct np_udp_socket socketsSentinel;
    np_communication_buffer* recvBuf;
};

struct nm_select_tcp_connect_context {
    np_tcp_connect_callback callback;
    void* userData;
};

struct nm_select_unix_tcp_write_context {
    np_tcp_write_callback callback;
    void* userData;
    const void* data;
    size_t dataLength;
};

struct nm_select_unix_tcp_read_context {
    np_tcp_read_callback callback;
    void* userData;
    void* buffer;
    size_t bufferSize;
};

struct np_tcp_socket {
    struct np_tcp_socket* next;
    struct np_tcp_socket* prev;
    struct np_platform* pl;
    struct nm_select_unix* selectCtx;
    int fd;

    struct nm_select_unix_tcp_write_context write;
    struct nm_select_unix_tcp_read_context read;
    np_tcp_connect_callback connectCb;
    void* connectCbData;
    struct np_event connectEvent;

};

struct nm_select_unix_tcp_sockets {
    struct np_tcp_socket socketsSentinel;
};

struct nm_select_unix {
    struct np_platform* pl;
    fd_set readFds;
    fd_set writeFds;
    int maxReadFd;
    int maxWriteFd;
    int pipefd[2];
    struct nm_select_unix_udp_sockets udpSockets;
    struct nm_select_unix_tcp_sockets tcpSockets;
};

void nm_select_unix_init(struct nm_select_unix* ctx, struct np_platform *pl);

/** defined here for testing purposes **/
int nm_select_unix_inf_wait(struct nm_select_unix* ctx);
int nm_select_unix_timed_wait(struct nm_select_unix* ctx, uint32_t ms);
void nm_select_unix_read(struct nm_select_unix* ctx, int nfds);

void nm_select_unix_close(struct nm_select_unix* ctx);
void nm_select_unix_break_wait(struct nm_select_unix* ctx);

// notify select that something has changed in the filedescriptor sets
void nm_select_unix_notify(struct nm_select_unix* ctx);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NM_SELECT_UNIX_H
