#ifndef NM_SELECT_UNIX_H
#define NM_SELECT_UNIX_H

#include <nabto_types.h>
#include <platform/np_udp.h>
#include <platform/np_platform.h>

#include <sys/select.h>

#include <modules/posix/nm_posix_udp.h>

#ifdef __cplusplus
extern "C" {
#endif


struct nm_select_unix_udp_recv_wait_context {
    struct np_completion_event* completionEvent;
};

struct np_udp_socket {
    struct np_platform* pl;
    struct nm_select_unix* selectCtx;
    struct nm_posix_udp_socket posixSocket;

    struct np_udp_socket* next;
    struct np_udp_socket* prev;
    bool aborted;
    bool destroyed;
    struct nm_select_unix_udp_recv_wait_context recv;
};

struct nm_select_unix_udp_sockets {
    struct np_platform* pl;
    struct np_udp_socket socketsSentinel;
};

struct nm_select_unix_tcp_connect_context {
    struct np_completion_event* completionEvent;
};

struct nm_select_unix_tcp_write_context {
    struct np_completion_event* completionEvent;
    const void* data;
    size_t dataLength;
};

struct nm_select_unix_tcp_read_context {
    struct np_completion_event* completionEvent;
    void* buffer;
    size_t bufferSize;
    size_t* readLength;
};

struct np_tcp_socket {
    struct np_tcp_socket* next;
    struct np_tcp_socket* prev;
    struct np_platform* pl;
    struct nm_select_unix* selectCtx;
    int fd;

    struct nm_select_unix_tcp_connect_context connect;
    struct nm_select_unix_tcp_write_context write;
    struct nm_select_unix_tcp_read_context read;

    bool destroyed;
    bool aborted;
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

/**
 * Functions used from the API
 */
np_error_code nm_select_unix_init(struct nm_select_unix* ctx, struct np_platform *pl);
void nm_select_unix_close(struct nm_select_unix* ctx);
void nm_select_unix_break_wait(struct nm_select_unix* ctx);

int nm_select_unix_timed_wait(struct nm_select_unix* ctx, uint32_t ms);
int nm_select_unix_inf_wait(struct nm_select_unix* ctx);

void nm_select_unix_read(struct nm_select_unix* ctx, int nfds);
bool nm_select_unix_finished(struct nm_select_unix* ctx);

/**
 * Functions only used internally in the module
 */

// notify select that something has changed in the filedescriptor sets
void nm_select_unix_notify(struct nm_select_unix* ctx);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NM_SELECT_UNIX_H
