#ifndef NM_SELECT_UNIX_H
#define NM_SELECT_UNIX_H

#include <api/nabto_device_threads.h>
#include <platform/np_platform.h>
#include <platform/np_types.h>

#include <sys/select.h>

#include <nn/llist.h>

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NM_SELECT_UNIX_INVALID_SOCKET (-1)

struct nm_select_unix_udp_recv_wait_context {
    struct np_completion_event* completionEvent;
};

struct np_udp_socket {
    struct nm_select_unix* selectCtx;
    int sock;
    enum np_ip_address_type type;

    struct nn_llist_node udpSocketsNode;
    bool aborted;
    struct nm_select_unix_udp_recv_wait_context recv;
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
    struct nn_llist_node tcpSocketsNode;
    struct nm_select_unix* selectCtx;
    int fd;

    struct nm_select_unix_tcp_connect_context connect;
    struct nm_select_unix_tcp_write_context write;
    struct nm_select_unix_tcp_read_context read;

    bool destroyed;
    bool aborted;
};

struct nm_select_unix {
    fd_set readFds;
    fd_set writeFds;
    int maxReadFd;
    int maxWriteFd;
    int pipefd[2];
    struct nn_llist udpSockets;
    struct nn_llist tcpSockets;

    pthread_t thread;
    // synchronize core thread and select thread access to the list of sockets.
    pthread_mutex_t mutex;
    bool stopped;
};

/**
 * Functions used from the API
 */
np_error_code nm_select_unix_init(struct nm_select_unix* ctx);
void nm_select_unix_deinit(struct nm_select_unix* ctx);

void nm_select_unix_run(struct nm_select_unix* ctx);
void nm_select_unix_stop(struct nm_select_unix* ctx);

void nm_select_unix_lock(struct nm_select_unix* ctx);
void nm_select_unix_unlock(struct nm_select_unix* ctx);

/**
 * Functions only used internally in the module
 */

// notify select that something has changed in the filedescriptor sets
void nm_select_unix_notify(struct nm_select_unix* ctx);

/**
 * Get implementations for the implemented modules.
 */

/**
 * Get an object implementing the udp interface.
 */
struct np_udp nm_select_unix_udp_get_impl(struct nm_select_unix* ctx);

/**
 * Get an object implementing the tcp interface.
 */
struct np_tcp nm_select_unix_tcp_get_impl(struct nm_select_unix* ctx);


#ifdef __cplusplus
} //extern "C"
#endif

#endif // NM_SELECT_UNIX_H
