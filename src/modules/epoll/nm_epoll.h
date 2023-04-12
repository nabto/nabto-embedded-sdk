#ifndef _NM_EPOLL_H_
#define _NM_EPOLL_H_

#include <stdbool.h>

#include <platform/np_error_code.h>
#include <platform/np_ip_address.h>

#include <modules/event_queue/nm_event_queue.h>

#include <sys/epoll.h>
#include <pthread.h>

#define ERR_IS_EAGAIN(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#define ERR_IS_EXPECTED(e) ((e) == EADDRNOTAVAIL || (e) == ENETUNREACH || (e) == EAFNOSUPPORT || (e) == EHOSTUNREACH)
#define ERR_IS_EADDRINUSE(e) ((e) == EADDRINUSE)
#define ERR_TO_STRING(e) strerror(e)

enum nm_epoll_type {
    NM_EPOLL_TYPE_UDP,
    NM_EPOLL_TYPE_TCP,
    NM_EPOLL_TYPE_NOTIFY
};

struct received_ctx {
    struct np_completion_event* completionEvent;
};

struct nm_epoll_handle {
    enum nm_epoll_type epollType;
};

struct np_udp_socket {
    enum nm_epoll_type epollType;
    struct received_ctx recv;
    enum np_ip_address_type type;
    int sock;
    struct nm_epoll* impl;
    bool aborted;
    struct epoll_event epollEvent;
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
    enum nm_epoll_type epollType;
    struct nm_epoll* ctx;
    int fd;

    struct nm_select_unix_tcp_connect_context connect;
    struct nm_select_unix_tcp_write_context write;
    struct nm_select_unix_tcp_read_context read;

    bool destroyed;
    bool aborted;
    struct epoll_event epollEvent;
};

// create a socketpair which is used to notify epoll_wait about events from outside epoll fd's
struct nm_epoll_notify {
    enum nm_epoll_type epollType;
    int writeSocket;
    int readSocket;
};

struct nm_epoll {
    int epollFd;
    bool running;
    struct nabto_device_mutex* coreMutex;
    struct nabto_device_mutex* queueMutex;
    struct nm_event_queue eventQueue;
    struct np_timestamp ts;

    struct nm_epoll_notify notify;

    pthread_t thread;
};

np_error_code nm_epoll_init(struct nm_epoll* ctx, struct nabto_device_mutex* coreMutex, struct np_timestamp ts);

np_error_code nm_epoll_run(struct nm_epoll* ctx);

void nm_epoll_stop_blocking(struct nm_epoll* ctx);

void nm_epoll_deinit(struct nm_epoll* ctx);



/**
 * Get an object implementing the udp interface.
 */
struct np_udp nm_epoll_udp_get_impl(struct nm_epoll* ctx);

/**
 * Get an object implementing the tcp interface.
 */
struct np_tcp nm_epoll_tcp_get_impl(struct nm_epoll* ctx);

/**
 * Get an object implementing the event queue
 */
struct np_event_queue nm_epoll_event_queue_get_impl(struct nm_epoll* ctx);

struct nm_mdns_udp_bind nm_epoll_mdns_udp_bind_get_impl(struct nm_epoll* ctx);

int nm_epoll_udp_create_nonblocking_socket(int domain, int type);

void nm_epoll_udp_handle_event(struct np_udp_socket* socket, uint32_t events);

void nm_epoll_tcp_handle_event(struct np_tcp_socket* sock, uint32_t events);
        
void nm_epoll_notify_init(struct nm_epoll* epoll);

void nm_epoll_notify_deini(struct nm_epoll* epoll);

void nm_epoll_notify(struct nm_epoll* epoll);

// event queue handling
bool nm_epoll_event_queue_handle_event(struct nm_epoll* epoll);
bool nm_epoll_event_queue_get_next_timed_event(struct nm_epoll* epoll, int32_t* ms);

#endif
