#ifndef _NM_EPOLL_H_
#define _NM_EPOLL_H_

#include <platform/np_communication_buffer.h>


#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NM_EPOLL_EVENTS_SIZE 64

enum nm_epoll_type {
    NM_EPOLL_TYPE_UDP,
    NM_EPOLL_TYPE_TCP
};

struct nm_epoll_base {
    enum nm_epoll_type type;
    struct nm_epoll_base* next;
    struct nm_epoll_base* prev;
};

struct nm_epoll_context {
    int fd;
    struct np_platform* pl;
    np_communication_buffer* recvBuffer;
    struct epoll_event events[NM_EPOLL_EVENTS_SIZE];
    int pipeFd[2];
    size_t openUdpSockets;
    size_t openTcpSockets;
    struct nm_epoll_base closeSentinelData;
    struct nm_epoll_base* closeSentinel;
};

void nm_epoll_init(struct nm_epoll_context* epoll, struct np_platform* pl);
void nm_epoll_close(struct nm_epoll_context* epoll);
void nm_epoll_break_wait(struct nm_epoll_context* epoll);

int nm_epoll_timed_wait(struct nm_epoll_context* epoll, uint32_t ms);
int nm_epoll_inf_wait(struct nm_epoll_context* epoll);

void nm_epoll_read(struct nm_epoll_context* epoll, int nfds);
bool nm_epoll_finished(struct nm_epoll_context* epoll);

void nm_epoll_add_udp_socket(struct nm_epoll_context* epoll);
void nm_epoll_add_tcp_socket(struct nm_epoll_context* epoll);
void nm_epoll_remove_udp_socket(struct nm_epoll_context* epoll);
void nm_epoll_remove_tcp_socket(struct nm_epoll_context* epoll);

void nm_epoll_close_socket(struct nm_epoll_context* epoll, struct nm_epoll_base* base);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
