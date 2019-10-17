#include "nm_epoll.h"
#include "nm_epoll_udp.h"
#include "nm_epoll_tcp.h"

#include <platform/np_logging.h>
#include <platform/np_communication_buffer.h>
#include <platform/np_platform.h>

#include <string.h>
#include <unistd.h>
#include <errno.h>

#define LOG NABTO_LOG_MODULE_NETWORK

void nm_epoll_init(struct nm_epoll_context* epoll, struct np_platform* pl)
{
    memset(epoll, 0, sizeof(struct nm_epoll_context));
    epoll->pl = pl;
    epoll->fd = epoll_create(42 /*unused*/);
    epoll->closeSentinel = &epoll->closeSentinelData;
    epoll->closeSentinel->next = epoll->closeSentinel;
    epoll->closeSentinel->prev = epoll->closeSentinel;
    if(pipe(epoll->pipeFd) == -1) {
        NABTO_LOG_ERROR(LOG, "Failed to create pipe file descriptors");
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLHUP;
    ev.data.ptr = NULL;
    if (epoll_ctl(epoll->fd, EPOLL_CTL_ADD, epoll->pipeFd[0], &ev) == -1) {
        NABTO_LOG_ERROR(LOG, "Cannot add fd to epoll");
    }

    if (epoll->fd == -1) {
        NABTO_LOG_FATAL(LOG, "Failed to create epoll socket: (%i) '%s'.", errno, strerror(errno));
    }

    epoll->recvBuffer = pl->buf.allocate();

    nm_epoll_udp_init(epoll, pl);
    nm_epoll_tcp_init(epoll, pl);
}


void nm_epoll_close(struct nm_epoll_context* epoll)
{
    struct np_platform* pl = epoll->pl;
    if (epoll_ctl(epoll->fd, EPOLL_CTL_DEL, epoll->pipeFd[0], NULL) == -1) {
        NABTO_LOG_ERROR(LOG,"Cannot remove fd from epoll set, %i: %s", errno, strerror(errno));
    }

    close(epoll->pipeFd[0]);
    close(epoll->pipeFd[1]);
    close(epoll->fd);
    pl->buf.free(epoll->recvBuffer);
}
void nm_epoll_break_wait(struct nm_epoll_context* epoll)
{
    write(epoll->pipeFd[1], "1", 1);
}

int nm_epoll_timed_wait(struct nm_epoll_context* epoll, uint32_t ms)
{
    int nfds;
    nfds = epoll_wait(epoll->fd, epoll->events, NM_EPOLL_EVENTS_SIZE, ms);
    if (nfds < 0) {
        NABTO_LOG_ERROR(LOG, "Error in epoll wait: (%i) '%s'", errno, strerror(errno));
    }
    return nfds;
}

int nm_epoll_inf_wait(struct nm_epoll_context* epoll)
{
    int nfds;
    nfds = epoll_wait(epoll->fd, epoll->events, NM_EPOLL_EVENTS_SIZE, -1);
    if (nfds < 0) {
        NABTO_LOG_ERROR(LOG, "Error in epoll wait: (%i) '%s'", errno, strerror(errno));
    }

    return nfds;
}

void nm_epoll_read(struct nm_epoll_context* epoll, int nfds)
{
    for (int i = 0; i < nfds; i++) {
        if ((epoll->events[i].events & EPOLLIN) ||
            (epoll->events[i].events & EPOLLOUT))
        {
            struct nm_epoll_base* base = (struct nm_epoll_base*)epoll->events[i].data.ptr;
            if (base != NULL) {
                if (base->type == NM_EPOLL_TYPE_UDP) {
                    nm_epoll_udp_handle_event((np_udp_socket*)base, epoll->events[i].events);
                } else if (base->type == NM_EPOLL_TYPE_TCP) {
                    nm_epoll_tcp_handle_event((np_tcp_socket*)base, epoll->events[i].events);
                }
            }
        }
    }
    struct nm_epoll_base* iterator = epoll->closeSentinel->next;
    while (iterator != epoll->closeSentinel) {
        struct nm_epoll_base* current = iterator;
        iterator = iterator->next;
        if (current->type == NM_EPOLL_TYPE_UDP) {
            current->prev->next = current->next;
            current->next->prev = current->prev;
            nm_epoll_udp_resolve_close(current);
        } else if (current->type == NM_EPOLL_TYPE_TCP) {
            // TODO tcp
            current->prev->next = current->next;
            current->next->prev = current->prev;
            nm_epoll_tcp_resolve_close(current);
        }
    }
}

bool nm_epoll_finished(struct nm_epoll_context* epoll)
{
    if (epoll->openUdpSockets > 0 || epoll->openTcpSockets > 0 ) {
        NABTO_LOG_TRACE(LOG, "Epoll not finished, UDP: %u, TCP: %u", epoll->openUdpSockets, epoll->openTcpSockets);
        return false;
    } else {
        return true;
    }
}

void nm_epoll_add_udp_socket(struct nm_epoll_context* epoll)
{
    epoll->openUdpSockets++;
}

void nm_epoll_add_tcp_socket(struct nm_epoll_context* epoll)
{
    epoll->openTcpSockets++;
}

void nm_epoll_remove_udp_socket(struct nm_epoll_context* epoll)
{
    epoll->openUdpSockets--;
}

void nm_epoll_remove_tcp_socket(struct nm_epoll_context* epoll)
{
    epoll->openTcpSockets--;
}

void nm_epoll_close_socket(struct nm_epoll_context* epoll, struct nm_epoll_base* base)
{
    struct nm_epoll_base* before = epoll->closeSentinel->prev;
    struct nm_epoll_base* after = epoll->closeSentinel;
    after->prev = base;
    before->next = base;
    base->next = after;
    base->prev = before;
}
