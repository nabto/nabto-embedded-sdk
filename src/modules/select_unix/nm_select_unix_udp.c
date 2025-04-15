#include "nm_select_unix_udp.h"

#include <platform/np_logging.h>
#include <platform/np_util.h>
#include <platform/np_completion_event.h>
#include <platform/np_allocator.h>



#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#define LOG NABTO_LOG_MODULE_UDP

/**
 * Helper function declarations
 */
static void nm_select_unix_udp_handle_event(struct np_udp_socket* sock);
static void nm_select_unix_udp_free_socket(struct np_udp_socket* sock);

/**
 * Api function declarations
 */
static np_error_code nm_select_unix_udp_create(struct np_udp* obj, struct np_udp_socket** sock);
static void nm_select_unix_udp_destroy(struct np_udp_socket* sock);
static void nm_select_unix_udp_abort(struct np_udp_socket* sock);
static void nm_select_unix_udp_async_bind_port(struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent);
static void nm_select_unix_udp_async_send_to(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                             uint8_t* buffer, uint16_t bufferSize,
                                             struct np_completion_event* completionEvent);
static void nm_select_unix_udp_async_recv_wait(struct np_udp_socket* socket, struct np_completion_event* completionEvent);
static np_error_code nm_select_unix_udp_recv_from(struct np_udp_socket* socket, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength);
static uint16_t nm_select_unix_udp_get_local_port(struct np_udp_socket* socket);

static np_error_code udp_send_to(struct np_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize);
static np_error_code udp_recv_from(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength);
static np_error_code bind_port(struct np_udp_socket* s, uint16_t port);
static uint16_t get_local_port(struct np_udp_socket* s);
static np_error_code create_socket_any(struct np_udp_socket* s);



static struct np_udp_functions module = {
    .create           = &nm_select_unix_udp_create,
    .destroy          = &nm_select_unix_udp_destroy,
    .abort            = &nm_select_unix_udp_abort,
    .async_bind_port  = &nm_select_unix_udp_async_bind_port,
    .async_send_to    = &nm_select_unix_udp_async_send_to,
    .async_recv_wait  = &nm_select_unix_udp_async_recv_wait,
    .recv_from        = &nm_select_unix_udp_recv_from,
    .get_local_port   = &nm_select_unix_udp_get_local_port
};


struct np_udp nm_select_unix_udp_get_impl(struct nm_select_unix* ctx)
{
    struct np_udp obj;
    obj.mptr = &module;
    obj.data = ctx;
    return obj;
}

np_error_code nm_select_unix_udp_create(struct np_udp* obj, struct np_udp_socket** sock)
{
    struct np_udp_socket* s = np_calloc(1, sizeof(struct np_udp_socket));
    if (!s) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    *sock = s;
    s->sock = NM_SELECT_UNIX_INVALID_SOCKET;

    struct nm_select_unix* selectCtx = obj->data;

    s->selectCtx = selectCtx;
    s->aborted = false;

    nm_select_unix_lock(selectCtx);
    nn_llist_append(&selectCtx->udpSockets, &s->udpSocketsNode, s);
    nm_select_unix_unlock(selectCtx);

    // add fd to select fd set.
    nm_select_unix_notify(selectCtx);

    return NABTO_EC_OK;
}

np_error_code nm_select_unix_udp_async_bind_port_ec(struct np_udp_socket* sock, uint16_t port)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec;

    ec = create_socket_any(sock);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = bind_port(sock, port);
    if (ec != NABTO_EC_OK) {
        close(sock->sock);
    }

    return ec;
}

void nm_select_unix_udp_async_bind_port(struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent)
{
    np_error_code ec = nm_select_unix_udp_async_bind_port_ec(sock, port);
    np_completion_event_resolve(completionEvent, ec);
}


np_error_code nm_select_unix_udp_async_send_to_ec(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                                  uint8_t* buffer, uint16_t bufferSize)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "send to called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    return udp_send_to(sock, ep, buffer, bufferSize);
}

void nm_select_unix_udp_async_send_to(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                      uint8_t* buffer, uint16_t bufferSize,
                                      struct np_completion_event* completionEvent)
{
    np_error_code ec = nm_select_unix_udp_async_send_to_ec(sock, ep, buffer, bufferSize);
    np_completion_event_resolve(completionEvent, ec);
}


void nm_select_unix_udp_async_recv_wait(struct np_udp_socket* sock,
                                        struct np_completion_event* completionEvent)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "recv from called on aborted socket");
        np_completion_event_resolve(completionEvent, NABTO_EC_ABORTED);
        return;
    }

    if (sock->recv.completionEvent != NULL) {
        NABTO_LOG_ERROR(LOG, "operation already in progress");
        np_completion_event_resolve(completionEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }

    sock->recv.completionEvent = completionEvent;
    nm_select_unix_notify(sock->selectCtx);
    return;
}

np_error_code nm_select_unix_udp_recv_from(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength)
{
    return udp_recv_from(sock, ep, buffer, bufferSize, readLength);
}

uint16_t nm_select_unix_udp_get_local_port(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "get local port called on aborted socket");
        return 0;
    }
    return get_local_port(sock);
}

void nm_select_unix_udp_abort(struct np_udp_socket* sock)
{
    if (!sock->aborted) {
        sock->aborted = true;
    }

    if (sock->recv.completionEvent != NULL) {
        struct np_completion_event* ev = sock->recv.completionEvent;
        sock->recv.completionEvent = NULL;
        np_completion_event_resolve(ev, NABTO_EC_ABORTED);
    }
}

void nm_select_unix_udp_destroy(struct np_udp_socket* sock)
{
    if (sock == NULL) {
        return;
    }
    nm_select_unix_udp_free_socket(sock);
    return;
}

void nm_select_unix_udp_handle_event(struct np_udp_socket* sock)
{
    if (sock->recv.completionEvent != NULL) {
        struct np_completion_event* ev = sock->recv.completionEvent;
        sock->recv.completionEvent = NULL;
        np_completion_event_resolve(ev, NABTO_EC_OK);
    }
}

void nm_select_unix_udp_free_socket(struct np_udp_socket* sock)
{
    nm_select_unix_lock(sock->selectCtx);
    nn_llist_erase_node(&sock->udpSocketsNode);
    nm_select_unix_unlock(sock->selectCtx);

    nm_select_unix_udp_abort(sock);
    shutdown(sock->sock, SHUT_RDWR);
    close(sock->sock);
    np_free(sock);
}

void nm_select_unix_udp_build_fd_sets(struct nm_select_unix* ctx)
{
    struct np_udp_socket* s;
    nm_select_unix_lock(ctx);
    NN_LLIST_FOREACH(s, &ctx->udpSockets)
    {
        if (s->recv.completionEvent && s->sock != NM_SELECT_UNIX_INVALID_SOCKET) {
            FD_SET(s->sock, &ctx->readFds);
            ctx->maxReadFd = NP_MAX(ctx->maxReadFd, s->sock);
        }
    }
    nm_select_unix_unlock(ctx);
}

void nm_select_unix_udp_handle_select(struct nm_select_unix* ctx, int nfds)
{
    (void)nfds;
    struct np_udp_socket* s;

    nm_select_unix_lock(ctx);
    NN_LLIST_FOREACH(s, &ctx->udpSockets)
    {
        if (s->sock != NM_SELECT_UNIX_INVALID_SOCKET && FD_ISSET(s->sock, &ctx->readFds)) {
            nm_select_unix_udp_handle_event(s);
        }
    }
    nm_select_unix_unlock(ctx);
}


int nm_select_unix_udp_nonblocking_socket(int domain, int type)
{
#if defined(SOCK_NONBLOCK)
    return socket(domain, type | SOCK_NONBLOCK, 0);
#elif defined(F_GETFL)
    int sock = socket(domain, type, 0);
    if (sock == NM_SELECT_UNIX_INVALID_SOCKET) {
        NABTO_LOG_ERROR(LOG, "Cannot create UDP socket.");
        return NM_SELECT_UNIX_INVALID_SOCKET;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        NABTO_LOG_ERROR(LOG, "Cannot get flags for UDP socket.");
        close(sock);
        return NM_SELECT_UNIX_INVALID_SOCKET;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        NABTO_LOG_ERROR(LOG, "Cannot set socket to nonblocking mode.");
        close(sock);
        return NM_SELECT_UNIX_INVALID_SOCKET;
    }
    return sock;
#else
    #error Cannot create a nonblocking socket.
#endif
}

np_error_code udp_send_to(struct np_udp_socket* s, const struct np_udp_endpoint* ep, const uint8_t* buffer, uint16_t bufferSize)
{
    ssize_t res;

    struct np_ip_address sendIp;

    if (s->type == ep->ip.type) {
        // No conversion needed.
        sendIp = ep->ip;
    } else if (s->type == NABTO_IPV6 && ep->ip.type == NABTO_IPV4) {
        // convert ipv4 to ipv6 mapped ipv4
        np_ip_convert_v4_to_v4_mapped(&ep->ip, &sendIp);
    } else if (s->type == NABTO_IPV4 && np_ip_is_v4_mapped(&ep->ip)) {
        np_ip_convert_v4_mapped_to_v4(&ep->ip, &sendIp);
    } else {
        NABTO_LOG_TRACE(LOG, "Cannot send ipv6 packets on an ipv4 socket.");
        return NABTO_EC_FAILED;
    }

    NABTO_LOG_TRACE(LOG, "Sending packet of size %d, to %s:%d", bufferSize, np_ip_address_to_string(&sendIp), ep->port);
    if (sendIp.type == NABTO_IPV4) {
        struct sockaddr_in srv_addr;
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons (ep->port);
        memcpy((void*)&srv_addr.sin_addr, sendIp.ip.v4, sizeof(srv_addr.sin_addr));
        res = sendto (s->sock, buffer, bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    } else { // IPv6
        struct sockaddr_in6 srv_addr;
        srv_addr.sin6_family = AF_INET6;
        srv_addr.sin6_flowinfo = 0;
        srv_addr.sin6_scope_id = 0;
        srv_addr.sin6_port = htons (ep->port);
        memcpy((void*)&srv_addr.sin6_addr,sendIp.ip.v6, sizeof(srv_addr.sin6_addr));
        res = sendto (s->sock, buffer, bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    }

    if (res < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
            // just drop the packet and the upper layers will take care of retransmissions.
            NABTO_LOG_TRACE(LOG, "UDP sendto returned an expected error status (%i) '%s'", status, strerror(status));
            return NABTO_EC_OK;
        } else if (status == EADDRNOTAVAIL || // if we send to ipv6 scopes we do not have
                   status == ENETUNREACH || // if we send ipv6 on a system without it.
                   status == EAFNOSUPPORT) // if we send ipv6 on an ipv4 only socket
        {
            NABTO_LOG_TRACE(LOG,"UDP sendto could not send the packet but the error was expected on some systems. (%i) '%s'", status, strerror(status));
        } else {
            NABTO_LOG_ERROR(LOG,"UDP sendto could not send the packet. (%i) '%s'", status, strerror(status));
        }
        return NABTO_EC_FAILED_TO_SEND_PACKET;
    }

    if (res >= 0 && res < (ssize_t)bufferSize) {
        NABTO_LOG_WARN(LOG, "sendto sent less bytes than expected.");
    }

    return NABTO_EC_OK;
}

np_error_code udp_recv_from(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength)
{
    ssize_t recvLength;
    if (sock->type == NABTO_IPV6) {
        struct sockaddr_in6 sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, buffer, bufferSize, 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep->ip.ip.v6, &sa.sin6_addr.s6_addr, sizeof(ep->ip.ip.v6));
        ep->port = ntohs(sa.sin6_port);
        ep->ip.type = NABTO_IPV6;
    } else {
        struct sockaddr_in sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, buffer, bufferSize, 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep->ip.ip.v4, &sa.sin_addr.s_addr, sizeof(ep->ip.ip.v4));
        ep->port = ntohs(sa.sin_port);
        ep->ip.type = NABTO_IPV4;
    }
    if (recvLength < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
            // wait for next event to check for data.
            return NABTO_EC_AGAIN;
        }
        NABTO_LOG_ERROR(LOG,"ERROR: (%d) '%s' in udp_recv_from", status, strerror(status));
        return NABTO_EC_UDP_SOCKET_ERROR;
    }
    *readLength = recvLength;
    return NABTO_EC_OK;
}

np_error_code bind_port(struct np_udp_socket* s, uint16_t port)
{
    int status;

    if (s->type == NABTO_IPV6) {
        struct sockaddr_in6 si_me6;
        memset(&si_me6, 0, sizeof(si_me6));
        si_me6.sin6_family = AF_INET6;
        si_me6.sin6_port = htons(port);
        si_me6.sin6_addr = in6addr_any;
        status = bind(s->sock, (struct sockaddr*)&si_me6, sizeof(si_me6));
    } else {
        struct sockaddr_in si_me;
        memset(&si_me, 0, sizeof(si_me));
        si_me.sin_family = AF_INET;
        si_me.sin_port = htons(port);
        si_me.sin_addr.s_addr = INADDR_ANY;
        status = bind(s->sock, (struct sockaddr*)&si_me, sizeof(si_me));
    }

    if (status == 0) {
        return NABTO_EC_OK;
    }
    int bindErrno = errno;
    NABTO_LOG_ERROR(LOG, "UDP bind failed. (%i) '%s'", bindErrno, strerror(bindErrno));
    return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
}

uint16_t get_local_port(struct np_udp_socket* s)
{
    if (s->type == NABTO_IPV6) {
        struct sockaddr_in6 addr;
        addr.sin6_port = 0;
        socklen_t length = sizeof(struct sockaddr_in6);
        // TODO handle errors
        getsockname(s->sock, (struct sockaddr*)(&addr), &length);
        return htons(addr.sin6_port);
    }
    struct sockaddr_in addr;
    addr.sin_port = 0;
    socklen_t length = sizeof(struct sockaddr_in);
    // TODO handle errors
    getsockname(s->sock, (struct sockaddr*)(&addr), &length);
    return htons(addr.sin_port);
}

np_error_code create_socket_any(struct np_udp_socket* s)
{
    int sock = nm_select_unix_udp_nonblocking_socket(AF_INET6, SOCK_DGRAM);
    if (sock == NM_SELECT_UNIX_INVALID_SOCKET) {
        sock = nm_select_unix_udp_nonblocking_socket(AF_INET, SOCK_DGRAM);
        if (s->sock == NM_SELECT_UNIX_INVALID_SOCKET) {
            int e = errno;
            NABTO_LOG_ERROR(LOG, "Unable to create socket: (%i) '%s'.", e, strerror(e));
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        }
        NABTO_LOG_WARN(LOG, "IPv4 socket opened since IPv6 socket creation failed");
        s->type = NABTO_IPV4;
    } else {
        int no = 0;
        s->type = NABTO_IPV6;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no)))
        {
            int e = errno;
            NABTO_LOG_ERROR(LOG,"Unable to set option: (%i) '%s'.", e, strerror(e));

            close(s->sock);
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        }
    }
    s->sock = sock;
    return NABTO_EC_OK;
}
