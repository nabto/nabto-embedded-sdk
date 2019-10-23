#include "nm_select_unix_udp.h"

#include <platform/np_logging.h>
#include <platform/np_util.h>

#include <modules/unix/nm_unix_mdns.h>

#include <stdlib.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#define LOG NABTO_LOG_MODULE_UDP

static const struct np_udp_endpoint emptyEp;

/**
 * Helper function declarations
 */
static void nm_select_unix_udp_cancel_all_events(np_udp_socket* sock);
static void nm_select_unix_udp_event_bind_port(void* data);
static void nm_select_unix_udp_event_send_to(void* data);
static np_error_code nm_select_unix_udp_create_socket(np_udp_socket* sock);
static void nm_select_unix_udp_handle_event(np_udp_socket* sock);
static void nm_select_unix_udp_free_socket(np_udp_socket* sock);
static void nm_select_unix_udp_event_bind_mdns_ipv4(void* data);
static void nm_select_unix_udp_event_bind_mdns_ipv6(void* data);
static void nm_select_unix_udp_add_send_base(np_udp_socket* sock, struct nm_select_unix_udp_send_base* base);
static void nm_select_unix_udp_remove_send_base(np_udp_socket* sock, struct nm_select_unix_udp_send_base* base);

/**
 * Api function declarations
 */
static np_error_code nm_select_unix_udp_create(struct np_platform* pl, np_udp_socket** sock);
static void nm_select_unix_udp_destroy(np_udp_socket* sock);
static np_error_code nm_select_unix_udp_abort(np_udp_socket* sock);
static np_error_code nm_select_unix_udp_async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data);
static np_error_code nm_select_unix_async_bind_mdns_ipv4(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);
static np_error_code nm_select_unix_async_bind_mdns_ipv6(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data);
static np_error_code nm_select_unix_udp_async_send_to(np_udp_socket* sock, struct np_udp_endpoint ep,
                                                      uint8_t* buffer, uint16_t bufferSize,
                                                      np_udp_packet_sent_callback cb, void* userData);
static np_error_code nm_select_unix_udp_async_recv_from(np_udp_socket* socket,
                                                        np_udp_packet_received_callback cb, void* data);
static enum np_ip_address_type nm_select_unix_udp_get_protocol(np_udp_socket* socket);
static uint16_t nm_select_unix_udp_get_local_port(np_udp_socket* socket);
static size_t nm_select_unix_udp_get_local_ip( struct np_ip_address *addrs, size_t addrsSize);

void nm_select_unix_udp_init(struct nm_select_unix* ctx, struct np_platform *pl)
{
    struct nm_select_unix_udp_sockets* sockets = &ctx->udpSockets;
    pl->udp.create           = &nm_select_unix_udp_create;
    pl->udp.destroy          = &nm_select_unix_udp_destroy;
    pl->udp.abort            = &nm_select_unix_udp_abort;
    pl->udp.async_bind_port  = &nm_select_unix_udp_async_bind_port;
    pl->udp.async_bind_mdns_ipv4 = &nm_select_unix_async_bind_mdns_ipv4;
    pl->udp.async_bind_mdns_ipv6 = &nm_select_unix_async_bind_mdns_ipv6;
    pl->udp.async_send_to    = &nm_select_unix_udp_async_send_to;
    pl->udp.async_recv_from  = &nm_select_unix_udp_async_recv_from;
    pl->udp.get_protocol     = &nm_select_unix_udp_get_protocol;
    pl->udp.get_local_ip     = &nm_select_unix_udp_get_local_ip;
    pl->udp.get_local_port   = &nm_select_unix_udp_get_local_port;
    pl->udpData = ctx;

    sockets->recvBuf = pl->buf.allocate();
    sockets->socketsSentinel.next = &sockets->socketsSentinel;
    sockets->socketsSentinel.prev = &sockets->socketsSentinel;

}

void nm_select_unix_udp_deinit(struct nm_select_unix* ctx)
{
    ctx->pl->buf.free(ctx->udpSockets.recvBuf);
}

bool nm_select_unix_udp_has_sockets(struct nm_select_unix* ctx)
{
    return ctx->udpSockets.socketsSentinel.next == &ctx->udpSockets.socketsSentinel;
}


np_error_code nm_select_unix_udp_create(struct np_platform* pl, np_udp_socket** sock)
{
    np_udp_socket* s = calloc(1, sizeof(np_udp_socket));
    if (!s) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    *sock = s;
    s->sock = -1;

    struct nm_select_unix* selectCtx = pl->udpData;
    struct nm_select_unix_udp_sockets* sockets = &selectCtx->udpSockets;

    s->pl = selectCtx->pl;
    s->selectCtx = pl->udpData;

    np_udp_socket* before = sockets->socketsSentinel.prev;
    np_udp_socket* after = &sockets->socketsSentinel;
    before->next = s;
    s->next = after;
    after->prev = s;
    s->prev = before;

    s->sendSentinel = &s->sendSentinelData;
    s->sendSentinel->next = s->sendSentinel;
    s->sendSentinel->prev = s->sendSentinel;

    // add fd to select fd set.
    nm_select_unix_notify(selectCtx);

    return NABTO_EC_OK;
}

np_error_code nm_select_unix_udp_async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }
    struct np_platform* pl = sock->pl;
    sock->created.cb = cb;
    sock->created.data = data;
    sock->created.port = port;
    sock->destroyed = false;
    sock->aborted = false;
    np_event_queue_post(pl, &sock->created.event, &nm_select_unix_udp_event_bind_port, sock);
    return NABTO_EC_OK;
}

np_error_code nm_select_unix_async_bind_mdns_ipv4(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }
    struct np_platform* pl = sock->pl;
    sock->created.cb = cb;
    sock->created.data = data;
    sock->destroyed = false;
    sock->aborted = false;
    np_event_queue_post(pl, &sock->created.event, &nm_select_unix_udp_event_bind_mdns_ipv4, sock);
    return NABTO_EC_OK;
}

np_error_code nm_select_unix_async_bind_mdns_ipv6(np_udp_socket* sock, np_udp_socket_created_callback cb, void* data)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }
    struct np_platform* pl = sock->pl;
    sock->created.cb = cb;
    sock->created.data = data;
    sock->destroyed = false;
    sock->aborted = false;
    np_event_queue_post(pl, &sock->created.event, &nm_select_unix_udp_event_bind_mdns_ipv6, sock);
    return NABTO_EC_OK;
}

void nm_select_unix_udp_event_bind_mdns_ipv4(void* data) {
    np_udp_socket* us = (np_udp_socket*)data;
    us->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (us->sock < 0) {
        np_udp_socket_created_callback cb = us->created.cb;
        us->created.cb = NULL;
        cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        return;
    }
    us->isIpv6 = false;

    int flags = fcntl(us->sock, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(us->sock, F_SETFL, flags | O_NONBLOCK);

    if (!nm_unix_init_mdns_ipv4_socket(us->sock)) {
        np_udp_socket_created_callback cb = us->created.cb;
        us->created.cb = NULL;
        cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        return;
    }
    np_udp_socket_created_callback cb = us->created.cb;
    us->created.cb = NULL;
    cb(NABTO_EC_OK, us->created.data);
    return;
}

void nm_select_unix_udp_event_bind_mdns_ipv6(void* data) {
    np_udp_socket* us = (np_udp_socket*)data;
    us->sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (us->sock < 0) {
        np_udp_socket_created_callback cb = us->created.cb;
        us->created.cb = NULL;
        cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        return;
    }
    us->isIpv6 = true;

    int no = 0;
    int status = setsockopt(us->sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no));
    if (status < 0)
    {
        NABTO_LOG_ERROR(LOG, "Cannot set IPV6_V6ONLY");
    }

    int flags = fcntl(us->sock, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(us->sock, F_SETFL, flags | O_NONBLOCK);

    if (!nm_unix_init_mdns_ipv6_socket(us->sock)) {
        np_udp_socket_created_callback cb = us->created.cb;
        us->created.cb = NULL;
        cb(NABTO_EC_UDP_SOCKET_CREATION_ERROR, us->created.data);
        return;
    }

    np_udp_socket_created_callback cb = us->created.cb;
    us->created.cb = NULL;
    cb(NABTO_EC_OK, us->created.data);
    return;
}

np_error_code nm_select_unix_udp_async_send_to(np_udp_socket* sock, struct np_udp_endpoint ep,
                                               uint8_t* buffer, uint16_t bufferSize,
                                               np_udp_packet_sent_callback cb, void* userData)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "send to called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    struct nm_select_unix_udp_send_context* ctx = (struct nm_select_unix_udp_send_context*)calloc(1, sizeof(struct nm_select_unix_udp_send_context));
    if (ctx == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->sock = sock;
    ctx->ep = ep;
    ctx->buffer = buffer;
    ctx->bufferSize = bufferSize;
    ctx->cb = cb;
    ctx->cbData = userData;
    nm_select_unix_udp_add_send_base(sock, (struct nm_select_unix_udp_send_base*)ctx);
    np_event_queue_post(sock->pl, &ctx->ev, nm_select_unix_udp_event_send_to, ctx);
    return NABTO_EC_OK;
}

np_error_code nm_select_unix_udp_async_recv_from(np_udp_socket* socket,
                                                 np_udp_packet_received_callback cb, void* data)
{
    if (socket->aborted) {
        NABTO_LOG_ERROR(LOG, "recv from called on aborted socket");
        return NABTO_EC_ABORTED;
    }
    socket->recv.cb = cb;
    socket->recv.data = data;
    nm_select_unix_notify(socket->selectCtx);
    return NABTO_EC_OK;
}

enum np_ip_address_type nm_select_unix_udp_get_protocol(np_udp_socket* socket)
{
    if(socket->isIpv6) {
        return NABTO_IPV6;
    } else {
        return NABTO_IPV4;
    }
}

size_t nm_select_unix_udp_get_local_ip( struct np_ip_address *addrs, size_t addrsSize)
{
    struct sockaddr_in si_me, si_other;
    struct sockaddr_in6 si6_me, si6_other;
    struct in_addr v4any;
    struct in6_addr v6any;
    size_t ind = 0;

    v4any.s_addr = INADDR_ANY;
    v6any = in6addr_any;
    if (addrsSize < 1) {
        return 0;
    }
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s != -1) {
        memset(&si_me, 0, sizeof(si_me));
        memset(&si_other, 0, sizeof(si_me));
        //bind to local port 4567
        si_me.sin_family = AF_INET;
        si_me.sin_port = htons(4567);
        si_me.sin_addr.s_addr = INADDR_ANY;

        //"connect" google's DNS server at 8.8.8.8 , port 4567
        si_other.sin_family = AF_INET;
        si_other.sin_port = htons(4567);
        si_other.sin_addr.s_addr = inet_addr("8.8.8.8");
        if(connect(s,(struct sockaddr*)&si_other,sizeof(si_other)) == -1) {
            // expected on systems without ipv4
            //NABTO_LOG_ERROR(LOG, "Cannot connect to host");
        } else {
            struct sockaddr_in my_addr;
            socklen_t len = sizeof my_addr;
            if(getsockname(s,(struct sockaddr*)&my_addr,&len) == -1) {
                NABTO_LOG_ERROR(LOG, "getsockname failed");
            } else {
                if (memcmp(&my_addr.sin_addr, &v4any, 4) != 0) {
                    addrs[ind].type = NABTO_IPV4;
                    memcpy(addrs[ind].ip.v4, &my_addr.sin_addr.s_addr, 4);
                    ind++;
                }
            }
        }
        close(s);
    }
    if (addrsSize < ind+1) {
        return ind;
    }
    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s != -1) {
        memset(&si6_me, 0, sizeof(si6_me));
        memset(&si6_other, 0, sizeof(si6_me));
        //bind to local port 4567
        si6_me.sin6_family = AF_INET6;
        si6_me.sin6_port = htons(4567);
        si6_me.sin6_addr = in6addr_any;

        //"connect" google's DNS server at 2001:4860:4860::8888 , port 4567
        si6_other.sin6_family = AF_INET6;
        si6_other.sin6_port = htons(4567);
        inet_pton(AF_INET6, "2001:4860:4860::8888", si6_other.sin6_addr.s6_addr);
        if(connect(s,(struct sockaddr*)&si6_other,sizeof(si6_other)) == -1) {
            // Expected on systems without IPv6
            // NABTO_LOG_ERROR(LOG, "Cannot connect to host");
        } else {
            struct sockaddr_in6 my_addr;
            socklen_t len = sizeof my_addr;
            if(getsockname(s,(struct sockaddr*)&my_addr,&len) == -1) {
                NABTO_LOG_ERROR(LOG, "getsockname failed");
            } else {
                if (memcmp(&my_addr.sin6_addr, &v6any, 16) != 0) {
                    addrs[ind].type = NABTO_IPV6;
                    memcpy(addrs[ind].ip.v6, my_addr.sin6_addr.s6_addr, 16);
                    ind++;
                }
            }
        }
        close(s);
    }
    return ind;
}

uint16_t nm_select_unix_udp_get_local_port(np_udp_socket* socket)
{
    if (socket->aborted) {
        NABTO_LOG_ERROR(LOG, "get local port called on aborted socket");
        return 0;
    }
    struct sockaddr_in6 addr;
    addr.sin6_port = 0;

    socklen_t length = sizeof(struct sockaddr_in6);
    getsockname(socket->sock, (struct sockaddr*)(&addr), &length);
    return htons(addr.sin6_port);
}

void nm_select_unix_udp_event_bind_port(void* data)
{
    np_udp_socket* sock = (np_udp_socket*)data;
    int i;

    np_error_code ec = nm_select_unix_udp_create_socket(sock);

    if (ec == NABTO_EC_OK) {
        if (sock->isIpv6) {
            struct sockaddr_in6 si_me6;
            si_me6.sin6_family = AF_INET6;
            si_me6.sin6_port = htons(sock->created.port);
            si_me6.sin6_addr = in6addr_any;
            si_me6.sin6_scope_id = 0;
            si_me6.sin6_flowinfo = 0;
            i = bind(sock->sock, (struct sockaddr*)&si_me6, sizeof(si_me6));
            NABTO_LOG_TRACE(LOG, "bind returned %i", i);
        } else {
            struct sockaddr_in si_me;
            si_me.sin_family = AF_INET;
            si_me.sin_port = htons(sock->created.port);
            si_me.sin_addr.s_addr = INADDR_ANY;
            i = bind(sock->sock, (struct sockaddr*)&si_me, sizeof(si_me));
            NABTO_LOG_TRACE(LOG, "bind returned %i", i);
        }
        if (i != 0) {
            NABTO_LOG_ERROR(LOG,"Unable to bind to port %i: (%i) '%s'.", sock->created.port, errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR;
            np_udp_socket_created_callback cb = sock->created.cb;
            sock->created.cb = NULL;
            cb(ec, sock->created.data);
            return;
        }
        np_udp_socket_created_callback cb = sock->created.cb;
        sock->created.cb = NULL;
        cb(NABTO_EC_OK, sock->created.data);
        return;
    } else {
        np_udp_socket_created_callback cb = sock->created.cb;
        sock->created.cb = NULL;
        cb(ec, sock->created.data);
        return;
    }
}

void nm_select_unix_udp_event_send_to(void* data)
{
    struct nm_select_unix_udp_send_context* ctx = (struct nm_select_unix_udp_send_context*)data;
    np_udp_socket* sock = ctx->sock;
    ssize_t res;
    np_error_code ec = NABTO_EC_OK;
    if (ctx->ep.ip.type == NABTO_IPV4 && !sock->isIpv6) { // IPv4 addr on IPv4 socket
        struct sockaddr_in srv_addr;
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons (ctx->ep.port);
        memcpy((void*)&srv_addr.sin_addr, ctx->ep.ip.ip.v4, sizeof(srv_addr.sin_addr));

        NABTO_LOG_TRACE(LOG, "Sending to: %s:%d", np_ip_address_to_string(&ctx->ep.ip), ctx->ep.port);
        res = sendto (sock->sock, ctx->buffer, ctx->bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    } else { // IPv6 addr or IPv4 addr on IPv6 socket
        struct sockaddr_in6 srv_addr;
        srv_addr.sin6_family = AF_INET6;
        srv_addr.sin6_flowinfo = 0;
        srv_addr.sin6_scope_id = 0;
        srv_addr.sin6_port = htons (ctx->ep.port);

        if (ctx->ep.ip.type == NABTO_IPV4) { // IPv4 addr on IPv6 socket
            // Map ipv4 to ipv6
            NABTO_LOG_TRACE(LOG, "mapping: %s: to IPv6", np_ip_address_to_string(&ctx->ep.ip));
            uint8_t* ptr = (uint8_t*)&srv_addr.sin6_addr;
            memset(ptr, 0, 10); // 80  bits of 0
            ptr += 10;
            memset(ptr, 0xFF, 2); // 16 bits of 1
            ptr += 2;
            memcpy(ptr,ctx->ep.ip.ip.v4, 4); // 32 bits of IPv4
        } else { // IPv6 addr copied directly
            memcpy((void*)&srv_addr.sin6_addr,ctx->ep.ip.ip.v6, 16);
            uint8_t* addr = (uint8_t*)&srv_addr.sin6_addr;
            NABTO_LOG_TRACE(LOG,
                            "Sending to v6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                            addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
        }
        res = sendto (sock->sock, ctx->buffer, ctx->bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    }
    if (res < 0) {
        int status = errno;
        NABTO_LOG_TRACE(LOG, "UDP returned error status %i", status);
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
        } else {
            if (status == EADDRNOTAVAIL) {
                NABTO_LOG_TRACE(LOG,"ERROR: (%i) '%s' in nm_select_unix_udp_event_send_to", (int) status, strerror(status));
            } else {
                NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_select_unix_udp_event_send_to", (int) status, strerror(status));
            }
            ec = NABTO_EC_FAILED_TO_SEND_PACKET;
        }
    }
    if (ctx->cb) {
        ctx->cb(ec, ctx->cbData);
    }
    nm_select_unix_udp_remove_send_base(sock, (struct nm_select_unix_udp_send_base*)ctx);
    free(ctx);
    return;
}

void nm_select_unix_udp_event_abort(void* userData)
{
    np_udp_socket* sock = (np_udp_socket*)userData;
    if (sock->recv.cb != NULL) {
        struct np_udp_endpoint ep = emptyEp;
        np_udp_packet_received_callback cb = sock->recv.cb;
        sock->recv.cb = NULL;
        cb(NABTO_EC_ABORTED, ep, NULL, 0, sock->recv.data);
    }
    if (sock->created.cb) {
        np_udp_socket_created_callback cb = sock->created.cb;
        sock->created.cb = NULL;
        cb(NABTO_EC_ABORTED, sock->created.data);
    }
    struct nm_select_unix_udp_send_base* iterator = sock->sendSentinel->next;
    while (iterator != sock->sendSentinel) {
        struct nm_select_unix_udp_send_context* current = (struct nm_select_unix_udp_send_context*)iterator;
        iterator = iterator->next;
        if (current->cb != NULL) {
            current->cb(NABTO_EC_ABORTED, current->cbData);
        }
        nm_select_unix_udp_remove_send_base(sock, (struct nm_select_unix_udp_send_base*)current);
    }
}

np_error_code nm_select_unix_udp_abort(np_udp_socket* sock)
{
    if (!sock->aborted) {
        sock->aborted = true;
        np_event_queue_post(sock->pl, &sock->abortEv, &nm_select_unix_udp_event_abort, sock);
    }
    return NABTO_EC_OK;
}

void nm_select_unix_udp_destroy(np_udp_socket* sock)
{
    if (sock == NULL) {
        return;
    }
    sock->destroyed = true;
    nm_select_unix_notify(sock->selectCtx);
    return;
}

np_error_code nm_select_unix_udp_create_socket(np_udp_socket* sock)
{
    sock->sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock->sock == -1) {
        sock->sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock->sock == -1) {
            NABTO_LOG_ERROR(LOG, "Unable to create socket: (%i) '%s'.", errno, strerror(errno));
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        } else {
            NABTO_LOG_WARN(LOG, "IPv4 socket opened since IPv6 socket creation failed");
            sock->isIpv6 = false;
        }
    } else {
        int no = 0;
        sock->isIpv6 = true;
        if (setsockopt(sock->sock, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &no, sizeof(no))) {
            NABTO_LOG_ERROR(LOG, "Unable to set option: (%i) '%s'.", errno, strerror(errno));
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        }
    }
    int flags = fcntl(sock->sock, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(sock->sock, F_SETFL, flags | O_NONBLOCK);
    return NABTO_EC_OK;
}

void nm_select_unix_udp_handle_event(np_udp_socket* sock)
{
    if (!sock->recv.cb) {
        return;
    }
    NABTO_LOG_TRACE(LOG, "handle event");
    struct np_udp_endpoint ep;
    struct np_platform* pl = sock->pl;
    ssize_t recvLength;
    uint8_t* start;
    np_communication_buffer* buffer = sock->selectCtx->udpSockets.recvBuf;
    size_t bufferLength = pl->buf.size(buffer);

    start = pl->buf.start(buffer);

    if (sock->isIpv6) {
        struct sockaddr_in6 sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, start, bufferLength, 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.ip.v6, &sa.sin6_addr.s6_addr, sizeof(ep.ip.ip.v6));
        ep.port = ntohs(sa.sin6_port);
        ep.ip.type = NABTO_IPV6;
    } else {
        struct sockaddr_in sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, start, bufferLength, 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.ip.v4, &sa.sin_addr.s_addr, sizeof(ep.ip.ip.v4));
        ep.port = ntohs(sa.sin_port);
        ep.ip.type = NABTO_IPV4;
    }
    if (recvLength < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
            return;
        } else {
            np_udp_packet_received_callback cb;
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_select_unix_udp_handle_event", strerror(status), (int) status);
            if(sock->recv.cb) {
                cb = sock->recv.cb;
                sock->recv.cb = NULL;
                cb(NABTO_EC_UDP_SOCKET_ERROR, ep, NULL, 0, sock->recv.data);
            }
            return;
        }
    }
    if (sock->recv.cb) {
        np_udp_packet_received_callback cb = sock->recv.cb;
        sock->recv.cb = NULL;
        NABTO_LOG_TRACE(LOG, "received data, invoking callback");
        cb(NABTO_EC_OK, ep, start, recvLength, sock->recv.data);
    }
    nm_select_unix_udp_handle_event(sock);
}

void nm_select_unix_udp_free_socket(np_udp_socket* sock)
{
    np_udp_socket* before = sock->prev;
    np_udp_socket* after = sock->next;
    before->next = after;
    after->prev = before;

    shutdown(sock->sock, SHUT_RDWR);
    close(sock->sock);
    nm_select_unix_udp_cancel_all_events(sock);
    free(sock);
}

void nm_select_unix_udp_cancel_all_events(np_udp_socket* sock)
{
    struct np_platform* pl = sock->pl;
    NABTO_LOG_TRACE(LOG, "Cancelling all events");
    np_event_queue_cancel_event(pl, &sock->created.event);
    np_event_queue_cancel_event(pl, &sock->recv.event);
    np_event_queue_cancel_event(pl, &sock->abortEv);
}

void nm_select_unix_udp_build_fd_sets(struct nm_select_unix* ctx, struct nm_select_unix_udp_sockets* sockets)
{
    np_udp_socket* iterator = sockets->socketsSentinel.next;

    while(iterator != &sockets->socketsSentinel)
    {
        if (iterator->recv.cb && iterator->sock != -1) {
            FD_SET(iterator->sock, &ctx->readFds);
            ctx->maxReadFd = NP_MAX(ctx->maxReadFd, iterator->sock);
        }
        iterator = iterator->next;
    }
}

void nm_select_unix_udp_handle_select(struct nm_select_unix* ctx, int nfds)
{
    struct nm_select_unix_udp_sockets* sockets = &ctx->udpSockets;
    np_udp_socket* iterator = sockets->socketsSentinel.next;
    while(iterator != &sockets->socketsSentinel)
    {
        if (iterator->destroyed) {
            np_udp_socket* current = iterator;
            iterator = iterator->next;
            nm_select_unix_udp_free_socket(current);
            continue;
        }
        if (iterator->sock != -1 && FD_ISSET(iterator->sock, &ctx->readFds)) {
            nm_select_unix_udp_handle_event(iterator);
        }
        iterator = iterator->next;
    }
}

void nm_select_unix_udp_add_send_base(np_udp_socket* sock, struct nm_select_unix_udp_send_base* base)
{
    struct nm_select_unix_udp_send_base* before = sock->sendSentinel->prev;
    struct nm_select_unix_udp_send_base* after = sock->sendSentinel;
    before->next = base;
    base->prev = before;
    after->prev = base;
    base->next = after;
}

void nm_select_unix_udp_remove_send_base(np_udp_socket* sock, struct nm_select_unix_udp_send_base* base)
{
    base->prev->next = base->next;
    base->next->prev = base->prev;
    base->prev = base;
    base->next = base;
}
