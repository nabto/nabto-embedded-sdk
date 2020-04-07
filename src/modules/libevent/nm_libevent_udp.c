#include "nm_libevent_udp.h"

struct np_udp_socket {
    evutil_socket_t sock;
};

static np_error_code create(struct np_platform* pl, np_udp_socket** sock);
static void destroy(struct np_udp_socket* sock);
static np_error_code async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data);

void nm_libevent_udp_init(struct np_platform* pl, struct event_base* base)
{
    pl->udpData = base;

    pl->udp.create  = &create;
    pl->udp.destroy = &destroy;
    pl->udp.async_bind_port = &async_bind_port;
}



np_error_code create(struct np_platform* pl, np_udp_socket** sock)
{
    np_udp_socket* s = calloc(1, sizeof(struct np_udp_socket));
}

void destroy(struct np_udp_socket* sock)
{

}


np_error_code async_bind_port(np_udp_socket* sock, uint16_t port, np_udp_socket_created_callback cb, void* data)
{
    sock->sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock->sock == -1) {
        return NABTO_EC_FAILED;
    }

    evutil_make_socket_nonblocking(sock->sock);

    struct sockaddr_in6 si_me6;
    memset(&si_me6, 0, sizeof(si_me6));
    si_me6.sin6_family = AF_INET6;
    si_me6.sin6_port = htons(us->created.port);
    si_me6.sin6_addr = in6addr_any;
    int status = bind(us->sock, (struct sockaddr*)&si_me6, sizeof(si_me6));
    NABTO_LOG_TRACE(LOG, "bind returned %i", status);

    pl_event_ready(sock->pl, event,)
    return NABTO_EC_OK;
}

np_error_code async_recv_from(np_udp_socket* sock, np_udp_packet_received_callback cb, void* data)
{
    struct event_base* base;
    event_assign(&sock->event, base, sock->sock, EV_READ, read_ready_callback, sock);
}

void udp_ready_callback(evutil_socket_t sock, short events, void* userData)
{
    struct np_udp_socket* sock = userData;
    if (events & EV_READ) {
        recv_from(sock);
    }
}

void read_ready_callback(np_udp_socket* sock)
{
    if (sock.recvCb == NULL) {
        return;
    }

        struct np_udp_endpoint ep;
    struct np_platform* pl = sock->pl;
    struct nm_epoll_context* epoll = pl->udpData;
    ssize_t recvLength;
    uint8_t* start;
    start = pl->buf.start(epoll->recvBuffer);

    struct sockaddr_in6 sa;
    socklen_t addrlen = sizeof(sa);
    recvLength = recvfrom(sock->sock, start,  pl->buf.size(epoll->recvBuffer), 0, (struct sockaddr*)&sa, &addrlen);
    memcpy(&ep.ip.ip.v6, &sa.sin6_addr.s6_addr, sizeof(ep.ip.ip.v6));
    ep.port = ntohs(sa.sin6_port);
    ep.ip.type = NABTO_IPV6;

    if (recvLength < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
            return;
        } else {
            np_udp_packet_received_callback cb;
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_epoll_udp_handle_event", strerror(status), (int) status);
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
        cb(NABTO_EC_OK, ep, pl->buf.start(epoll->recvBuffer), recvLength, sock->recv.data);
    }

}
