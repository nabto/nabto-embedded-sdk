#include "nm_select_unix.h"

#include <platform/np_logging.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define LOG NABTO_LOG_MODULE_UDP

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
    int sock;
    bool isIpv6;
    struct nm_select_unix_created_ctx created;
    struct nm_select_unix_destroyed_ctx des;
    struct nm_select_unix_received_ctx recv;
};

static struct np_platform* pl = 0;
static np_communication_buffer* recv_buf;

/**
 * Api function declarations
 */
void nm_select_unix_async_create(np_udp_socket_created_callback cb, void* data);
void nm_select_unix_async_bind_port(uint16_t port, np_udp_socket_created_callback cb, void* data);
void nm_select_unix_async_send_to(struct np_udp_send_context* ctx);
void nm_select_unix_async_recv_from(np_udp_socket* socket,
                                    np_udp_packet_received_callback cb, void* data);
void nm_select_unix_cancel_recv_from(np_udp_socket* socket);
void nm_select_unix_cancel_send_to(struct np_udp_send_context* socket);
enum np_ip_address_type nm_select_unix_get_protocol(np_udp_socket* socket);
uint16_t nm_select_unix_get_local_port(np_udp_socket* socket);
void nm_select_unix_async_destroy(np_udp_socket* socket, np_udp_socket_destroyed_callback cb, void* data);
int nm_select_unix_inf_wait();
int nm_select_unix_timed_wait(uint32_t ms);
void nm_select_unix_read(int nfds);


/**
 * Helper function declarations
 */
void nm_select_unix_cancel_all_events(np_udp_socket* sock);
void nm_select_unix_event_create(void* data);
void nm_select_unix_event_destroy(void* data);
void nm_select_unix_event_bind_port(void* data);
void nm_select_unix_event_send_to(void* data);


/**
 * Api functions start
 */
void nm_select_unix_init(struct np_platform *pl_in)
{
    pl = pl_in;
    pl->udp.async_create     = &nm_select_unix_async_create;
    pl->udp.async_bind_port  = &nm_select_unix_async_bind_port;
    pl->udp.async_send_to    = &nm_select_unix_async_send_to;
    pl->udp.async_recv_from  = &nm_select_unix_async_recv_from;
    pl->udp.cancel_recv_from = &nm_select_unix_cancel_recv_from;
    pl->udp.cancel_send_to   = &nm_select_unix_cancel_send_to;
    pl->udp.get_protocol     = &nm_select_unix_get_protocol;
    pl->udp.get_local_port   = &nm_select_unix_get_local_port;
    pl->udp.async_destroy    = &nm_select_unix_async_destroy;
    pl->udp.inf_wait         = &nm_select_unix_inf_wait;
    pl->udp.timed_wait       = &nm_select_unix_timed_wait;
    pl->udp.read             = &nm_select_unix_read;

    recv_buf = pl->buf.allocate();
}

void nm_select_unix_async_create(np_udp_socket_created_callback cb, void* data)
{
    np_udp_socket* sock;

    sock = (np_udp_socket*)malloc(sizeof(np_udp_socket));
    sock->created.cb = cb;
    sock->created.data = data;
    np_event_queue_post(pl, &sock->created.event, &nm_select_unix_event_create, sock);

}

void nm_select_unix_async_bind_port(uint16_t port, np_udp_socket_created_callback cb, void* data)
{

}

void nm_select_unix_async_send_to(struct np_udp_send_context* ctx)
{
    np_event_queue_post(pl, &ctx->ev, nm_select_unix_event_send_to, ctx);
}

void nm_select_unix_async_recv_from(np_udp_socket* socket,
                                    np_udp_packet_received_callback cb, void* data)
{
    socket->recv.cb = cb;
    socket->recv.data = data;
}

void nm_select_unix_cancel_recv_from(np_udp_socket* socket)
{
    np_event_queue_cancel_event(pl, &socket->recv.event);
    socket->recv.cb = NULL;
}

void nm_select_unix_cancel_send_to(struct np_udp_send_context* ctx)
{
    np_event_queue_cancel_event(pl, &ctx->ev);
    ctx->cb = NULL;
}

enum np_ip_address_type nm_select_unix_get_protocol(np_udp_socket* socket)
{
    if(socket->isIpv6) {
        return NABTO_IPV6;
    } else {
        return NABTO_IPV4;
    }
}

uint16_t nm_select_unix_get_local_port(np_udp_socket* socket)
{
    struct sockaddr_in6 addr;
    socklen_t length = sizeof(struct sockaddr_in6);
    getsockname(socket->sock, (struct sockaddr*)(&addr), &length);
    return htons(addr.sin6_port);
}

void nm_select_unix_async_destroy(np_udp_socket* socket, np_udp_socket_destroyed_callback cb, void* data)
{
    socket->des.cb = cb;
    socket->des.data = data;
    np_event_queue_post(pl, &socket->des.event, nm_select_unix_event_destroy, socket);
}

int nm_select_unix_inf_wait()
{
    return 0;
}

int nm_select_unix_timed_wait(uint32_t ms)
{
    return 0;
}

void nm_select_unix_read(int nfds)
{

}

/**
 * Helper functions start
 */

void nm_select_unix_cancel_all_events(np_udp_socket* sock)
{
    NABTO_LOG_TRACE(LOG, "Cancelling all events");
    np_event_queue_cancel_event(pl, &sock->created.event);
    np_event_queue_cancel_event(pl, &sock->des.event);
    np_event_queue_cancel_event(pl, &sock->recv.event);
}

void nm_select_unix_event_create(void* data)
{

}

void nm_select_unix_event_bind_port(void* data)
{


}

void nm_select_unix_event_send_to(void* data)
{

}

void nm_select_unix_event_destroy(void* data)
{
    np_udp_socket* sock = (np_udp_socket*)data;
    if (sock == NULL) {
        return;
    }
    shutdown(sock->sock, SHUT_RDWR);
    NABTO_LOG_TRACE(LOG, "shutdown with data: %u", sock->des.data);
    return;
}

