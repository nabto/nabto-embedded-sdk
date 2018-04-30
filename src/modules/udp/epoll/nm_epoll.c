#include "nm_epoll.h"
#include <modules/list/list.h>
#include <platform/logging.h>
#include <platform/platform.h>

#include <sys/epoll.h>
#include <sys/socket.h>

typedef struct nabto_udp_socket{
    int sock;
};

struct socketListElement {
    nabto_udp_socket sock;
    struct socketListElement *prev;
    struct socketListElement *next;
} socketListElement;

static int nm_epoll_fd = 0;
static struct socketListElement list = 0;
struct nabto_platform *pl = 0;

void nm_epoll_init(nabto_platform *pl_in) {
    pl = pl_in;
    pl->nabto_udp_module.async_create    = &nm_epoll_async_create;
    pl->nabto_udp_module.async_bind_port = &nm_epoll_async_bind_port;
    pl->nabto_udp_module.async_send_to   = &nm_epoll_async_send_to;
    pl->nabto_udp_module.async_recv_from = &nm_epoll_async_recv_from;
    pl->nabto_udp_module.async_destroy   = &nm_epoll_async_destroy;
}

void nm_epoll_event_create(nabto_udp_socket_created_callback cb, void* data)
{
    socketListElement* se;
    nabto_udp_socket us;

    us.sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (us.sock == -1) {
        us.sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (us.sock == -1) {
            nabto_error_code ec;
            NABTO_LOG_ERROR(NABTO_LOG_MODULE_UDP, "Unable to create socket: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR;
            cb(ec, NULL, data);
            return;
        } else {
            NABTO_LOG_WARN(NABTO_LOG_MODULE_UDP, "IPv4 socket opened since IPv6 socket creation failed");
        }
    } else {
        int no = 0;
        if (setsockopt(us.sd, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &no, sizeof(no)))
        {
            nabto_error_code ec;
            NABTO_LOG_ERROR("Unable to set option: (%i) '%s'.", errno, strerror(errno));
            ec = NABTO_EC_UDP_SOCKET_CREATION_ERROR; 
            close(us.sock);
            cb(ec, NULL, data);
            return;
        }        
    }
    
    se = (socketListElement*)malloc(sizeof(socketListElement));
    se.sock = us;
    DL_APPEND(list,se);
    cb(NABTO_EC_OK, &se.sock, data);
    return;
}

void nm_epoll_event_destroy(nabto_udp_scoket* socket, nabto_udp_socket_destroyed_callback cb, void* data)
{
    socketListElement *se;
    socketListElement *found = 0;
    DL_FOREACH(list, se) {
        if (&(se->sock) == socket) {
            found = se;
            break;
        }
    }
    if ( !found ) {
        nabto_error_code ec;
        NABTO_LOG_ERROR("Socket %i Not found in socket list", *sock);
        ec = NABTO_EC_INVALID_SOCKET;
        cb(ec, data);
        return;
    } else {
        if (epoll_ctl(nm_epoll_fd, EPOLL_CTL_DEL, found->sock.sock, NULL) == -1) {
            NABTO_LOG_ERROR("Cannot remove fd from epoll set, %i: %s", errno, strerror(errno));
        }
        close(found->sock.sock);
        DL_DELETE(list, found);
        free(found);
        socket = NULL;
        cb(NABTO_EC_OK, data);
    }

}

void nm_epoll_async_create(nabto_udp_socket_created_callback cb, void* data)
{

}
void nm_epoll_async_bind_port(uint16_t port, nabto_udp_socket_created_callback cb, void* data)
{

}

void nm_epoll_async_send_to(nabto_udp_socket* socket, struct nabto_udp_endpoint* ep, uint8_t* buffer, uint16_t bufferSize, nabto_udp_packet_sent_callback cb, void* data)
{

}

void nm_epoll_async_recv_from(nabto_udp_socket* socket, nabto_udp_packet_received_callback cb, void* data)
{

}

void nm_epoll_async_destroy(nabto_udp_socket* socket, nabto_udp_socket_destroyed_callback cb, void* data)
{


}


