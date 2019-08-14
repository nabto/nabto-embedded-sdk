#include "nm_select_unix.h"

#include <platform/np_logging.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#define LOG NABTO_LOG_MODULE_UDP
#define MAX(a,b) (((a)>(b))?(a):(b))

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
    struct np_udp_socket* next;
    struct np_udp_socket* prev;
    bool closing;
};

static struct np_platform* pl = 0;
static np_communication_buffer* recvBuf;
static struct np_udp_socket* head = NULL;
static fd_set readFds;
static int maxReadFd;
static int pipefd[2];

/**
 * Api function declarations
 */
void nm_select_unix_async_create(np_udp_socket_created_callback cb, void* data);
void nm_select_unix_async_bind_port(uint16_t port, np_udp_socket_created_callback cb, void* data);
void nm_select_unix_async_send_to(struct np_udp_send_context* ctx);
void nm_select_unix_async_recv_from(np_udp_socket* socket,
                                    np_udp_packet_received_callback cb, void* data);
enum np_ip_address_type nm_select_unix_get_protocol(np_udp_socket* socket);
uint16_t nm_select_unix_get_local_port(np_udp_socket* socket);
void nm_select_unix_async_destroy(np_udp_socket* socket, np_udp_socket_destroyed_callback cb, void* data);
int nm_select_unix_inf_wait();
int nm_select_unix_timed_wait(uint32_t ms);
void nm_select_unix_read(int nfds);


/**
 * Helper function declarations
 */
void nm_select_unix_build_fd_sets();
void nm_select_unix_cancel_all_events(np_udp_socket* sock);
void nm_select_unix_event_create(void* data);
void nm_select_unix_event_bind_port(void* data);
void nm_select_unix_event_destroy(void* data);
void nm_select_unix_event_bind_port(void* data);
void nm_select_unix_event_send_to(void* data);
np_error_code nm_select_unix_create_socket(np_udp_socket* sock);
void nm_select_unix_handle_event(np_udp_socket* sock);
void nm_select_unix_free_socket(np_udp_socket* sock);

/**
 * Api functions start
 */
void nm_unix_udp_select_init(struct np_platform *pl_in)
{
    pl = pl_in;
    pl->udp.async_create     = &nm_select_unix_async_create;
    pl->udp.async_bind_port  = &nm_select_unix_async_bind_port;
    pl->udp.async_send_to    = &nm_select_unix_async_send_to;
    pl->udp.async_recv_from  = &nm_select_unix_async_recv_from;
    pl->udp.get_protocol     = &nm_select_unix_get_protocol;
    pl->udp.get_local_ip     = &nm_select_unix_get_local_ip;
    pl->udp.get_local_port   = &nm_select_unix_get_local_port;
    pl->udp.async_destroy    = &nm_select_unix_async_destroy;

    recvBuf = pl->buf.allocate();
    if(pipe(pipefd) == -1) {
        NABTO_LOG_ERROR(LOG, "Failed to create pipe file descriptors");
    }
    nm_select_unix_build_fd_sets();
}

void nm_select_unix_async_create(np_udp_socket_created_callback cb, void* data)
{
    np_udp_socket* sock;

    sock = (np_udp_socket*)malloc(sizeof(np_udp_socket));
    memset(sock, 0, sizeof(np_udp_socket));
    sock->created.cb = cb;
    sock->created.data = data;
    sock->closing = false;
    np_event_queue_post(pl, &sock->created.event, &nm_select_unix_event_create, sock);
}

void nm_select_unix_async_bind_port(uint16_t port, np_udp_socket_created_callback cb, void* data)
{
    np_udp_socket* sock;

    sock = (np_udp_socket*)malloc(sizeof(np_udp_socket));
    memset(sock, 0, sizeof(np_udp_socket));
    sock->created.cb = cb;
    sock->created.data = data;
    sock->created.port = port;
    sock->closing = false;
    np_event_queue_post(pl, &sock->created.event, &nm_select_unix_event_bind_port, sock);
}

void nm_select_unix_async_send_to(struct np_udp_send_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "Async_send_to");
    np_event_queue_post(pl, &ctx->ev, nm_select_unix_event_send_to, ctx);
}

void nm_select_unix_async_recv_from(np_udp_socket* socket,
                                    np_udp_packet_received_callback cb, void* data)
{
    socket->recv.cb = cb;
    socket->recv.data = data;
}

enum np_ip_address_type nm_select_unix_get_protocol(np_udp_socket* socket)
{
    if(socket->isIpv6) {
        return NABTO_IPV6;
    } else {
        return NABTO_IPV4;
    }
}

size_t nm_select_unix_get_local_ip( struct np_ip_address *addrs, size_t addrsSize)
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
            NABTO_LOG_ERROR(LOG, "Cannot connect to host");
        } else {
            struct sockaddr_in my_addr;
            socklen_t len = sizeof my_addr;
            if(getsockname(s,(struct sockaddr*)&my_addr,&len) == -1) {
                NABTO_LOG_ERROR(LOG, "getsockname failed");
            } else {
                if (memcmp(&my_addr.sin_addr, &v4any, 4) != 0) {
                    addrs[ind].type = NABTO_IPV4;
                    memcpy(addrs[ind].v4.addr, &my_addr.sin_addr.s_addr, 4);
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
            NABTO_LOG_ERROR(LOG, "Cannot connect to host");
        } else {
            struct sockaddr_in6 my_addr;
            socklen_t len = sizeof my_addr;
            if(getsockname(s,(struct sockaddr*)&my_addr,&len) == -1) {
                NABTO_LOG_ERROR(LOG, "getsockname failed");
            } else {
                if (memcmp(&my_addr.sin6_addr, &v6any, 16) != 0) {
                    addrs[ind].type = NABTO_IPV6;
                    memcpy(addrs[ind].v6.addr, my_addr.sin6_addr.s6_addr, 16);
                    ind++;
                }
            }
        }
        close(s);
    }
    return ind;
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
    int nfds;
    nfds = select(maxReadFd+1, &readFds, NULL, NULL, NULL);
    if (nfds < 0) {
        NABTO_LOG_ERROR(LOG, "Error in select: (%i) '%s'", errno, strerror(errno));
    } else {
        NABTO_LOG_TRACE(LOG, "select returned with %i file descriptors", nfds);
    }
    return nfds;
}

int nm_select_unix_timed_wait(uint32_t ms)
{
    int nfds;
    struct timeval timeout_val;
    timeout_val.tv_sec = (ms/1000);
    timeout_val.tv_usec = ((ms)%1000)*1000;

    nfds = select(maxReadFd+1, &readFds, NULL, NULL, &timeout_val);
    if (nfds < 0) {
        NABTO_LOG_ERROR(LOG, "Error in select wait: (%i) '%s'", errno, strerror(errno));
    }
    return nfds;
}

void nm_select_unix_read(int nfds)
{
    np_udp_socket* next = head;
    char one;
    NABTO_LOG_TRACE(LOG, "read: %i", nfds);
    while (next != NULL) {
        if (FD_ISSET(next->sock, &readFds)) {
            nm_select_unix_handle_event(next);
        }
        next = next->next;
    }
    if (FD_ISSET(pipefd[0], &readFds)) {
        read(pipefd[0], &one, 1);
    }
    if (FD_ISSET(pipefd[1], &readFds)) {
        read(pipefd[1], &one, 1);
    }
    nm_select_unix_build_fd_sets();
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
    np_udp_socket* sock = (np_udp_socket*)data;

    np_error_code ec = nm_select_unix_create_socket(sock);

    if (ec == NABTO_EC_OK) {
        sock->next = head;
        if (head != NULL) {
            head->prev = sock;
        }
        head = sock;
        write(pipefd[1], "1", 1);
        sock->created.cb(NABTO_EC_OK, sock, sock->created.data);
        return;
    } else {
        sock->created.cb(ec, NULL, sock->created.data);
        free(sock);
        return;
    }
}

void nm_select_unix_event_bind_port(void* data)
{
    np_udp_socket* sock = (np_udp_socket*)data;
    int i;

    np_error_code ec = nm_select_unix_create_socket(sock);

    if (ec == NABTO_EC_OK) {
        if (sock->isIpv6) {
            struct sockaddr_in6 si_me6;
            si_me6.sin6_family = AF_INET6;
            si_me6.sin6_port = htons(sock->created.port);
            si_me6.sin6_addr = in6addr_any;
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
            close(sock->sock);
            sock->created.cb(ec, NULL, sock->created.data);
            free(sock);
            return;
        }
        sock->next = head;
        if (head != NULL) {
            head->prev = sock;
        }
        head = sock;
        write(pipefd[1], "1", 1);
        sock->created.cb(NABTO_EC_OK, sock, sock->created.data);
        return;
    } else {
        sock->created.cb(ec, NULL, sock->created.data);
        free(sock);
        return;
    }
}

void nm_select_unix_event_send_to(void* data)
{
    struct np_udp_send_context* ctx = (struct np_udp_send_context*)data;
    np_udp_socket* sock = ctx->sock;
    ssize_t res;
    if (ctx->ep.ip.type == NABTO_IPV4 && !sock->isIpv6) { // IPv4 addr on IPv4 socket
        struct sockaddr_in srv_addr;
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons (ctx->ep.port);
        memcpy((void*)&srv_addr.sin_addr, ctx->ep.ip.v4.addr, sizeof(srv_addr.sin_addr));
        NABTO_LOG_TRACE(LOG, "Sending to v4: %u.%u.%u.%u:%u", ctx->ep.ip.v4.addr[0], ctx->ep.ip.v4.addr[1], ctx->ep.ip.v4.addr[2], ctx->ep.ip.v4.addr[3], ctx->ep.port);
        res = sendto (sock->sock, pl->buf.start(ctx->buffer), ctx->bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    } else { // IPv6 addr or IPv4 addr on IPv6 socket
        struct sockaddr_in6 srv_addr;
        srv_addr.sin6_family = AF_INET6;
        srv_addr.sin6_flowinfo = 0;
        srv_addr.sin6_scope_id = 0;
        srv_addr.sin6_port = htons (ctx->ep.port);

        if (ctx->ep.ip.type == NABTO_IPV4) { // IPv4 addr on IPv6 socket
            // Map ipv4 to ipv6
            NABTO_LOG_TRACE(LOG, "mapping: %u.%u.%u.%u:%u to IPv6", ctx->ep.ip.v4.addr[0], ctx->ep.ip.v4.addr[1], ctx->ep.ip.v4.addr[2], ctx->ep.ip.v4.addr[3], ctx->ep.port);
            uint8_t* ptr = (uint8_t*)&srv_addr.sin6_addr;
            memset(ptr, 0, 10); // 80  bits of 0
            ptr += 10;
            memset(ptr, 0xFF, 2); // 16 bits of 1
            ptr += 2;
            memcpy(ptr,ctx->ep.ip.v4.addr, 4); // 32 bits of IPv4
        } else { // IPv6 addr copied directly
            NABTO_LOG_TRACE(LOG, "Sending to v6");
            memcpy((void*)&srv_addr.sin6_addr,ctx->ep.ip.v6.addr, 16);
        }
        res = sendto (sock->sock, pl->buf.start(ctx->buffer), ctx->bufferSize, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    }
    if (res < 0) {
        int status = errno;
        NABTO_LOG_TRACE(LOG, "UDP returned error status %i", status);
        if (status == EAGAIN || status == EWOULDBLOCK) {
            // expected
        } else {
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_select_unix_event_send_to", (int) status, strerror(status));
            if (ctx->cb) {
                ctx->cb(NABTO_EC_FAILED_TO_SEND_PACKET, ctx->cbData);
            }
            return;
        }
    }
    if (ctx->cb) {
        ctx->cb(NABTO_EC_OK, ctx->cbData);
    }
    return;
}

void nm_select_unix_event_destroy(void* data)
{
    np_udp_socket* sock = (np_udp_socket*)data;
    if (sock == NULL) {
        return;
    }
    sock->closing = true;
    shutdown(sock->sock, SHUT_RDWR);
    NABTO_LOG_TRACE(LOG, "shutdown with data: %u", sock->des.data);
    return;
}

void nm_select_unix_build_fd_sets()
{
    np_udp_socket* next = head;
    FD_SET(pipefd[0], &readFds);
    maxReadFd = pipefd[0];
    FD_SET(pipefd[1], &readFds);
    maxReadFd = MAX(maxReadFd, pipefd[1]);
    while (next != NULL) {
        if (!next->closing) {
            FD_SET(next->sock, &readFds);
            maxReadFd = MAX(maxReadFd, next->sock);
            next = next->next;
        } else {
            np_udp_socket* tmp;
            tmp = next;
            next = next->next;
            nm_select_unix_free_socket(tmp);
        }
    }
}

np_error_code nm_select_unix_create_socket(np_udp_socket* sock)
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
            close(sock->sock);
            return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
        }
    }
    int flags = fcntl(sock->sock, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(sock->sock, F_SETFL, flags | O_NONBLOCK);


    return NABTO_EC_OK;
}

void nm_select_unix_handle_event(np_udp_socket* sock)
{
    NABTO_LOG_TRACE(LOG, "handle event");
    struct np_udp_endpoint ep;
    ssize_t recvLength;
    uint8_t* start;
    start = pl->buf.start(recvBuf);
    if (sock->isIpv6) {
        struct sockaddr_in6 sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, start,  pl->buf.size(recvBuf), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.v6.addr,&sa.sin6_addr.s6_addr, sizeof(ep.ip.v6.addr));
        ep.port = ntohs(sa.sin6_port);
        ep.ip.type = NABTO_IPV6;
    } else {
        struct sockaddr_in sa;
        socklen_t addrlen = sizeof(sa);
        recvLength = recvfrom(sock->sock, start, pl->buf.size(recvBuf), 0, (struct sockaddr*)&sa, &addrlen);
        memcpy(&ep.ip.v4.addr,&sa.sin_addr.s_addr, sizeof(ep.ip.v4.addr));
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
            NABTO_LOG_ERROR(LOG,"ERROR: (%i) '%s' in nm_select_unix_handle_event", strerror(status), (int) status);
            if(sock->recv.cb) {
                cb = sock->recv.cb;
                sock->recv.cb = NULL;
                cb(NABTO_EC_UDP_SOCKET_ERROR, ep, NULL, 0, sock->recv.data);
            }
            nm_select_unix_free_socket(sock);
            return;
        }
    }
    if (sock->recv.cb) {
        np_udp_packet_received_callback cb = sock->recv.cb;
        sock->recv.cb = NULL;
        NABTO_LOG_TRACE(LOG, "received data, invoking callback");
        cb(NABTO_EC_OK, ep, recvBuf, recvLength, sock->recv.data);
    }
    nm_select_unix_handle_event(sock);
}

void nm_select_unix_free_socket(np_udp_socket* sock)
{
    NABTO_LOG_TRACE(LOG, "shutdown with data: %u", sock->des.data);
    np_udp_socket* next = head;
    if (sock == head) {
        head = sock->next;
    } else {
        while (next != sock) {
            next = next->next;
            if (next == NULL) {
                NABTO_LOG_ERROR(LOG, "tried to remove socket not in the list");
                break;
            }
        }
        if (next) {
            if (next->prev) {
                next->prev->next = next->next;
            }
            if (next->next) {
                next->next->prev = next->prev;
            }
        }
    }

    np_udp_socket_destroyed_callback cb;
    void* cbData;
    close(sock->sock);
    nm_select_unix_cancel_all_events(sock);
    cb = sock->des.cb;
    cbData = sock->des.data;
    free(sock);
    if (cb) {
        cb(NABTO_EC_OK, cbData);
    }
}
