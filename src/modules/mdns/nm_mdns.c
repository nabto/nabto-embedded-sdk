#include "nm_mdns.h"

#include <platform/np_logging.h>
#include <platform/np_completion_event.h>
#include <platform/np_udp_wrapper.h>
#include <platform/np_local_ip_wrapper.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_MDNS

#define MAX_LOCAL_IPS 2

static void nm_mdns_socket_opened_v4(const np_error_code ec, void* userData);
static void nm_mdns_recv_packet_v4(struct nm_mdns_server* mdns);
static void nm_mdns_packet_recv_wait_completed_v4(const np_error_code ec, void* userData);
static void nm_mdns_send_packet_v4(struct nm_mdns_server* mdns);
static void nm_mdns_packet_sent_v4(const np_error_code ec, void* userData);

static void nm_mdns_socket_opened_v6(const np_error_code ec, void* userData);
static void nm_mdns_recv_packet_v6(struct nm_mdns_server* mdns);
static void nm_mdns_packet_recv_wait_completed_v6(const np_error_code ec, void* userData);
static void nm_mdns_send_packet_v6(struct nm_mdns_server* mdns);
static void nm_mdns_packet_sent_v6(const np_error_code ec, void* userData);

static void nm_mdns_update_local_ips(struct nm_mdns_server* mdns);

static void publish_service(struct np_mdns* obj, uint16_t port, const char* productId, const char* deviceId);

static struct np_mdns_functions vtable = {
    .publish_service = publish_service
};

struct np_mdns nm_mdns_get_impl(struct nm_mdns_server* server)
{
    struct np_mdns obj;
    obj.vptr = &vtable;
    obj.data = server;
    return obj;
}

// initialize the mdns server
np_error_code nm_mdns_init(struct nm_mdns_server* server, struct np_event_queue* eq, struct np_udp* udp, struct np_local_ip* localIp)
{
    server->stopped = false;
    server->running = false;
    server->v4Done = false;
    server->v6Done = false;
    server->eq = *eq;
    server->udp = *udp;
    server->localIp = *localIp;

    np_error_code ec;
    ec = np_udp_create(udp, &server->socketv4);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_udp_create(udp, &server->socketv6);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(eq, &server->v4OpenedCompletionEvent, nm_mdns_socket_opened_v4, server);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_completion_event_init(eq, &server->v6OpenedCompletionEvent, nm_mdns_socket_opened_v6, server);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(eq, &server->v4RecvWaitCompletionEvent, nm_mdns_packet_recv_wait_completed_v4, server);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(eq, &server->v6RecvWaitCompletionEvent, nm_mdns_packet_recv_wait_completed_v6, server);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(eq, &server->v4SendCompletionEvent, nm_mdns_packet_sent_v4, server);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(eq, &server->v6SendCompletionEvent, nm_mdns_packet_sent_v6, server);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    return NABTO_EC_OK;
}

// deinitialize the mdns server
void nm_mdns_deinit(struct nm_mdns_server* mdns)
{
    np_completion_event_deinit(&mdns->v4OpenedCompletionEvent);
    np_completion_event_deinit(&mdns->v6OpenedCompletionEvent);

    np_completion_event_deinit(&mdns->v4RecvWaitCompletionEvent);
    np_completion_event_deinit(&mdns->v6RecvWaitCompletionEvent);

    np_completion_event_deinit(&mdns->v4SendCompletionEvent);
    np_completion_event_deinit(&mdns->v6SendCompletionEvent);

    np_udp_destroy(&mdns->udp, mdns->socketv4);
    np_udp_destroy(&mdns->udp, mdns->socketv6);

    free(mdns);
}

void nm_mdns_stop(struct nm_mdns_server* mdns)
{
    mdns->stopped = true;
    np_udp_abort(&mdns->udp, mdns->socketv4);
    np_udp_abort(&mdns->udp, mdns->socketv6);
}

void publish_service(struct np_mdns* obj, uint16_t port, const char* productId, const char* deviceId)
{
    struct nm_mdns_server* server = obj->data;
    if (server->running) {
        // publishing more than one service is not supported
        return;
    }
    server->running = true;
    server->port = port;
    nabto_mdns_server_init(&server->mdnsServer, deviceId, productId,
                           deviceId /*serviceName must be unique*/,
                           deviceId /*hostname must be unique*/);

    np_udp_async_bind_mdns_ipv4(&server->udp, server->socketv4, &server->v4OpenedCompletionEvent);
    np_udp_async_bind_mdns_ipv6(&server->udp, server->socketv6, &server->v6OpenedCompletionEvent);
}

void nm_mdns_update_local_ips(struct nm_mdns_server* mdns)
{
    struct np_ip_address ips[MAX_LOCAL_IPS];
    size_t ipsFound = np_local_ip_get_local_ips(&mdns->localIp, ips, MAX_LOCAL_IPS);

    mdns->localIpsSize = ipsFound;
    for(int i = 0; i < ipsFound; i++) {
        struct np_ip_address* ip = &ips[i];
        struct nabto_mdns_ip_address* mdnsIp = &mdns->localIps[i];
        if (ip->type == NABTO_IPV4) {
            mdnsIp->type = NABTO_MDNS_IPV4;
            memcpy(mdnsIp->v4.addr, ip->ip.v4, 4);
        } else {
            mdnsIp->type = NABTO_MDNS_IPV6;
            memcpy(mdnsIp->v6.addr, ip->ip.v6, 16);
        }
    }
}

void nm_mdns_socket_opened_v4(const np_error_code ec, void* userData)
{
    struct nm_mdns_server* mdns = userData;
    if (mdns->stopped) {
        mdns->v4Done = true;
        return;
    }
    if (ec == NABTO_EC_OK) {
        // dont start receiving until send callback returns to ensure send buffer is not overwritten
        nm_mdns_send_packet_v4(mdns);
    } else {
        NABTO_LOG_TRACE(LOG, "V4 socket open failed with (%u) %s", ec, np_error_code_to_string(ec));
        mdns->v4Done = true;
    }
}

void nm_mdns_recv_packet_v4(struct nm_mdns_server* mdns)
{
    np_udp_async_recv_wait(&mdns->udp, mdns->socketv4, &mdns->v4RecvWaitCompletionEvent);
}

void nm_mdns_packet_recv_wait_completed_v4(const np_error_code ec, void* userData)
{
    struct nm_mdns_server* mdns = userData;
    if (ec == NABTO_EC_OK) {
        size_t recvSize;
        struct np_udp_endpoint recvEp;
        uint8_t* recvBuffer = mdns->recvBuffer;
        size_t recvBufferSize = 1500;
        np_error_code ec = np_udp_recv_from(&mdns->udp, mdns->socketv4, &recvEp, recvBuffer, recvBufferSize, &recvSize);
        if (ec == NABTO_EC_OK) {
            if (nabto_mdns_server_handle_packet(&mdns->mdnsServer,
                                                recvBuffer, recvSize))
            {
                nm_mdns_send_packet_v4(mdns);
                // next receive is started by send
                return;
            }
        }

        if (ec == NABTO_EC_OK /*|| ec == NABTO_EC_AGAIN*/) {
            nm_mdns_recv_packet_v4(mdns);
            return;
        }
    }

    // an error occured
    mdns->v4Done = true;

    if (mdns->stopped) {
        return;
    }
}

void nm_mdns_send_packet_v4(struct nm_mdns_server* mdns)
{
    size_t written;
    struct np_udp_endpoint ep;
    ep.ip.type = NABTO_IPV4;
    ep.port = 5353;
    uint8_t addr[] = { 0xe0, 0x00, 0x00, 0xfb };
    memcpy(ep.ip.ip.v4, addr, 4);
    uint16_t port = mdns->port;
    nm_mdns_update_local_ips(mdns);
    if (port > 0) {
        if (nabto_mdns_server_build_packet(&mdns->mdnsServer, mdns->localIps, mdns->localIpsSize, port, mdns->sendBufferV4, 1500, &written))
        {
            np_udp_async_send_to(&mdns->udp, mdns->socketv4,
                                 &ep, mdns->sendBufferV4, (uint16_t)written,
                                 &mdns->v4SendCompletionEvent);
            return;
        }
    }
    nm_mdns_recv_packet_v4(mdns);
}

void nm_mdns_packet_sent_v4(const np_error_code ec, void* userData)
{
    struct nm_mdns_server* mdns = userData;
    if (mdns->stopped) {
        mdns->v4Done = true;
        return;
    }
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "v4 packet sent callback with error: (%u) %s", ec, np_error_code_to_string(ec));
    }
    nm_mdns_recv_packet_v4(mdns);
}

void nm_mdns_socket_opened_v6(const np_error_code ec, void* userData)
{
    struct nm_mdns_server* mdns = userData;
    if (mdns->stopped) {
        mdns->v6Done = true;
        return;
    }
    if (ec == NABTO_EC_OK) {
        // dont start receiving untill send callback returns to ensure send buffer is not overwritten
        nm_mdns_send_packet_v6(mdns);
    } else {
        NABTO_LOG_INFO(LOG, "V6 socket open failed with (%u) %s", ec, np_error_code_to_string(ec));
        mdns->v6Done = true;
    }
}

void nm_mdns_recv_packet_v6(struct nm_mdns_server* mdns)
{
    np_udp_async_recv_wait(&mdns->udp, mdns->socketv6, &mdns->v6RecvWaitCompletionEvent);
}

void nm_mdns_packet_recv_wait_completed_v6(const np_error_code ec, void* userData)
{
    struct nm_mdns_server* mdns = userData;
    if (ec == NABTO_EC_OK) {
        size_t recvSize;

        struct np_udp_endpoint ep;
        np_error_code ec = np_udp_recv_from(&mdns->udp, mdns->socketv6, &ep, mdns->recvBuffer, 1500, &recvSize);
        if (ec == NABTO_EC_OK) {
            if (nabto_mdns_server_handle_packet(&mdns->mdnsServer,
                                                mdns->recvBuffer, recvSize))
            {
                nm_mdns_send_packet_v6(mdns);
                // next receive is started by send
                return;
            }
        }

        if (ec == NABTO_EC_OK || ec == NABTO_EC_AGAIN) {
            nm_mdns_recv_packet_v6(mdns);
            return;
        }
    }

    // an error occured
    mdns->v6Done = true;

    if (mdns->stopped) {
        return;
    }
}

void nm_mdns_send_packet_v6(struct nm_mdns_server* mdns)
{
    size_t written;
    struct np_udp_endpoint ep;
    ep.ip.type = NABTO_IPV6;
    ep.port = 5353;
    uint8_t addr[] = { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb };
    memcpy(ep.ip.ip.v6, addr, 16);

    uint16_t port = mdns->port;
    nm_mdns_update_local_ips(mdns);
    if (port > 0) {
        if (nabto_mdns_server_build_packet(&mdns->mdnsServer, mdns->localIps, mdns->localIpsSize, port, mdns->sendBufferV6, 1500, &written)) {
            np_udp_async_send_to(&mdns->udp, mdns->socketv6,
                                 &ep, mdns->sendBufferV6, (uint16_t)written,
                                 &mdns->v6SendCompletionEvent);
            return;
        }
    }
    nm_mdns_recv_packet_v6(mdns);
}

void nm_mdns_packet_sent_v6(const np_error_code ec, void* userData)
{
    struct nm_mdns_server* mdns = userData;
    if (mdns->stopped) {
        mdns->v6Done = true;
        return;
    }
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "v6 packet sent callback with error: (%u) %s", ec, np_error_code_to_string(ec));
    }
    nm_mdns_recv_packet_v6(mdns);
}
