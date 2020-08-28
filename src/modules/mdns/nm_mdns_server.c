#include "nm_mdns_server.h"
#include "nm_mdns_udp_bind.h"

#include <platform/np_logging.h>
#include <platform/np_completion_event.h>
#include <platform/np_udp_wrapper.h>
#include <platform/np_local_ip_wrapper.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_MDNS

#define MAX_LOCAL_IPS 2

static void nm_mdns_socket_opened(const np_error_code ec, void* userData);
static void nm_mdns_recv_packet(struct nm_mdns_server_instance* instance);
static void nm_mdns_packet_recv_wait_completed(const np_error_code ec, void* userData);
static void nm_mdns_send_packet(struct nm_mdns_server_instance* instance, uint16_t id, bool unicastResponse);
static void nm_mdns_packet_sent(const np_error_code ec, void* userData);

static void nm_mdns_update_local_ips(struct nm_mdns_server* mdns);

static void publish_service(struct np_mdns* obj, uint16_t port, const char* instanceName, struct nn_string_set* subtypes, struct nn_string_map* txtItems);

static struct np_mdns_functions module = {
    .publish_service = publish_service
};

struct np_mdns nm_mdns_server_get_impl(struct nm_mdns_server* server)
{
    struct np_mdns obj;
    obj.mptr = &module;
    obj.data = server;
    return obj;
}

static np_error_code instance_init(struct nm_mdns_server_instance* instance, struct nm_mdns_server* server, bool v4)
{
    np_error_code ec;

    instance->done = false;

    instance->server = server;

    ec = np_udp_create(&instance->server->udp, &instance->socket);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_completion_event_init(&instance->server->eq, &instance->openedCompletionEvent, nm_mdns_socket_opened, instance);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(&instance->server->eq, &instance->recvWaitCompletionEvent, nm_mdns_packet_recv_wait_completed, instance);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(&instance->server->eq, &instance->sendCompletionEvent, nm_mdns_packet_sent, instance);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    if (v4) {
        instance->sendEp.ip.type = NABTO_IPV4;
        instance->sendEp.port = 5353;
        uint8_t addr[] = { 0xe0, 0x00, 0x00, 0xfb };
        memcpy(instance->sendEp.ip.ip.v4, addr, 4);
    } else {
        instance->sendEp.ip.type = NABTO_IPV6;
        instance->sendEp.port = 5353;
        uint8_t addr[] = { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb };
        memcpy(instance->sendEp.ip.ip.v6, addr, 16);
    }

    return ec;
}

static void instance_deinit(struct nm_mdns_server_instance* instance)
{
    np_completion_event_deinit(&instance->openedCompletionEvent);
    np_completion_event_deinit(&instance->recvWaitCompletionEvent);
    np_completion_event_deinit(&instance->sendCompletionEvent);
    np_udp_destroy(&instance->server->udp, instance->socket);
}

// initialize the mdns server
np_error_code nm_mdns_server_init(struct nm_mdns_server* server, struct np_event_queue* eq, struct np_udp* udp, struct nm_mdns_udp_bind* mdnsUdpBind, struct np_local_ip* localIp)
{
    server->stopped = false;
    server->running = false;
    server->eq = *eq;
    server->udp = *udp;
    server->mdnsUdpBind = *mdnsUdpBind;
    server->localIp = *localIp;

    np_error_code ec;
    ec = instance_init(&server->v4, server, true);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    return instance_init(&server->v6, server, false);
}

// deinitialize the mdns server
void nm_mdns_server_deinit(struct nm_mdns_server* server)
{
    instance_deinit(&server->v4);
    instance_deinit(&server->v6);
}

void nm_mdns_server_stop(struct nm_mdns_server* server)
{
    server->stopped = true;
    np_udp_abort(&server->udp, server->v4.socket);
    np_udp_abort(&server->udp, server->v6.socket);
}

void publish_service(struct np_mdns* obj, uint16_t port, const char* instanceName, struct nn_string_set* subtypes, struct nn_string_map* txtItems)
{
    struct nm_mdns_server* server = obj->data;
    if (server->running) {
        // publishing more than one service is not supported
        return;
    }
    server->running = true;
    server->port = port;
    nabto_mdns_server_init(&server->mdnsServer);
    nabto_mdns_server_update_info(&server->mdnsServer, instanceName, subtypes, txtItems);

    nm_mdns_udp_bind_async_ipv4(&server->mdnsUdpBind, server->v4.socket, &server->v4.openedCompletionEvent);
    nm_mdns_udp_bind_async_ipv6(&server->mdnsUdpBind, server->v6.socket, &server->v6.openedCompletionEvent);
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

void nm_mdns_socket_opened(const np_error_code ec, void* userData)
{
    struct nm_mdns_server_instance* instance = userData;
    if (instance->server->stopped) {
        instance->done = true;
        return;
    }
    if (ec == NABTO_EC_OK) {
        // dont start receiving until send callback returns to ensure send buffer is not overwritten
        nm_mdns_send_packet(instance, 0, false);
    } else {
        NABTO_LOG_TRACE(LOG, "socket open failed with (%u) %s", ec, np_error_code_to_string(ec));
        instance->done = true;
    }
}

void nm_mdns_recv_packet(struct nm_mdns_server_instance* instance)
{
    np_udp_async_recv_wait(&instance->server->udp, instance->socket, &instance->recvWaitCompletionEvent);
}

void nm_mdns_packet_recv_wait_completed(const np_error_code ec, void* userData)
{
    struct nm_mdns_server_instance* instance = userData;
    if (ec == NABTO_EC_OK) {
        size_t recvSize;
        uint8_t* recvBuffer = instance->recvBuffer;
        size_t recvBufferSize = 1500;
        np_error_code ec = np_udp_recv_from(&instance->server->udp, instance->socket, &instance->recvEp, recvBuffer, recvBufferSize, &recvSize);
        if (ec == NABTO_EC_OK) {
            uint16_t id;

            if (nabto_mdns_server_handle_packet(&instance->server->mdnsServer,
                                                recvBuffer, recvSize, &id))
            {
                bool unicastResponse = false;
                if (instance->recvEp.port != 5353) {
                    unicastResponse = true;
                }
                nm_mdns_send_packet(instance, id, unicastResponse);
                // next receive is started by send
                return;
            }
        }

        if (ec == NABTO_EC_OK /*|| ec == NABTO_EC_AGAIN*/) {
            nm_mdns_recv_packet(instance);
            return;
        }
    }

    // an error occured
    instance->done = true;
}

void nm_mdns_send_packet(struct nm_mdns_server_instance* instance, uint16_t id, bool unicastResponse)
{
    size_t written;
    uint16_t port = instance->server->port;
    nm_mdns_update_local_ips(instance->server);

    struct np_udp_endpoint* ep = &instance->sendEp;
    if (unicastResponse) {
        ep = &instance->recvEp;
    }

    if (port > 0) {
        if (nabto_mdns_server_build_packet(&instance->server->mdnsServer, id, unicastResponse, instance->server->localIps, instance->server->localIpsSize, port, instance->sendBuffer, 1500, &written))
        {
            np_udp_async_send_to(&instance->server->udp, instance->socket,
                                 ep, instance->sendBuffer, (uint16_t)written,
                                 &instance->sendCompletionEvent);
            return;
        }
    }
    nm_mdns_recv_packet(instance);
}

void nm_mdns_packet_sent(const np_error_code ec, void* userData)
{
    struct nm_mdns_server_instance* instance = userData;
    if (instance->server->stopped) {
        instance->done = true;
        return;
    }
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "v4 packet sent callback with error: (%u) %s", ec, np_error_code_to_string(ec));
    }
    nm_mdns_recv_packet(instance);
}

void nm_mdns_udp_bind_async_ipv4(struct nm_mdns_udp_bind* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    return udp->mptr->async_bind_mdns_ipv4(sock, completionEvent);
}

void nm_mdns_udp_bind_async_ipv6(struct nm_mdns_udp_bind* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    return udp->mptr->async_bind_mdns_ipv6(sock, completionEvent);
}
