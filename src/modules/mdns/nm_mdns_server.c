#include "nm_mdns_server.h"
#include "nm_mdns_udp_bind.h"

#include <platform/np_allocator.h>
#include <platform/np_completion_event.h>
#include <platform/np_local_ip_wrapper.h>
#include <platform/np_logging.h>
#include <platform/np_udp_wrapper.h>


#define LOG NABTO_LOG_MODULE_MDNS

#define MAX_LOCAL_IPS 2

static void nm_mdns_socket_opened(np_error_code ec, void* userData);
static void nm_mdns_recv_packet(struct nm_mdns_server_instance* instance);
static void nm_mdns_packet_recv_wait_completed(np_error_code ec, void* userData);
static void nm_mdns_send_packet(struct nm_mdns_server_instance* instance, uint16_t id, bool unicastResponse);
static void nm_mdns_packet_sent(np_error_code ec, void* userData);

static void nm_mdns_update_local_ips(struct nm_mdns_server* mdns);

static void publish_service(struct np_mdns* obj, uint16_t port, const char* instanceName, struct nn_string_set* subtypes, struct nn_string_map* txtItems);
static void unpublish_service(struct np_mdns* obj);

/*
* Close a server instance, the completion event is resolved with NABTO_EC_OK if
* the close went as good as possible.
*/
static void nm_mdns_server_close_instance(struct nm_mdns_server_instance* instance, struct np_completion_event* completionEvent);
static void v6_closed(const np_error_code ec, void* userData);
static void v4_closed(const np_error_code ec, void* userData);

static struct np_mdns_functions module = {
    .publish_service = publish_service,
    .unpublish_service = unpublish_service
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
    instance->sendBuffer = NULL;
    instance->server = server;

    np_error_code ec = np_udp_create(&instance->server->udp, &instance->socket);
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
    server->state = NM_MDNS_SERVER_NEW;
    server->eq = *eq;
    server->udp = *udp;
    server->mdnsUdpBind = *mdnsUdpBind;
    server->localIp = *localIp;

    np_error_code ec = np_completion_event_init(eq, &server->instanceCloseCompletionEvent, NULL, NULL);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = instance_init(&server->v4, server, true);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    return instance_init(&server->v6, server, false);
}

// deinitialize the mdns server
void nm_mdns_server_deinit(struct nm_mdns_server* server)
{
    instance_deinit(&server->v6);
    instance_deinit(&server->v4);
    np_completion_event_deinit(&server->instanceCloseCompletionEvent);
}

void v4_closed(const np_error_code ec, void* userData)
{
    struct nm_mdns_server* server = userData;
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_INFO(LOG, "v4 closed with error. Trying V6");
    }
    np_completion_event_reinit(&server->instanceCloseCompletionEvent, v6_closed, server);
    nm_mdns_server_close_instance(&server->v6, &server->instanceCloseCompletionEvent);
}

void v6_closed(const np_error_code ec, void* userData)
{
    struct nm_mdns_server* server = userData;
    np_completion_event_resolve(server->closedCompletionEvent, ec);
    server->closedCompletionEvent = NULL;
}

void nm_mdns_server_close(struct nm_mdns_server* server, struct np_completion_event* closedEvent)
{
    if (server->closedCompletionEvent != NULL) {
        np_completion_event_resolve(closedEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }
    if (server->state != NM_MDNS_SERVER_RUNNING) {
        np_completion_event_resolve(closedEvent, NABTO_EC_OK);
        return;
    }
    server->state = NM_MDNS_SERVER_CLOSED;
    server->closedCompletionEvent = closedEvent;
    np_completion_event_reinit(&server->instanceCloseCompletionEvent, v4_closed, server);
    nm_mdns_server_close_instance(&server->v4, &server->instanceCloseCompletionEvent);
}

void nm_mnds_server_close_instance_udp_sent_callback(const np_error_code ec, void* userData)
{
    struct nm_mdns_server_instance* instance = (struct nm_mdns_server_instance*)userData;
    np_free(instance->sendBuffer);
    instance->sendBuffer = NULL;
    if (ec == NABTO_EC_OK || ec == NABTO_EC_FAILED_TO_SEND_PACKET) {
        np_completion_event_resolve(instance->closeCompletionEvent, NABTO_EC_OK);
        return;
    }
    np_completion_event_resolve(instance->closeCompletionEvent, ec);
}

void nm_mdns_server_close_instance(struct nm_mdns_server_instance* instance, struct np_completion_event* completionEvent)
{
    if (instance->sendBuffer != NULL) {
        NABTO_LOG_INFO(LOG, "Tried to send mDNS goodbye but is already sending");
        np_completion_event_resolve(completionEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }

    instance->closeCompletionEvent = completionEvent;

    size_t written = 0;
    uint16_t port = instance->server->port;
    nm_mdns_update_local_ips(instance->server);

    struct np_udp_endpoint* ep = &instance->sendEp;

    np_completion_event_reinit(&instance->sendCompletionEvent, nm_mnds_server_close_instance_udp_sent_callback, instance);

    if (port > 0) {
        instance->sendBuffer = np_calloc(1, NM_MDNS_SEND_BUFFER_SIZE);
        if (instance->sendBuffer == NULL) {
            NABTO_LOG_ERROR(LOG, "Cannot allocate buffer for sending mdns goodbye packet");
            np_completion_event_resolve(completionEvent, NABTO_EC_OUT_OF_MEMORY);
            return;
        }

        if (nabto_mdns_server_build_packet(&instance->server->mdnsServer, 0, false, true, instance->server->localIps, instance->server->localIpsSize, port, instance->sendBuffer, 1500, &written))
        {
            np_udp_async_send_to(&instance->server->udp, instance->socket,
                                 ep, instance->sendBuffer, (uint16_t)written,
                                 &instance->sendCompletionEvent);
            return;
        }
        np_free(instance->sendBuffer);
        instance->sendBuffer = NULL;
    }
    np_completion_event_resolve(completionEvent, NABTO_EC_UNKNOWN);
}

void nm_mdns_server_instance_stop(struct nm_mdns_server* server, struct nm_mdns_server_instance* instance)
{
    np_udp_abort(&server->udp, instance->socket);
}

void nm_mdns_server_stop(struct nm_mdns_server* server)
{
    server->state = NM_MDNS_SERVER_STOPPED;
    nm_mdns_server_instance_stop(server, &server->v4);
    nm_mdns_server_instance_stop(server, &server->v6);
}

void publish_service(struct np_mdns* obj, uint16_t port, const char* instanceName, struct nn_string_set* subtypes, struct nn_string_map* txtItems)
{
    struct nm_mdns_server* server = obj->data;


    if (server->state == NM_MDNS_SERVER_NEW) {
        server->state = NM_MDNS_SERVER_RUNNING;
        nabto_mdns_server_init(&server->mdnsServer);

        nm_mdns_udp_bind_async_ipv4(&server->mdnsUdpBind, server->v4.socket, &server->v4.openedCompletionEvent);
        nm_mdns_udp_bind_async_ipv6(&server->mdnsUdpBind, server->v6.socket, &server->v6.openedCompletionEvent);
    }

    if (server->state == NM_MDNS_SERVER_RUNNING) {
        // Do not publish from closed/stopped states
        server->port = port;
        nabto_mdns_server_update_info(&server->mdnsServer, instanceName, subtypes, txtItems);
    }
}

void unpublish_service(struct np_mdns* obj)
{
    (void)obj;
    // do nothing
}

void nm_mdns_update_local_ips(struct nm_mdns_server* mdns)
{
    struct np_ip_address ips[MAX_LOCAL_IPS];
    size_t ipsFound = np_local_ip_get_local_ips(&mdns->localIp, ips, MAX_LOCAL_IPS);

    mdns->localIpsSize = ipsFound;
    for(size_t i = 0; i < ipsFound; i++) {
        struct np_ip_address* ip = &ips[i];
        struct nn_ip_address* mdnsIp = &mdns->localIps[i];
        if (ip->type == NABTO_IPV4) {
            mdnsIp->type = NN_IPV4;
            memcpy(mdnsIp->ip.v4, ip->ip.v4, 4);
        } else {
            mdnsIp->type = NN_IPV6;
            memcpy(mdnsIp->ip.v6, ip->ip.v6, 16);
        }
    }
}

void nm_mdns_socket_opened(const np_error_code ec, void* userData)
{
    struct nm_mdns_server_instance* instance = userData;
    if (instance->server->state == NM_MDNS_SERVER_STOPPED ||
        instance->server->state == NM_MDNS_SERVER_CLOSED) {
        return;
    }
    if (ec == NABTO_EC_OK) {
        // dont start receiving until send callback returns to ensure send buffer is not overwritten
        nm_mdns_send_packet(instance, 0, false);
    } else {
        NABTO_LOG_TRACE(LOG, "socket open failed with (%u) %s", ec, np_error_code_to_string(ec));
    }
}

void nm_mdns_recv_packet(struct nm_mdns_server_instance* instance)
{
    if (instance->server->state == NM_MDNS_SERVER_RUNNING) {
        np_udp_async_recv_wait(&instance->server->udp, instance->socket, &instance->recvWaitCompletionEvent);
    }
}

void nm_mdns_packet_recv_wait_completed(const np_error_code ecIn, void* userData)
{
    struct nm_mdns_server_instance* instance = userData;

    if (instance->server->state == NM_MDNS_SERVER_STOPPED ||
        instance->server->state == NM_MDNS_SERVER_CLOSED ||
        ecIn == NABTO_EC_ABORTED) {
        return;
    }

    if (ecIn != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "The mDNS server has received an unrecoverable error while receiving from the UDP socket. '%s'", np_error_code_to_string(ecIn));
        return;
    }

    size_t recvSize = 0;
    size_t recvBufferSize = 1500;
    uint8_t* recvBuffer = np_calloc(1, recvBufferSize);
    if (recvBuffer == NULL) {
        // Discard the UDP packet.
        uint8_t dummyBuffer[1];
        np_error_code ec = np_udp_recv_from(&instance->server->udp, instance->socket, &instance->recvEp, dummyBuffer, sizeof(dummyBuffer), &recvSize);
        if (ec == NABTO_EC_OK || ec == NABTO_EC_AGAIN) {
            nm_mdns_recv_packet(instance);
        } else if (ec == NABTO_EC_ABORTED) {
            // Ok since the application has closed the socket
        } else {
            NABTO_LOG_ERROR(LOG, "The mDNS server has stopped receiving packets as an unrecoverable error occured on the UDP socket. '%s'", np_error_code_to_string(ec));
        }
        return;
    }
    bool doRecv = true;  // set to false if the nm_mdns_send_packet initiates the next recv.

    np_error_code ec = np_udp_recv_from(&instance->server->udp, instance->socket, &instance->recvEp, recvBuffer, recvBufferSize, &recvSize);
    if (ec == NABTO_EC_OK) {
        uint16_t id = 0;

        if (nabto_mdns_server_handle_packet(&instance->server->mdnsServer,
                                            recvBuffer, recvSize, &id)) {
            bool unicastResponse = false;
            if (instance->recvEp.port != 5353) {
                unicastResponse = true;
            }
            nm_mdns_send_packet(instance, id, unicastResponse);
            doRecv = false;
        }
    }

    np_free(recvBuffer);
    if (ec == NABTO_EC_OK || ec == NABTO_EC_AGAIN) {
        if (doRecv) {
            nm_mdns_recv_packet(instance);
        }
    } else if (ec == NABTO_EC_ABORTED) {
        // Ok since the application has closed the socket.
    } else {
        NABTO_LOG_ERROR(LOG, "The mDNS server has stopped receiving packets as an unrecoverable error occured on the UDP socket. '%s'", np_error_code_to_string(ec));
    }
}

void nm_mdns_send_packet(struct nm_mdns_server_instance* instance, uint16_t id, bool unicastResponse)
{
    uint16_t port = instance->server->port;

    if (instance->server->state == NM_MDNS_SERVER_RUNNING &&
        instance->sendBuffer == NULL &&
        port > 0) {
        size_t written = 0;
        nm_mdns_update_local_ips(instance->server);

        struct np_udp_endpoint* ep = &instance->sendEp;
        if (unicastResponse) {
            ep = &instance->recvEp;
        }
        instance->sendBuffer = np_calloc(1, NM_MDNS_SEND_BUFFER_SIZE);
        if (instance->sendBuffer == NULL) {
            NABTO_LOG_ERROR(LOG, "Cannot allocate buffer for sending mdns packet");
        } else {
            if (nabto_mdns_server_build_packet(&instance->server->mdnsServer, id, unicastResponse, false, instance->server->localIps, instance->server->localIpsSize, port, instance->sendBuffer, NM_MDNS_SEND_BUFFER_SIZE, &written))
            {
                np_udp_async_send_to(&instance->server->udp, instance->socket,
                                     ep, instance->sendBuffer, (uint16_t)written,
                                     &instance->sendCompletionEvent);
                return;
            }
            np_free(instance->sendBuffer);
            instance->sendBuffer = NULL;
        }
    }
    nm_mdns_recv_packet(instance);
}

void nm_mdns_packet_sent(const np_error_code ec, void* userData)
{
    struct nm_mdns_server_instance* instance = userData;
    np_free(instance->sendBuffer);
    instance->sendBuffer = NULL;
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "mDNS UDP send callback resolved with error: (%u) %s", ec, np_error_code_to_string(ec));
    }

    nm_mdns_recv_packet(instance);
}

void nm_mdns_udp_bind_async_ipv4(struct nm_mdns_udp_bind* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    udp->mptr->async_bind_mdns_ipv4(sock, completionEvent);
}

void nm_mdns_udp_bind_async_ipv6(struct nm_mdns_udp_bind* udp, struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    udp->mptr->async_bind_mdns_ipv6(sock, completionEvent);
}
