#include "nm_mdns.h"
#include <platform/np_logging.h>
#include <platform/np_completion_event.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_MDNS

#define MAX_LOCAL_IPS 2

struct np_mdns_context {
    struct np_platform* pl;
    bool stopped;
    bool v4Done;
    bool v6Done;
    np_mdns_get_port getPort;
    void* getPortUserData;
    struct nabto_mdns_server_context mdnsServer;
    struct np_udp_socket* socketv4;
    struct np_udp_socket* socketv6;
    struct nabto_mdns_ip_address localIps[MAX_LOCAL_IPS];
    size_t localIpsSize;
    struct np_communication_buffer* sendBufferv4;
    struct np_communication_buffer* sendBufferv6;
    struct np_communication_buffer* recvBuffer;

    struct np_completion_event v4OpenedCompletionEvent;
    struct np_completion_event v6OpenedCompletionEvent;
    struct np_completion_event v4RecvWaitCompletionEvent;
    struct np_completion_event v6RecvWaitCompletionEvent;
    struct np_completion_event v4SendCompletionEvent;
    struct np_completion_event v6SendCompletionEvent;
};

static np_error_code mdns_create(struct np_platform* pl, const char* productId, const char* deviceId, np_mdns_get_port getPort, void* getPortUserData, struct np_mdns_context** mdns);

static void mdns_destroy(struct np_mdns_context* mdns);

static void mdns_start(struct np_mdns_context* mdns);
static void mdns_stop(struct np_mdns_context* mdns);

static void nm_mdns_socket_opened_v4(const np_error_code ec, void* userData);
static void nm_mdns_recv_packet_v4(struct np_mdns_context* mdns);
static void nm_mdns_packet_recv_wait_completed_v4(const np_error_code ec, void* userData);
static void nm_mdns_send_packet_v4(struct np_mdns_context* mdns);
static void nm_mdns_packet_sent_v4(const np_error_code ec, void* userData);

static void nm_mdns_socket_opened_v6(const np_error_code ec, void* userData);
static void nm_mdns_recv_packet_v6(struct np_mdns_context* mdns);
static void nm_mdns_packet_recv_wait_completed_v6(const np_error_code ec, void* userData);
static void nm_mdns_send_packet_v6(struct np_mdns_context* mdns);
static void nm_mdns_packet_sent_v6(const np_error_code ec, void* userData);

static void nm_mdns_update_local_ips(struct np_mdns_context* mdns);

void nm_mdns_init(struct np_platform* pl)
{
    // todo add create and destroy.
    pl->mdns.create = &mdns_create;
    pl->mdns.destroy = &mdns_destroy;
    pl->mdns.start = &mdns_start;
    pl->mdns.stop = &mdns_stop;

}

void mdns_stop(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    mdns->stopped = true;
    pl->udp.abort(mdns->socketv4);
    pl->udp.abort(mdns->socketv6);
}

void nm_mdns_force_free(struct np_mdns_context* mdns)
{
    mdns->v4Done = true;
    mdns->v6Done = true;
}

np_error_code mdns_create(struct np_platform* pl, const char* productId, const char* deviceId, np_mdns_get_port getPort, void* getPortUserData, struct np_mdns_context** mdns)
{

    struct np_mdns_context* ctx = calloc(1, sizeof(struct np_mdns_context));
    if (ctx == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->stopped = false;
    ctx->v4Done = false;
    ctx->v6Done = false;
    ctx->pl = pl;
    ctx->sendBufferv4 = pl->buf.allocate();
    ctx->sendBufferv6 = pl->buf.allocate();
    ctx->recvBuffer = pl->buf.allocate();
    if (!ctx->sendBufferv4 ||
        !ctx->sendBufferv6 ||
        !ctx->recvBuffer)
    {
        nm_mdns_force_free(ctx);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    ctx->getPort = getPort;
    ctx->getPortUserData = getPortUserData;
    np_error_code ec;
    ec = pl->udp.create(pl, &ctx->socketv4);
    if (ec != NABTO_EC_OK) {
        nm_mdns_force_free(ctx);
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ec = pl->udp.create(pl, &ctx->socketv6);
    if (ec != NABTO_EC_OK) {
        nm_mdns_force_free(ctx);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    nabto_mdns_server_init(&ctx->mdnsServer, deviceId, productId,
                           deviceId /*serviceName must be unique*/,
                           deviceId /*hostname must be unique*/);

    // TODO check ec
    ec = np_completion_event_init(pl, &ctx->v4OpenedCompletionEvent, nm_mdns_socket_opened_v4, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_completion_event_init(pl, &ctx->v6OpenedCompletionEvent, nm_mdns_socket_opened_v6, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(pl, &ctx->v4RecvWaitCompletionEvent, nm_mdns_packet_recv_wait_completed_v4, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(pl, &ctx->v6RecvWaitCompletionEvent, nm_mdns_packet_recv_wait_completed_v6, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(pl, &ctx->v4SendCompletionEvent, nm_mdns_packet_sent_v4, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(pl, &ctx->v6SendCompletionEvent, nm_mdns_packet_sent_v6, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    *mdns = ctx;
    return NABTO_EC_OK;
}

void mdns_destroy(struct np_mdns_context* mdns)
{
    np_completion_event_deinit(&mdns->v4OpenedCompletionEvent);
    np_completion_event_deinit(&mdns->v6OpenedCompletionEvent);

    np_completion_event_deinit(&mdns->v4RecvWaitCompletionEvent);
    np_completion_event_deinit(&mdns->v6RecvWaitCompletionEvent);

    np_completion_event_deinit(&mdns->v4SendCompletionEvent);
    np_completion_event_deinit(&mdns->v6SendCompletionEvent);

    struct np_platform* pl = mdns->pl;
    pl->udp.destroy(mdns->socketv4);
    pl->udp.destroy(mdns->socketv6);


    pl->buf.free(mdns->sendBufferv4);
    pl->buf.free(mdns->sendBufferv6);
    pl->buf.free(mdns->recvBuffer);
    free(mdns);
}

void mdns_start(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    if (pl->udp.async_bind_mdns_ipv4 != NULL) {
        pl->udp.async_bind_mdns_ipv4(mdns->socketv4, &mdns->v4OpenedCompletionEvent);
    }
    if (pl->udp.async_bind_mdns_ipv6 != NULL) {
        pl->udp.async_bind_mdns_ipv6(mdns->socketv6, &mdns->v6OpenedCompletionEvent);
    }
}

void nm_mdns_update_local_ips(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    struct np_ip_address ips[MAX_LOCAL_IPS];
    size_t ipsFound = pl->udp.get_local_ip(ips, MAX_LOCAL_IPS);

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
    struct np_mdns_context* mdns = userData;
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

void nm_mdns_recv_packet_v4(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    pl->udp.async_recv_wait(mdns->socketv4, &mdns->v4RecvWaitCompletionEvent);
}

void nm_mdns_packet_recv_wait_completed_v4(const np_error_code ec, void* userData)
{
    struct np_mdns_context* mdns = userData;
    struct np_platform* pl = mdns->pl;
    if (ec == NABTO_EC_OK) {
        size_t recvSize;
        struct np_udp_endpoint recvEp;
        uint8_t* recvBuffer = pl->buf.start(mdns->recvBuffer);
        size_t recvBufferSize = pl->buf.size(mdns->recvBuffer);
        np_error_code ec = pl->udp.recv_from(mdns->socketv4, &recvEp, recvBuffer, recvBufferSize, &recvSize);
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

void nm_mdns_send_packet_v4(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    size_t written;
    struct np_udp_endpoint ep;
    ep.ip.type = NABTO_IPV4;
    ep.port = 5353;
    uint8_t addr[] = { 0xe0, 0x00, 0x00, 0xfb };
    memcpy(ep.ip.ip.v4, addr, 4);
    uint16_t port = mdns->getPort(mdns->getPortUserData);
    nm_mdns_update_local_ips(mdns);
    if (port > 0) {
        if (nabto_mdns_server_build_packet(&mdns->mdnsServer, mdns->localIps, mdns->localIpsSize, port, pl->buf.start(mdns->sendBufferv4), pl->buf.size(mdns->sendBufferv4), &written))
        {
            pl->udp.async_send_to(mdns->socketv4,
                                  &ep, pl->buf.start(mdns->sendBufferv4), (uint16_t)written,
                                  &mdns->v4SendCompletionEvent);
            return;
        }
    }
    nm_mdns_recv_packet_v4(mdns);
}

void nm_mdns_packet_sent_v4(const np_error_code ec, void* userData)
{
    struct np_mdns_context* mdns = userData;
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
    struct np_mdns_context* mdns = userData;
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

void nm_mdns_recv_packet_v6(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    pl->udp.async_recv_wait(mdns->socketv6, &mdns->v6RecvWaitCompletionEvent);
}

void nm_mdns_packet_recv_wait_completed_v6(const np_error_code ec, void* userData)
{
    struct np_mdns_context* mdns = userData;
    struct np_platform* pl = mdns->pl;
    if (ec == NABTO_EC_OK) {
        size_t recvSize;
        uint8_t* recvBuffer = pl->buf.start(mdns->recvBuffer);
        size_t recvBufferSize = pl->buf.size(mdns->recvBuffer);

        struct np_udp_endpoint ep;
        np_error_code ec = pl->udp.recv_from(mdns->socketv6, &ep, recvBuffer, recvBufferSize, &recvSize);
        if (ec == NABTO_EC_OK) {
            if (nabto_mdns_server_handle_packet(&mdns->mdnsServer,
                                                recvBuffer, recvSize))
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

void nm_mdns_send_packet_v6(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    size_t written;
    struct np_udp_endpoint ep;
    ep.ip.type = NABTO_IPV6;
    ep.port = 5353;
    uint8_t addr[] = { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb };
    memcpy(ep.ip.ip.v6, addr, 16);

    uint16_t port = mdns->getPort(mdns->getPortUserData);
    nm_mdns_update_local_ips(mdns);
    if (port > 0) {
        if (nabto_mdns_server_build_packet(&mdns->mdnsServer, mdns->localIps, mdns->localIpsSize, port, pl->buf.start(mdns->sendBufferv6), pl->buf.size(mdns->sendBufferv6), &written)) {
            pl->udp.async_send_to(mdns->socketv6,
                                  &ep, pl->buf.start(mdns->sendBufferv6), (uint16_t)written,
                                  &mdns->v6SendCompletionEvent);
            return;
        }
    }
    nm_mdns_recv_packet_v6(mdns);
}

void nm_mdns_packet_sent_v6(const np_error_code ec, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (mdns->stopped) {
        mdns->v6Done = true;
        return;
    }
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "v6 packet sent callback with error: (%u) %s", ec, np_error_code_to_string(ec));
    }
    nm_mdns_recv_packet_v6(mdns);
}
