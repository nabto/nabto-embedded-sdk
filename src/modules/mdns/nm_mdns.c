#include "nm_mdns.h"
#include <platform/np_logging.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_MDNS

struct np_mdns_context {
    struct np_platform* pl;
    bool stopped;
    bool v4Done;
    bool v6Done;
    np_mdns_get_port getPort;
    void* getPortUserData;
    struct nabto_mdns_server_context mdnsServer;
    np_udp_socket* socketv4;
    np_udp_socket* socketv6;
    struct nabto_mdns_ip_address mdnsIps[2];
    struct np_communication_buffer* sendBufferv4;
    struct np_communication_buffer* sendBufferv6;
};

np_error_code nm_mdns_start(struct np_mdns_context* mdns);
static void nm_mdns_socket_opened_v4(const np_error_code ec, void* userData);
static void nm_mdns_recv_packet_v4(struct np_mdns_context* mdns);
static void nm_mdns_packet_received_v4(const np_error_code ec, struct np_udp_endpoint ep,
                                    uint8_t* buffer, uint16_t bufferSize, void* userData);
static void nm_mdns_send_packet_v4(struct np_mdns_context* mdns);
static void nm_mdns_packet_sent_v4(const np_error_code ec, void* userData);

static void nm_mdns_socket_opened_v6(const np_error_code ec, void* userData);
static void nm_mdns_recv_packet_v6(struct np_mdns_context* mdns);
static void nm_mdns_packet_received_v6(const np_error_code ec, struct np_udp_endpoint ep,
                                    uint8_t* buffer, uint16_t bufferSize, void* userData);
static void nm_mdns_send_packet_v6(struct np_mdns_context* mdns);
static void nm_mdns_packet_sent_v6(const np_error_code ec, void* userData);

void nm_mdns_init(struct np_platform* pl)
{
    pl->mdns.start = &nm_mdns_create;
    pl->mdns.stop = &nm_mdns_stop;
}

void nm_mdns_try_done(struct np_mdns_context* mdns)
{
    if (mdns->v4Done && mdns->v6Done) {
        mdns->pl->udp.destroy(mdns->socketv4);
        mdns->pl->udp.destroy(mdns->socketv6);

        // UDP module should resolve all callback on destroy, so it should be okay to clean up here
        mdns->pl->buf.free(mdns->sendBufferv4);
        mdns->pl->buf.free(mdns->sendBufferv6);
        free(mdns);
    }
}

void nm_mdns_stop(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    mdns->stopped = true;
    pl->udp.abort(mdns->socketv4);
    pl->udp.abort(mdns->socketv6);
    nm_mdns_try_done(mdns);
}

np_error_code nm_mdns_create(struct np_mdns_context** mdns, struct np_platform* pl, const char* productId, const char* deviceId, np_mdns_get_port getPort, void* userData)
{
    struct np_ip_address ips[2];
    *mdns = calloc(1, sizeof(struct np_mdns_context));
    if (*mdns == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    (*mdns)->stopped = false;
    (*mdns)->v4Done = false;
    (*mdns)->v6Done = false;
    (*mdns)->pl = pl;
    (*mdns)->sendBufferv4 = pl->buf.allocate();
    (*mdns)->sendBufferv6 = pl->buf.allocate();
    (*mdns)->getPort = getPort;
    (*mdns)->getPortUserData = userData;
    np_error_code ec;
    ec = pl->udp.create(pl, &(*mdns)->socketv4);
    if (ec != NABTO_EC_OK) {
        pl->buf.free((*mdns)->sendBufferv4);
        pl->buf.free((*mdns)->sendBufferv6);
        free(*mdns);
        return ec;
    }
    ec = pl->udp.create(pl, &(*mdns)->socketv6);
    if (ec != NABTO_EC_OK) {
        pl->buf.free((*mdns)->sendBufferv4);
        pl->buf.free((*mdns)->sendBufferv6);
        free(*mdns);
        return ec;
    }

    size_t ipsFound = pl->udp.get_local_ip(ips, 2);

    for(int i = 0; i < ipsFound; i++) {
        struct np_ip_address* ip = &ips[i];
        struct nabto_mdns_ip_address* mdnsIp = &(*mdns)->mdnsIps[i];
        if (ip->type == NABTO_IPV4) {
            mdnsIp->type = NABTO_MDNS_IPV4;
            memcpy(mdnsIp->v4.addr, ip->ip.v4, 4);
        } else {
            mdnsIp->type = NABTO_MDNS_IPV6;
            memcpy(mdnsIp->v6.addr, ip->ip.v6, 16);
        }
    }

    nabto_mdns_server_init(&(*mdns)->mdnsServer, deviceId, productId,
                           deviceId /*serviceName must be unique*/,
                           deviceId /*hostname must be unique*/,
                           (*mdns)->mdnsIps, ipsFound);
    ec = nm_mdns_start(*mdns);
    if (ec != NABTO_EC_OK) {
        pl->udp.destroy((*mdns)->socketv4);
        pl->udp.destroy((*mdns)->socketv6);
        pl->buf.free((*mdns)->sendBufferv4);
        pl->buf.free((*mdns)->sendBufferv6);
        free(*mdns);
        return ec;
    }
    return NABTO_EC_OK;
}

np_error_code nm_mdns_start(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    np_error_code ec;
    if (pl->udp.async_bind_mdns_ipv4 != NULL) {
        ec = pl->udp.async_bind_mdns_ipv4(mdns->socketv4, nm_mdns_socket_opened_v4, mdns);
        if (ec != NABTO_EC_OK) {
            NABTO_LOG_TRACE(LOG, "mDNS unable to bind to IPv4: %s. Continueing with IPv6", np_error_code_to_string(ec));
            mdns->v4Done = true;
        }
    }
    if (pl->udp.async_bind_mdns_ipv6 != NULL) {
        ec = pl->udp.async_bind_mdns_ipv6(mdns->socketv6, nm_mdns_socket_opened_v6, mdns);
        if (ec != NABTO_EC_OK) {
            NABTO_LOG_TRACE(LOG, "mDNS unable to bind to IPv6: %s. Continueing with IPv4", np_error_code_to_string(ec));
            mdns->v6Done = true;
        }
    }
    if (mdns->v6Done && mdns->v4Done) {
        NABTO_LOG_INFO(LOG, "mDNS failed to bind both IPv4 and IPv6 sockets. This device will not be discoverable locally.");
        return ec;
    }
    return NABTO_EC_OK;
}

void nm_mdns_socket_opened_v4(const np_error_code ec, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (mdns->stopped) {
        mdns->v4Done = true;
        nm_mdns_try_done(mdns);
        return;
    }
    if (ec == NABTO_EC_OK) {
        // dont start receiving until send callback returns to ensure send buffer is not overwritten
        nm_mdns_send_packet_v4(mdns);
    } else {
        // todo how to fail?
        NABTO_LOG_TRACE(LOG, "V4 socket open failed with (%u) %s", ec, np_error_code_to_string(ec));
        mdns->v4Done = true;
    }
}

void nm_mdns_recv_packet_v4(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    np_error_code ec = pl->udp.async_recv_from(mdns->socketv4, nm_mdns_packet_received_v4, mdns);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "IPv4 async recv from failed with: %s", np_error_code_to_string(ec));
        mdns->v4Done = true;
    }
}

void nm_mdns_packet_received_v4(const np_error_code ec, struct np_udp_endpoint ep,
                                uint8_t* buffer, uint16_t bufferSize, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (mdns->stopped) {
        mdns->v4Done = true;
        nm_mdns_try_done(mdns);
        return;
    }
    if (ec == NABTO_EC_OK) {
        if (nabto_mdns_server_handle_packet(&mdns->mdnsServer,
                                            buffer, bufferSize))
        {
            nm_mdns_send_packet_v4(mdns);
            // next receive is started by send
            return;
        }
        nm_mdns_recv_packet_v4(mdns);
    } else {
        // TODO: consider if log message is enough to make the user aware of failures.
        // On socket error we stop receiving, clean up will be done when stopped.
        NABTO_LOG_TRACE(LOG, "UDP V4 receive callback with error code: (%i) %s", ec, np_error_code_to_string(ec));
        mdns->v4Done = true;
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
    if (port > 0) {
        if (nabto_mdns_server_build_packet(&mdns->mdnsServer, port, pl->buf.start(mdns->sendBufferv4), pl->buf.size(mdns->sendBufferv4), &written)) {
            np_error_code ec = pl->udp.async_send_to(mdns->socketv4,
                                                     ep, pl->buf.start(mdns->sendBufferv4), (uint16_t)written,
                                                     nm_mdns_packet_sent_v4, mdns);
            // the send callback starts a new recv to ensure send buffer is not overwritten
            if (ec != NABTO_EC_OK) {
                NABTO_LOG_TRACE(LOG, "IPv4 async send failed with: %s", np_error_code_to_string(ec));
                mdns->v4Done = true;
            }
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
        nm_mdns_try_done(mdns);
        return;
    }
    if (ec == NABTO_EC_OK) {
        nm_mdns_recv_packet_v4(mdns);
    } else {
        NABTO_LOG_TRACE(LOG, "v4 packet sent callback with error: (%u) %s", ec, np_error_code_to_string(ec));
        mdns->v4Done = true;
    }
}

void nm_mdns_socket_opened_v6(const np_error_code ec, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (mdns->stopped) {
        mdns->v6Done = true;
        nm_mdns_try_done(mdns);
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
    np_error_code ec = pl->udp.async_recv_from(mdns->socketv6, nm_mdns_packet_received_v6, mdns);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "IPv6 async recv from failed with: %s", np_error_code_to_string(ec));
        mdns->v6Done = true;
    }
}

void nm_mdns_packet_received_v6(const np_error_code ec, struct np_udp_endpoint ep,
                                uint8_t* buffer, uint16_t bufferSize, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (mdns->stopped) {
        mdns->v6Done = true;
        nm_mdns_try_done(mdns);
        return;
    }
    if (ec == NABTO_EC_OK) {
        if (nabto_mdns_server_handle_packet(&mdns->mdnsServer,
                                            buffer, bufferSize))
        {
            nm_mdns_send_packet_v6(mdns);
            // next receive is started by send
            return;
        }
        nm_mdns_recv_packet_v6(mdns);
    } else {
        NABTO_LOG_TRACE(LOG, "UDP V6 receive callback with error code: (%i) %s", ec, np_error_code_to_string(ec));
        mdns->v6Done = true;
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
    if (port > 0) {
        if (nabto_mdns_server_build_packet(&mdns->mdnsServer, port, pl->buf.start(mdns->sendBufferv6), pl->buf.size(mdns->sendBufferv6), &written)) {
            // todo check return value
            np_error_code ec = pl->udp.async_send_to(mdns->socketv6,
                                                     ep, pl->buf.start(mdns->sendBufferv6), (uint16_t)written,
                                                     nm_mdns_packet_sent_v6, mdns);
            // the send handler starts a new recv in this case
            if (ec != NABTO_EC_OK) {
                NABTO_LOG_TRACE(LOG, "IPv6 async send failed with: %s", np_error_code_to_string(ec));
                mdns->v6Done = true;
            }
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
        nm_mdns_try_done(mdns);
        return;
    }
    if (ec == NABTO_EC_OK) {
        nm_mdns_recv_packet_v6(mdns);
    } else {
        NABTO_LOG_TRACE(LOG, "v6 packet sent callback with error: (%u) %s", ec, np_error_code_to_string(ec));
        mdns->v6Done = true;
    }
}
