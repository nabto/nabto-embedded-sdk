#include "nm_mdns.h"
#include <platform/np_logging.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_MDNS

struct np_mdns_context {
    struct np_platform* pl;
    bool stopped;
    np_mdns_get_port getPort;
    void* getPortUserData;
    struct nabto_mdns_server_context mdnsServer;
    np_udp_socket* socketv4;
    np_udp_socket* socketv6;
    struct nabto_mdns_ip_address mdnsIps[2];
    struct np_communication_buffer* sendBufferv4;
    struct np_communication_buffer* sendBufferv6;
    struct np_udp_send_context sendContextv4;
    struct np_udp_send_context sendContextv6;
};

void nm_mdns_start(struct np_mdns_context* mdns);
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

void nm_mdns_create(struct np_mdns_context** mdns, struct np_platform* pl, const char* productId, const char* deviceId, np_mdns_get_port getPort, void* userData)
{
    struct np_ip_address ips[2];
    *mdns = calloc(1, sizeof(struct np_mdns_context));
    (*mdns)->stopped = false;
    (*mdns)->pl = pl;
    (*mdns)->sendBufferv4 = pl->buf.allocate();
    (*mdns)->sendBufferv6 = pl->buf.allocate();
    (*mdns)->getPort = getPort;
    (*mdns)->getPortUserData = userData;
    pl->udp.create(pl, &(*mdns)->socketv4);
    pl->udp.create(pl, &(*mdns)->socketv6);

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
    nm_mdns_start(*mdns);
}

void nm_mdns_stop(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    mdns->stopped = true;
    pl->udp.destroy(mdns->socketv4);
    pl->udp.destroy(mdns->socketv6);

    // UDP module should resolve all callback on destroy, so it should be okay to clean up here
    pl->buf.free(mdns->sendBufferv4);
    pl->buf.free(mdns->sendBufferv6);
    free(mdns);
}

void nm_mdns_start(struct np_mdns_context* mdns)
{
    if (mdns->stopped) {
        return;
    }
    struct np_platform* pl = mdns->pl;
    if (pl->udp.async_bind_mdns_ipv4 != NULL) {
        pl->udp.async_bind_mdns_ipv4(mdns->socketv4, nm_mdns_socket_opened_v4, mdns);
    }
    if (pl->udp.async_bind_mdns_ipv6 != NULL) {
        pl->udp.async_bind_mdns_ipv6(mdns->socketv6, nm_mdns_socket_opened_v6, mdns);
    }
}

void nm_mdns_socket_opened_v4(const np_error_code ec, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (mdns->stopped) {
        return;
    }
    if (ec == NABTO_EC_OK) {
        // dont start receiving untill send callback returns to ensure send buffer is not overwritten
        nm_mdns_send_packet_v4(mdns);
    } else {
        // todo how to fail?
        NABTO_LOG_TRACE(LOG, "V4 socket open failed with (%u) %s", ec, np_error_code_to_string(ec));
    }
}

void nm_mdns_recv_packet_v4(struct np_mdns_context* mdns)
{
    if (mdns->stopped) {
        return;
    }
    struct np_platform* pl = mdns->pl;
    pl->udp.async_recv_from(mdns->socketv4, nm_mdns_packet_received_v4, mdns);
}

void nm_mdns_packet_received_v4(const np_error_code ec, struct np_udp_endpoint ep,
                                uint8_t* buffer, uint16_t bufferSize, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (ec == NABTO_EC_OK) {
        if (mdns->stopped) {
            return;
        }
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
//        mdns->stopped = true;
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
            np_udp_populate_send_context(&mdns->sendContextv4, mdns->socketv4,
                                         ep, pl->buf.start(mdns->sendBufferv4), (uint16_t)written,
                                         nm_mdns_packet_sent_v4, mdns);
            pl->udp.async_send_to(&mdns->sendContextv4);
            // the send callback starts a new recv to ensure send buffer is not overwritten
            return;
        }
    }
    nm_mdns_recv_packet_v4(mdns);
}

void nm_mdns_packet_sent_v4(const np_error_code ec, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (ec == NABTO_EC_OK) {
        if (mdns->stopped) {
            return;
        }
        nm_mdns_recv_packet_v4(mdns);
    } else {
        NABTO_LOG_TRACE(LOG, "v4 packet sent callback with error: (%u) %s", ec, np_error_code_to_string(ec));
    }
}

void nm_mdns_socket_opened_v6(const np_error_code ec, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (mdns->stopped) {
        return;
    }
    if (ec == NABTO_EC_OK) {
        // dont start receiving untill send callback returns to ensure send buffer is not overwritten
        nm_mdns_send_packet_v6(mdns);
    } else {
        NABTO_LOG_TRACE(LOG, "V6 socket open failed with (%u) %s", ec, np_error_code_to_string(ec));
    }
}

void nm_mdns_recv_packet_v6(struct np_mdns_context* mdns)
{
    if (mdns->stopped) {
        return;
    }
    struct np_platform* pl = mdns->pl;
    pl->udp.async_recv_from(mdns->socketv6, nm_mdns_packet_received_v6, mdns);
}

void nm_mdns_packet_received_v6(const np_error_code ec, struct np_udp_endpoint ep,
                                uint8_t* buffer, uint16_t bufferSize, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (ec == NABTO_EC_OK) {
        if (mdns->stopped) {
            return;
        }
        if (nabto_mdns_server_handle_packet(&mdns->mdnsServer,
                                            buffer, bufferSize))
        {
            nm_mdns_send_packet_v6(mdns);
            // next receive is started by send
            return;
        }
        nm_mdns_recv_packet_v6(mdns);
    } else {
        // TODO: consider if log message is enough to make the user aware of failures.
        // On socket error we stop receiving, clean up will be done when stopped.
        NABTO_LOG_TRACE(LOG, "UDP V6 receive callback with error code: (%i) %s", ec, np_error_code_to_string(ec));
        //mdns->stopped = true;
    }
}

void nm_mdns_send_packet_v6(struct np_mdns_context* mdns)
{
    struct np_platform* pl = mdns->pl;
    size_t written;
    struct np_udp_endpoint ep;
    ep.ip.type = NABTO_IPV6;
    ep.port = 5353;
    uint8_t addr[] = { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb };
    memcpy(ep.ip.ip.v6, addr, 16);

    uint16_t port = mdns->getPort(mdns->getPortUserData);
    if (port > 0) {
        if (nabto_mdns_server_build_packet(&mdns->mdnsServer, port, pl->buf.start(mdns->sendBufferv6), pl->buf.size(mdns->sendBufferv6), &written)) {
            np_udp_populate_send_context(&mdns->sendContextv6, mdns->socketv6,
                                         ep, pl->buf.start(mdns->sendBufferv6), (uint16_t)written,
                                         nm_mdns_packet_sent_v6, mdns);
            pl->udp.async_send_to(&mdns->sendContextv6);
            // the send handler starts a new recv in this case
            return;
        }
    }
    nm_mdns_recv_packet_v6(mdns);
}

void nm_mdns_packet_sent_v6(const np_error_code ec, void* userData)
{
    struct np_mdns_context* mdns = userData;
    if (ec == NABTO_EC_OK) {
        nm_mdns_recv_packet_v6(mdns);
    } else {
        NABTO_LOG_TRACE(LOG, "v6 packet sent callback with error: (%u) %s", ec, np_error_code_to_string(ec));
    }
}
