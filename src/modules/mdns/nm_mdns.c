#include "nm_mdns.h"

void nm_mdns_start(struct nm_mdns* mdns);
static void nm_mdns_socket_opened_v4(const np_error_code ec, void* userData);
static void nm_mdns_recv_packet_v4(struct nm_mdns* mdns);
static void nm_mdns_packet_received_v4(const np_error_code ec, struct np_udp_endpoint ep,
                                    np_communication_buffer* buffer, uint16_t bufferSize, void* userData);
static void nm_mdns_send_packet_v4(struct nm_mdns* mdns);
static void nm_mdns_packet_sent_v4(const np_error_code ec, void* userData);

static void nm_mdns_socket_opened_v6(const np_error_code ec, void* userData);
static void nm_mdns_recv_packet_v6(struct nm_mdns* mdns);
static void nm_mdns_packet_received_v6(const np_error_code ec, struct np_udp_endpoint ep,
                                    np_communication_buffer* buffer, uint16_t bufferSize, void* userData);
static void nm_mdns_send_packet_v6(struct nm_mdns* mdns);
static void nm_mdns_packet_sent_v6(const np_error_code ec, void* userData);

void nm_mdns_init(struct nm_mdns* mdns, struct np_platform* pl, const char* productId, const char* deviceId, nm_mdns_get_port getPort, void* userData)
{
    struct np_ip_address ips[2];
    memset(mdns, 0, sizeof(struct nm_mdns));
    mdns->stopped = false;
    mdns->pl = pl;
    mdns->sendBufferv4 = pl->buf.allocate();
    mdns->sendBufferv6 = pl->buf.allocate();
    mdns->getPort = getPort;
    mdns->getPortUserData = userData;
    pl->udp.create(pl, &mdns->socketv4);
    pl->udp.create(pl, &mdns->socketv6);

    size_t ipsFound = pl->udp.get_local_ip(ips, 2);

    for(int i = 0; i < ipsFound; i++) {
        struct np_ip_address* ip = &ips[i];
        struct nabto_mdns_ip_address* mdnsIp = &mdns->mdnsIps[i];
        if (ip->type == NABTO_IPV4) {
            mdnsIp->type = NABTO_MDNS_IPV4;
            memcpy(mdnsIp->v4.addr, ip->v4.addr, 4);
        } else {
            mdnsIp->type = NABTO_MDNS_IPV6;
            memcpy(mdnsIp->v6.addr, ip->v6.addr, 16);
        }
    }

    nabto_mdns_server_init(&mdns->mdnsServer, deviceId, productId,
                           deviceId /*serviceName must be unique*/,
                           deviceId /*hostname must be unique*/,
                           mdns->mdnsIps, ipsFound);
    nm_mdns_start(mdns);
}

void nm_mdns_deinit(struct nm_mdns* mdns)
{
    if (mdns->stopped) {
        return;
    }
    struct np_platform* pl = mdns->pl;
    mdns->stopped = true;

    pl->udp.destroy(mdns->socketv4);
    pl->udp.destroy(mdns->socketv6);
    pl->buf.free(mdns->sendBufferv4);
    pl->buf.free(mdns->sendBufferv6);
}

void nm_mdns_start(struct nm_mdns* mdns)
{
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
    struct nm_mdns* mdns = userData;
    nm_mdns_recv_packet_v4(mdns);
}

void nm_mdns_recv_packet_v4(struct nm_mdns* mdns)
{
    if (mdns->stopped) {
        return;
    }
    struct np_platform* pl = mdns->pl;
    pl->udp.async_recv_from(mdns->socketv4, nm_mdns_packet_received_v4, mdns);
}

void nm_mdns_packet_received_v4(const np_error_code ec, struct np_udp_endpoint ep,
                             np_communication_buffer* buffer, uint16_t bufferSize, void* userData)
{
    struct nm_mdns* mdns = userData;
    struct np_platform* pl = mdns->pl;
    if (ec == NABTO_EC_OK) {
        if (nabto_mdns_server_handle_packet(&mdns->mdnsServer,
                                            pl->buf.start(buffer), bufferSize))
        {
            nm_mdns_send_packet_v4(mdns);
            return;
        }
    }
    nm_mdns_recv_packet_v4(mdns);
}

void nm_mdns_send_packet_v4(struct nm_mdns* mdns)
{
    struct np_platform* pl = mdns->pl;
    size_t written;
    struct np_udp_endpoint ep;
    ep.ip.type = NABTO_IPV4;
    ep.port = 5353;
    uint8_t addr[] = { 0xe0, 0x00, 0x00, 0xfb };
    memcpy(ep.ip.v4.addr,addr, 4);
    uint16_t port = mdns->getPort(mdns->getPortUserData);
    if (port > 0) {
        if (nabto_mdns_server_build_packet(&mdns->mdnsServer, port, pl->buf.start(mdns->sendBufferv4), pl->buf.size(mdns->sendBufferv4), &written)) {
            np_udp_populate_send_context(&mdns->sendContextv4, mdns->socketv4,
                                         ep, mdns->sendBufferv4, (uint16_t)written,
                                         nm_mdns_packet_sent_v4, mdns);
            pl->udp.async_send_to(&mdns->sendContextv4);
            // the send handler starts a new recv in this case
            return;
        }
    }
    nm_mdns_recv_packet_v4(mdns);
}

void nm_mdns_packet_sent_v4(const np_error_code ec, void* userData)
{
    struct nm_mdns* mdns = userData;
    nm_mdns_recv_packet_v4(mdns);
}

void nm_mdns_socket_opened_v6(const np_error_code ec, void* userData)
{
    struct nm_mdns* mdns = userData;
    nm_mdns_recv_packet_v6(mdns);
}

void nm_mdns_recv_packet_v6(struct nm_mdns* mdns)
{
    if (mdns->stopped) {
        return;
    }
    struct np_platform* pl = mdns->pl;
    pl->udp.async_recv_from(mdns->socketv6, nm_mdns_packet_received_v6, mdns);
}

void nm_mdns_packet_received_v6(const np_error_code ec, struct np_udp_endpoint ep,
                                np_communication_buffer* buffer, uint16_t bufferSize, void* userData)
{
    struct nm_mdns* mdns = userData;
    struct np_platform* pl = mdns->pl;
    if (ec == NABTO_EC_OK) {
        if (nabto_mdns_server_handle_packet(&mdns->mdnsServer,
                                            pl->buf.start(buffer), bufferSize))
        {
            nm_mdns_send_packet_v6(mdns);
            return;
        }
    }
    nm_mdns_recv_packet_v6(mdns);
}

void nm_mdns_send_packet_v6(struct nm_mdns* mdns)
{
    struct np_platform* pl = mdns->pl;
    size_t written;
    struct np_udp_endpoint ep;
    ep.ip.type = NABTO_IPV6;
    ep.port = 5353;
    uint8_t addr[] = { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb };
    memcpy(ep.ip.v6.addr,addr, 16);

    uint16_t port = mdns->getPort(mdns->getPortUserData);
    if (port > 0) {
        if (nabto_mdns_server_build_packet(&mdns->mdnsServer, port, pl->buf.start(mdns->sendBufferv6), pl->buf.size(mdns->sendBufferv6), &written)) {
            np_udp_populate_send_context(&mdns->sendContextv6, mdns->socketv6,
                                         ep, mdns->sendBufferv6, (uint16_t)written,
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
    struct nm_mdns* mdns = userData;
    nm_mdns_recv_packet_v6(mdns);
}
