#include "nm_mdns.h"

void nm_mdns_start(struct nm_mdns* mdns);
static void nm_mdns_socket_opened(const np_error_code ec, np_udp_socket* socket, void* userData);
static void nm_mdns_recv_packet(struct nm_mdns* mdns);
static void nm_mdns_packet_received(const np_error_code ec, struct np_udp_endpoint ep,
                                    np_communication_buffer* buffer, uint16_t bufferSize, void* userData);
static void nm_mdns_send_packet(struct nm_mdns* mdns, struct np_udp_endpoint ep);
static void nm_mdns_packet_sent(const np_error_code ec, void* userData);
static void nm_mdns_socket_destroyed(const np_error_code ec, void* userData);

void nm_mdns_init(struct nm_mdns* mdns, struct np_platform* pl, const char* productId, const char* deviceId, nm_mdns_get_port getPort, void* userData)
{
    struct np_ip_address ips[2];
    memset(mdns, 0, sizeof(struct nm_mdns));
    mdns->stopped = false;
    mdns->pl = pl;
    mdns->sendBuffer = pl->buf.allocate();
    mdns->getPort = getPort;
    mdns->getPortUserData = userData;

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
    pl->udp.async_destroy(mdns->socket, nm_mdns_socket_destroyed, NULL);
    pl->buf.free(mdns->sendBuffer);
}

void nm_mdns_start(struct nm_mdns* mdns)
{
    struct np_platform* pl = mdns->pl;
    if (pl->udp.async_create_mdns != NULL) {
        pl->udp.async_create_mdns(nm_mdns_socket_opened, mdns);
    } else {
        // TODO fail.
    }
}

void nm_mdns_socket_destroyed(const np_error_code ec, void* userData)
{

}


void nm_mdns_socket_opened(const np_error_code ec, np_udp_socket* socket, void* userData)
{
    struct nm_mdns* mdns = userData;

    if (socket == NULL) {
        return;
    }

    mdns->socket = socket;
    nm_mdns_recv_packet(mdns);
}

void nm_mdns_recv_packet(struct nm_mdns* mdns)
{
    if (mdns->stopped) {
        return;
    }
    struct np_platform* pl = mdns->pl;
    pl->udp.async_recv_from(mdns->socket, nm_mdns_packet_received, mdns);
}

void nm_mdns_packet_received(const np_error_code ec, struct np_udp_endpoint ep,
                             np_communication_buffer* buffer, uint16_t bufferSize, void* userData)
{
    struct nm_mdns* mdns = userData;
    struct np_platform* pl = mdns->pl;
    if (ec == NABTO_EC_OK) {
        if (nabto_mdns_server_handle_packet(&mdns->mdnsServer,
                                            pl->buf.start(buffer), bufferSize))
        {
            nm_mdns_send_packet(mdns, ep);
            return;
        }
    }
    nm_mdns_recv_packet(mdns);
}

void nm_mdns_send_packet(struct nm_mdns* mdns, struct np_udp_endpoint ep)
{
    struct np_platform* pl = mdns->pl;
    size_t written;
    uint16_t port = mdns->getPort(mdns->getPortUserData);
    if (port > 0) {
        if (nabto_mdns_server_build_packet(&mdns->mdnsServer, port, pl->buf.start(mdns->sendBuffer), pl->buf.size(mdns->sendBuffer), &written)) {
            np_udp_populate_send_context(&mdns->sendContext, mdns->socket,
                                         ep, mdns->sendBuffer, (uint16_t)written,
                                         nm_mdns_packet_sent, mdns);
            pl->udp.async_send_to(&mdns->sendContext);
            // the send handler starts a new recv in this case
            return;
        }
    }
    nm_mdns_recv_packet(mdns);
}

void nm_mdns_packet_sent(const np_error_code ec, void* userData)
{
    struct nm_mdns* mdns = userData;
    nm_mdns_recv_packet(mdns);
}
