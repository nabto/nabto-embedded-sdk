#ifndef NC_RENDEZVOUS_H
#define NC_RENDEZVOUS_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>
#include <platform/np_completion_event.h>

#define NC_RENDEZVOUS_SEND_QUEUE_LENGTH 10

struct nc_client_connection_dispatch_context;

// context describing a rendezvous packet.
struct nc_rendezvous_send_packet {
    uint8_t type; // either RENDEZVOUS_DEVICE_PROBE_REQUREST or RENDEZVOUS_CLIENT_PROBE_RESPONSE
    uint8_t connectionId[14];
    uint8_t channelId;
    struct nc_udp_dispatch_context* udpDispatch;
    struct np_udp_endpoint ep;
};

struct nc_rendezvous_context {
    struct np_platform* pl;
    struct np_communication_buffer* priBuf;
    struct nc_udp_dispatch_context* defaultUdpDispatch;
    struct nc_rendezvous_send_packet packetList[NC_RENDEZVOUS_SEND_QUEUE_LENGTH];
    // index of first empty spot in epList
    uint8_t packetIndex;
    bool sendingDevReqs;

    struct np_completion_event sendCompletionEvent;
};


np_error_code nc_rendezvous_init(struct nc_rendezvous_context* ctx,
                                 struct np_platform* pl);
void nc_rendezvous_deinit(struct nc_rendezvous_context* ctx);

void nc_rendezvous_set_udp_dispatch(struct nc_rendezvous_context* ctx, struct nc_udp_dispatch_context* udpDispatch);
void nc_rendezvous_remove_udp_dispatch(struct nc_rendezvous_context* ctx);

void nc_rendezvous_handle_packet(
    struct nc_rendezvous_context* rendezvous,
    struct nc_udp_dispatch_context* udpDispatch,
    struct nc_client_connection_dispatch_context* connectionDispatch,
    struct np_udp_endpoint* ep,
    uint8_t* buffer, uint16_t bufferSize);

// enqueue a rendezvous packet to be sent async. The packet is copied
// into the internal structure of the module.
void nc_rendezvous_send_rendezvous(struct nc_rendezvous_context* ctx, struct nc_rendezvous_send_packet* packet);

#endif // NC_RENDEZVOUS_H
