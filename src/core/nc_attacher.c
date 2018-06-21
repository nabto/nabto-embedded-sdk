
#include "nc_attacher.h"

#include <core/nc_keep_alive.h>
#include <core/nc_packet.h>
#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

struct nc_attach_context {
    struct np_platform* pl;
    nc_attached_callback cb;
    nc_detached_callback detachCb;
    void* detachData;
    np_udp_socket* sock;
    void* cbData;
    np_connection adConn;
    np_connection anConn;
    np_dtls_cli_context* adDtls;
    np_dtls_cli_context* anDtls;
    np_communication_buffer* buffer;
    char dns[64]; // TODO: Hardcoded DNS length limit
    uint8_t token[1024]; // TODO: How to store token ?
    uint16_t tokenLen;
    struct np_connection_id id;
    struct np_connection_channel anChannel;
    struct np_connection_channel adChannel;
    struct keep_alive_context kactx;
};

struct nc_attach_context ctx;

// TODO: Handle error codes in all callback functions!!

/**
 * Attach node functions
 */
void nc_attacher_an_dtls_send_cb(const np_error_code ec, void* data);
void nc_attacher_an_handle_event(const np_error_code ec, np_communication_buffer* buf,
                                     uint16_t bufferSize, void* data);
void nc_attacher_an_dtls_conn_cb(const np_error_code ec, np_dtls_cli_context* crypCtx, void* data);
void nc_attacher_an_conn_created_cb(const np_error_code ec, uint8_t channelId, void* data);
void nc_attacher_an_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data);

/**
 * general packet dispatching
 */
void nc_attacher_dtls_recv_cb(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                              np_communication_buffer* buf, uint16_t bufferSize, void* data);

/**
 * Attach dispatcher functions
 */
void nc_attacher_ad_dtls_closed_cb(const np_error_code ec, void* data);
void nc_attacher_ad_dtls_send_cb(const np_error_code ec, void* data);
void nc_attacher_ad_handle_event(const np_error_code ec, np_communication_buffer* buf,
                                 uint16_t bufferSize, void* data);
void nc_attacher_ad_dtls_conn_cb(const np_error_code ec, np_dtls_cli_context* crypCtx, void* data);
void nc_attacher_ad_conn_created_cb(const np_error_code ec, uint8_t channelId, void* data);
void nc_attacher_ad_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data);

/**
 * create socket reused for both DTLS connections
 */
void nc_attacher_sock_created_cb(const np_error_code ec, np_udp_socket* sock, void* data);


void nc_attacher_ka_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(LOG,"Attacher received keep alive callback with error code: %u", ec);
}

void nc_attacher_an_handle_event(const np_error_code ec, np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    uint8_t type;
    if(ec != NABTO_EC_OK) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    type= ctx.pl->buf.start(buf)[1];
    NABTO_LOG_TRACE(LOG, "ATTACH packet received");
    NABTO_LOG_BUF(LOG, ctx.pl->buf.start(buf), bufferSize);
    if (type == ATTACH_SERVER_HELLO) {
        NABTO_LOG_INFO(LOG, "Device is now ATTACHED");
        nc_keep_alive_init(ctx.pl, &ctx.kactx, ctx.anDtls, &nc_attacher_ka_cb, &ctx);
        ctx.cb(NABTO_EC_OK, ctx.cbData);
    } else {
        NABTO_LOG_ERROR(LOG, "unknown attach_content_type %u found ",type); 
    }
}

void nc_attacher_ad_handle_event(const np_error_code ec, np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    uint8_t* start = ctx.pl->buf.start(buf);
    uint8_t* ptr = start;
    uint8_t* dns;
    uint16_t dnsLen;
    uint16_t extensionLen = uint16_read(start+2);
    uint8_t* token = start + NABTO_PACKET_HEADER_SIZE + extensionLen + 2;
    uint16_t tokenLen = uint16_read(start + NABTO_PACKET_HEADER_SIZE + extensionLen);

    if (ec != NABTO_EC_OK) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    if (bufferSize < NABTO_PACKET_HEADER_SIZE || *start != ATTACH_DISPATCH) {
        NABTO_LOG_ERROR(LOG, "Received malformed ATTACH_DISPATCH response packet");
        ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
        return;
    }
    NABTO_LOG_TRACE(LOG, "ATTACH_DISPATCH packet received");
    NABTO_LOG_BUF(LOG, start, bufferSize);
    if (*(start+1) == ATTACH_DISPATCH_RESPONSE) {
        NABTO_LOG_TRACE(LOG, "ATTACH_DISPATCH_RESPONSE");
        if (extensionLen < 4 || bufferSize <= extensionLen + NABTO_PACKET_HEADER_SIZE) {
            NABTO_LOG_ERROR(LOG, "Received ATTACH_DISPATCH_RESPONSE either missing DNS extension or token");
            ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
            return;
        }
        ptr = ptr + NABTO_PACKET_HEADER_SIZE; // skip header;
        while (true) {
            uint16_t extType = uint16_read(ptr);
            uint16_t extLen = uint16_read(ptr+2);
            if (extType == UDP_DNS_EP) {
                ctx.anChannel.ep.port = uint16_read(ptr+4);
                dns = ptr+8;
                dnsLen = uint16_read(ptr+6);
                NABTO_LOG_TRACE(LOG, "Found DNS extension with port: %u, dns: %s", ctx.anChannel.ep.port, (char*)dns);
                break;
            }
            ptr = ptr + extLen + 4;
            if (ptr - start >= bufferSize) {
                NABTO_LOG_ERROR(LOG, "Failed to find DNS extension in ATTACH_DISPATCH_RESPONSE");
                ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
                return;
            }
        }
        memcpy(ctx.dns, dns, dnsLen);
        ctx.dns[dnsLen] = '\0';
        memcpy(ctx.token, token, tokenLen);
        ctx.tokenLen = tokenLen;
        NABTO_LOG_TRACE(LOG, "dns: %s", ctx.dns);
        NABTO_LOG_BUF(LOG, ctx.token, tokenLen);
        ctx.pl->dns.async_resolve(ctx.pl, ctx.dns, &nc_attacher_an_dns_cb, &ctx);
        ctx.pl->dtlsC.async_close(ctx.pl, ctx.adDtls, &nc_attacher_ad_dtls_closed_cb, &ctx);
        
    } else if (*(start+1) == ATTACH_DISPATCH_REDIRECT) {
        NABTO_LOG_TRACE(LOG, "ATTACH_DISPATCH_REDIRECT");
        if (extensionLen < 4) {
            NABTO_LOG_ERROR(LOG, "Received ATTACH_DISPATCH_REDIRECT missing DNS extension");
            ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
            return;
        }
        ptr = ptr + NABTO_PACKET_HEADER_SIZE; // skip header;
        while (true) {
            uint16_t extType = uint16_read(ptr);
            uint16_t extLen = uint16_read(ptr+2);
            if (extType == UDP_DNS_EP) {
                ctx.adChannel.ep.port = uint16_read(ptr+4);
                dns = ptr+8;
                dnsLen = uint16_read(ptr+6);
                NABTO_LOG_TRACE(LOG, "Found DNS extension with port: %u, dns: %s", ctx.adChannel.ep.port, (char*)dns);
                break;
            }
            ptr = ptr + extLen + 4;
            if (ptr - start >= bufferSize) {
                NABTO_LOG_ERROR(LOG, "Failed to find DNS extension in ATTACH_DISPATCH_RESPONSE");
                ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
                return;
            }
        }
        memcpy(ctx.dns, dns, dnsLen);
        ctx.pl->dns.async_resolve(ctx.pl, ctx.dns, &nc_attacher_ad_dns_cb, &ctx);
        
        return;

    } else {
        NABTO_LOG_ERROR(LOG, "Received ATTACH_DISPATCH packet with invalid content type");
        ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
        return;
    }
        
}

void nc_attacher_an_dtls_conn_cb(const np_error_code ec, np_dtls_cli_context* crypCtx, void* data)
{
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.anDtls = crypCtx;
    uint8_t* ptr = ctx.pl->buf.start(ctx.buffer);
    uint8_t* start = ptr;
    ptr = init_packet_header(ptr, ATTACH);
    *(start+1) = ATTACH_DEVICE_HELLO;
    // TODO: only insert extensions which are supported
    ptr = insert_packet_extension(ctx.pl, ctx.buffer, UDP_IPV4_EP, NULL, 0);
    ptr = insert_packet_extension(ctx.pl, ctx.buffer, UDP_IPV6_EP, NULL, 0);
    ptr = write_uint16_length_data(ptr, ctx.token, ctx.tokenLen);
    NABTO_LOG_BUF(LOG, start, ptr - start);
    ctx.pl->dtlsC.async_send_to(ctx.pl, ctx.anDtls, 0xff, start, ptr - start, &nc_attacher_an_dtls_send_cb, &ctx);
    ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.anDtls, ATTACH, &nc_attacher_dtls_recv_cb, &ctx);
//    ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.anDtls, KEEP_ALIVE, &nc_attacher_dtls_recv_cb, &ctx);
}

void nc_attacher_an_conn_created_cb(const np_error_code ec, uint8_t channelId, void* data)
{
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.pl->dtlsC.async_connect(ctx.pl, &ctx.anConn, &nc_attacher_an_dtls_conn_cb, &ctx);
}

void nc_attacher_an_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
{
    NABTO_LOG_INFO(LOG, "Attach node address resolved with status: %u", ec);
    if (ec != NABTO_EC_OK || recSize == 0) {
        NABTO_LOG_ERROR(LOG, "Failed to resolve attach node host");
        ctx.cb(ec, ctx.cbData);
        return;
    }
    memcpy(&ctx.anChannel.ep.ip, &rec[0], sizeof(struct np_ip_address));
    ctx.anChannel.type = NABTO_CHANNEL_DTLS;
    ctx.anChannel.sock = ctx.sock;
    ctx.pl->conn.async_create(ctx.pl, &ctx.anConn, &ctx.anChannel, &ctx.id, &nc_attacher_an_conn_created_cb, &ctx);
}

void nc_attacher_ad_dtls_conn_cb(const np_error_code ec, np_dtls_cli_context* crypCtx, void* data)
{
    uint8_t* ptr;
    uint8_t* start;
    uint16_t len;
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.adDtls = crypCtx;
    ctx.buffer = ctx.pl->buf.allocate();
    ptr = ctx.pl->buf.start(ctx.buffer);
    start = ptr;
    ptr = init_packet_header(ptr, ATTACH_DISPATCH);
    *(start+1) = ATTACH_DISPATCH_REQUEST;
    // TODO: only insert extensions which is supported
    ptr = insert_packet_extension(ctx.pl, ctx.buffer, UDP_IPV4_EP, NULL, 0);
    ptr = insert_packet_extension(ctx.pl, ctx.buffer, UDP_IPV6_EP, NULL, 0);
    NABTO_LOG_TRACE(LOG, "Sending Attach Dispatch Request:");
    NABTO_LOG_BUF(LOG, start, ptr - start);
    ctx.pl->dtlsC.async_send_to(ctx.pl, ctx.adDtls, 0xff, start, ptr - start, &nc_attacher_ad_dtls_send_cb, &ctx);
    ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.adDtls, ATTACH_DISPATCH, &nc_attacher_dtls_recv_cb, &ctx);
}

void nc_attacher_ad_conn_created_cb(const np_error_code ec, uint8_t channelId, void* data)
{
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.pl->dtlsC.async_connect(ctx.pl, &ctx.adConn, &nc_attacher_ad_dtls_conn_cb, &ctx);
}

void nc_attacher_ad_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
{
    if (ec != NABTO_EC_OK || recSize == 0) {
        NABTO_LOG_ERROR(LOG, "Failed to resolve attach dispatcher host");
        ctx.cb(ec, ctx.cbData);
        return;
    }
    // TODO: get attach_dispatcher_port from somewhere
    ctx.adChannel.ep.port = ATTACH_DISPATCHER_PORT;
    // TODO: Pick a record which matches the supported protocol IPv4/IPv6 ?
    for (int i = 0; i < recSize; i++) {
    }
    memcpy(&ctx.adChannel.ep.ip, &rec[0], sizeof(struct np_ip_address));
    ctx.adChannel.type = NABTO_CHANNEL_DTLS;
    ctx.adChannel.sock = ctx.sock;
    ctx.pl->conn.async_create(ctx.pl, &ctx.adConn, &ctx.adChannel, &ctx.id, &nc_attacher_ad_conn_created_cb, &ctx);
}

void nc_attacher_sock_created_cb(const np_error_code ec, np_udp_socket* sock, void* data)
{
    ctx.sock = sock;
    ctx.pl->dns.async_resolve(ctx.pl, ctx.dns, &nc_attacher_ad_dns_cb, &ctx);
}

/**
 * Dispatching function for incoming packets
 */
void nc_attacher_dtls_recv_cb(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                              np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    uint8_t* start = ctx.pl->buf.start(buf);
    switch ((enum application_data_type)start[0]) {
        case ATTACH:
            nc_attacher_an_handle_event(ec, buf, bufferSize, data);
            ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.anDtls, ATTACH, &nc_attacher_dtls_recv_cb, &ctx);
            return;
        case ATTACH_DISPATCH:
            nc_attacher_ad_handle_event(ec, buf, bufferSize, data);
            ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.adDtls, ATTACH_DISPATCH, &nc_attacher_dtls_recv_cb, &ctx);
            return;
        default:
            NABTO_LOG_ERROR(LOG, "Attacher received a packet which was neither ATTACH or ATTACH_DISPATCH");
            return;
    }
}

/** 
 * API functions
 */
np_error_code nc_attacher_async_attach(struct np_platform* pl, nc_attached_callback cb, void* data)
{
    ctx.pl = pl;
    ctx.cb = cb;
    ctx.cbData = data;
    // TODO: resolve a attach dispatcher host from somewhere
    memcpy(ctx.dns, "localhost", 10);
    pl->udp.async_create(&nc_attacher_sock_created_cb, &ctx);
}

np_error_code nc_attacher_register_detatch_callback(nc_detached_callback cb, void* data)
{
    ctx.detachCb = cb;
    ctx.detachData = data;
}

/**
 * Callback functions only used for error handling
 */
void nc_attacher_an_dtls_send_cb(const np_error_code ec, void* data) {
    NABTO_LOG_TRACE(LOG, "an_dtls_send_cb invoked");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "Failed to send attach device hello");
        ctx.cb(ec, ctx.cbData);
        return;
    }
}

void nc_attacher_ad_dtls_closed_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(LOG, "dtls connection closed callback");
}

void nc_attacher_ad_dtls_send_cb(const np_error_code ec, void* data) {
    NABTO_LOG_TRACE(LOG, "dtlsSendCb invoked");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "Failed to send attach dispatcher request");
        ctx.cb(ec, ctx.cbData);
        return;
    }
}

