
#include "nc_attacher.h"

#include <core/nc_packet.h>
#include <platform/np_logging.h>
#include <core/nc_version.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

// TODO: Move this definition to some configuration
#define NABTO_MAX_DR_EPS 2

struct nc_attach_dr_endpoint {
    uint16_t port;
    uint8_t az;
    uint8_t fp[16];
    char dns[256];
    uint8_t dnsLen;
};

struct nc_attach_send_data {
    np_dtls_cli_context* cryp;
    uint8_t chan;
    uint8_t* start;
    uint32_t size;
    np_dtls_send_to_callback cb;
    void* data;
    struct np_timed_event ev;
};

struct nc_attach_context {
    struct np_platform* pl;
    const struct nc_attach_parameters* params;
    struct nc_attach_send_data sendData;
    uint32_t sessionId;
    struct nc_attach_dr_endpoint drEps[NABTO_MAX_DR_EPS];
    uint8_t activeDrEps;
    nc_attached_callback cb;
    nc_detached_callback detachCb;
    void* detachData;
    np_udp_socket* sock;
    void* cbData;
    np_connection lbConn;
    np_connection drConn;
    np_dtls_cli_context* lbDtls;
    np_dtls_cli_context* drDtls;
    np_communication_buffer* buffer;
    struct np_connection_id id;
    struct np_connection_channel drChannel;
    struct np_connection_channel lbChannel;
    char dns[256];
    uint8_t dnsLen;
};

struct nc_attach_context ctx;

/**
 * Device Relay functions
 */
void nc_attacher_dr_dtls_closed_cb(const np_error_code ec, void* data);
void nc_attacher_dr_dtls_send_cb(const np_error_code ec, void* data);
void nc_attacher_dr_handle_event(const np_error_code ec, np_communication_buffer* buf,
                                     uint16_t bufferSize, void* data);
void nc_attacher_dr_dtls_conn_cb(const np_error_code ec, np_dtls_cli_context* crypCtx, void* data);
void nc_attacher_dr_conn_created_cb(const np_error_code ec, uint8_t channelId, void* data);
void nc_attacher_dr_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data);

/**
 * general packet dispatching
 */
void nc_attacher_dtls_recv_cb(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                              np_communication_buffer* buf, uint16_t bufferSize, void* data);

/**
 * Attach dispatcher functions
 */
void nc_attacher_lb_dtls_closed_cb(const np_error_code ec, void* data);
void nc_attacher_lb_dtls_send_cb(const np_error_code ec, void* data);
void nc_attacher_lb_handle_event(const np_error_code ec, np_communication_buffer* buf,
                                 uint16_t bufferSize, void* data);
void nc_attacher_lb_dtls_conn_cb(const np_error_code ec, np_dtls_cli_context* crypCtx, void* data);
void nc_attacher_lb_conn_created_cb(const np_error_code ec, uint8_t channelId, void* data);
void nc_attacher_lb_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data);
/**
 * create socket reused for both DTLS connections
 */
void nc_attacher_sock_created_cb(const np_error_code ec, np_udp_socket* sock, void* data);

void nc_attacher_send_to(np_dtls_cli_context* cryp, uint8_t chan, uint8_t* start, uint32_t size, np_dtls_send_to_callback cb, void* data);

void nc_attacher_dr_handle_event(const np_error_code ec, np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    uint8_t type;
    uint8_t fp[16];
    np_error_code fpEc;
    if(ec != NABTO_EC_OK) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    fpEc = ctx.pl->dtlsC.get_fingerprint(ctx.pl, ctx.drDtls, fp);
    if (fpEc != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "get_fingerprint failed");
        NABTO_LOG_BUF(LOG, fp, 16);
        NABTO_LOG_BUF(LOG, ctx.drEps[0].fp, 16);
        ctx.cb(fpEc, ctx.cbData);
        return;
    }
    if(memcmp(fp, ctx.drEps[0].fp, 16) != 0) {
        NABTO_LOG_ERROR(LOG, "Device relay connected with invalid fingerprint");
        NABTO_LOG_BUF(LOG, fp, 16);
        NABTO_LOG_BUF(LOG, ctx.drEps[0].fp, 16);
        ctx.cb(NABTO_EC_INVALID_PEER_FINGERPRINT, ctx.cbData);
        return;
    }
    type= ctx.pl->buf.start(buf)[1];
    NABTO_LOG_TRACE(LOG, "ATTACH packet received");
    NABTO_LOG_BUF(LOG, ctx.pl->buf.start(buf), bufferSize);
    if (type == CT_DEVICE_RELAY_HELLO_RESPONSE) {
        np_event_queue_cancel_timed_event(ctx.pl, &ctx.sendData.ev);
        NABTO_LOG_INFO(LOG, "Device is now ATTACHED");
        ctx.cb(NABTO_EC_OK, ctx.cbData);
    } else {
        NABTO_LOG_ERROR(LOG, "unknown attach_content_type %u found ",type); 
    }
}

void nc_attacher_lb_handle_event(const np_error_code ec, np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    uint8_t* start = ctx.pl->buf.start(buf);
    uint8_t* ptr = start;
    uint8_t* dns = NULL;
    uint16_t dnsLen;
    uint32_t sessionId;
    bool sessionFound = false;

    if (ec != NABTO_EC_OK) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    if (bufferSize < NABTO_PACKET_HEADER_SIZE || *start != AT_DEVICE_LB) {
        NABTO_LOG_ERROR(LOG, "Received malformed AT_DEVICE_LB response packet");
        ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
        return;
    }
    NABTO_LOG_TRACE(LOG, "AT_DEVICE_LB packet received:");
    NABTO_LOG_BUF(LOG, start, bufferSize);
    if (*(start+1) == CT_DEVICE_LB_RESPONSE) {
        NABTO_LOG_TRACE(LOG, "CT_DEVICE_LB_RESPONSE");
        np_event_queue_cancel_timed_event(ctx.pl, &ctx.sendData.ev);
        ptr = ptr + NABTO_PACKET_HEADER_SIZE; // skip header;
        NABTO_LOG_TRACE(LOG, "starting while with %u <= %u", ptr-start+4, bufferSize);
        ctx.activeDrEps = 0;
        while (ptr - start + 4 <= bufferSize) { // while 4 bytes(extension header size) more is available
            NABTO_LOG_TRACE(LOG, "Remaining packet for decoding:");
            NABTO_LOG_BUF(LOG, ptr, bufferSize - (ptr-start));
            uint16_t extType = uint16_read(ptr);
            uint16_t extLen = uint16_read(ptr+2);
            if (extType == EX_DTLS_EP) {
                if (extLen < 20) {
                    NABTO_LOG_ERROR(LOG, "Found DTLS_EP extension with invalid length");
                    ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
                    return;
                } 
                if (ctx.activeDrEps < NABTO_MAX_DR_EPS) {
                    ctx.drEps[ctx.activeDrEps].port = uint16_read(ptr+4);
                    ctx.drEps[ctx.activeDrEps].az = *(ptr+6);
                    memcpy(ctx.drEps[ctx.activeDrEps].fp, ptr+7, 16);
                    ctx.drEps[ctx.activeDrEps].dnsLen = *(ptr+23);
                    memcpy(ctx.drEps[ctx.activeDrEps].dns, ptr+24, ctx.drEps[ctx.activeDrEps].dnsLen);
                    ctx.drEps[ctx.activeDrEps].dns[ctx.drEps[ctx.activeDrEps].dnsLen] = '\0';
                    NABTO_LOG_TRACE(LOG, "Found DNS extension with port: %u, az: %u, dnsLen: %u, dns: %s, fp:",
                                    ctx.drEps[ctx.activeDrEps].port, ctx.drEps[ctx.activeDrEps].az,
                                    ctx.drEps[ctx.activeDrEps].dnsLen, ctx.drEps[ctx.activeDrEps].dns);
                    NABTO_LOG_BUF(LOG, ctx.drEps[ctx.activeDrEps].fp, 16);
                    ctx.activeDrEps++;
                } else {
                    NABTO_LOG_TRACE(LOG, "Found DNS extension but array is full");
                }
                
            } else if (extType == EX_SESSION_ID) {
                if (extLen != 4) {
                    NABTO_LOG_ERROR(LOG, "Found SESSION_ID extension with invalid length");
                    ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
                    return;
                }
                sessionId = uint32_read(ptr+4);
                sessionFound = true;
                NABTO_LOG_TRACE(LOG, "Found SESSION_ID extension with id: %u", sessionId);
            }
            ptr = ptr + extLen + 4;
        }
        if (ctx.activeDrEps == 0 || !sessionFound) {
            NABTO_LOG_ERROR(LOG, "Failed to find DTLS_EP or SESSION_ID extension in DEVICE_LB_RESPONSE");
            ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
            return;
        }
        // TODO: For now we simply attach to the first AN in the array
        ctx.sessionId = sessionId;
        ctx.drChannel.ep.port = ctx.drEps[0].port;
        ctx.pl->dns.async_resolve(ctx.pl, ctx.drEps[0].dns, &nc_attacher_dr_dns_cb, &ctx);
        ctx.pl->dtlsC.cancel_recv_from(ctx.pl, ctx.lbDtls, AT_DEVICE_LB);
        ctx.pl->dtlsC.async_close(ctx.pl, ctx.lbDtls, &nc_attacher_lb_dtls_closed_cb, &ctx);
        
    } else if (*(start+1) == CT_DEVICE_LB_REDIRECT) {
        NABTO_LOG_TRACE(LOG, "CT_DEVICE_LB_REDIRECT");
        ptr = ptr + NABTO_PACKET_HEADER_SIZE; // skip header;
        while (true) {
            uint16_t extType = uint16_read(ptr);
            uint16_t extLen = uint16_read(ptr+2);
            if (extType == EX_UDP_DNS_EP) {
                ctx.lbChannel.ep.port = uint16_read(ptr+4);
                dns = ptr+8;
                dnsLen = uint16_read(ptr+6);
                NABTO_LOG_TRACE(LOG, "Found DNS extension with port: %u, dns: %s", ctx.lbChannel.ep.port, (char*)dns);
                break;
            }
            ptr = ptr + extLen + 4;
            if (ptr - start >= bufferSize) {
                NABTO_LOG_ERROR(LOG, "Failed to find DNS extension in CT_DEVICE_LB_REDIRECT");
                ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
                return;
            }
        }
        memcpy(ctx.dns, dns, dnsLen);
        ctx.pl->dns.async_resolve(ctx.pl, ctx.dns, &nc_attacher_lb_dns_cb, &ctx);
        
        return;

    } else {
        NABTO_LOG_ERROR(LOG, "Received AT_DEVICE_LB packet with invalid content type");
        ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
        return;
    }
        
}

void nc_attacher_send_to_event(const np_error_code ec, void* data)
{
    if (ec == NABTO_EC_OK) {
        nc_attacher_send_to(ctx.sendData.cryp, ctx.sendData.chan, ctx.sendData.start, ctx.sendData.size, ctx.sendData.cb, ctx.sendData.data);
    }
}

void nc_attacher_send_to(np_dtls_cli_context* cryp, uint8_t chan, uint8_t* start,
                         uint32_t size, np_dtls_send_to_callback cb, void* data)
{
    ctx.sendData.cryp = cryp;
    ctx.sendData.chan = chan;
    ctx.sendData.start = start;
    ctx.sendData.size = size;
    ctx.sendData.cb = cb;
    ctx.sendData.data = data;
    ctx.pl->dtlsC.async_send_to(ctx.pl, cryp, chan, start, size, cb, data);
    np_event_queue_post_timed_event(ctx.pl, &ctx.sendData.ev, 5000, &nc_attacher_send_to_event, &ctx);
}

void nc_attacher_dr_dtls_conn_cb(const np_error_code ec, np_dtls_cli_context* crypCtx, void* data)
{
    uint8_t attachIndex = 0;
    uint8_t* ptr = ctx.pl->buf.start(ctx.buffer);
    uint8_t* start = ptr;
    uint8_t extBuffer[37];
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    if( ctx.pl->dtlsC.get_alpn_protocol(crypCtx) == NULL ) {
        NABTO_LOG_ERROR(LOG, "Application Layer Protocol Negotiation failed for Device Relay connection");
        ctx.pl->dtlsC.async_close(ctx.pl, crypCtx, &nc_attacher_dr_dtls_closed_cb, &ctx);
        ctx.cb(NABTO_EC_ALPN_FAILED, ctx.cbData);
        return;
    }
    
    ctx.drDtls = crypCtx;
    ptr = init_packet_header(ptr, AT_DEVICE_RELAY);
    *(start+1) = CT_DEVICE_RELAY_HELLO_REQUEST;
    ptr = insert_packet_extension(ctx.pl, ptr, EX_SESSION_ID, (uint8_t*)&ctx.sessionId, 4);
    // TODO: only using first DR_EP for now, expand to multi attach
    ptr = insert_packet_extension(ctx.pl, ptr, EX_ATTACH_INDEX, (uint8_t*)&attachIndex, 1);

    extBuffer[0] = (uint8_t)strlen(NABTO_VERSION);
    memcpy(&extBuffer[1], NABTO_VERSION, strlen(NABTO_VERSION));
    ptr = insert_packet_extension(ctx.pl, ptr, EX_NABTO_VERSION, extBuffer, strlen(NABTO_VERSION)+1);

    extBuffer[0] = ctx.params->appVersionLength;
    memcpy(&extBuffer[1], ctx.params->appVersion, ctx.params->appVersionLength);
    ptr = insert_packet_extension(ctx.pl, ptr, EX_APPLICATION_VERSION, extBuffer, ctx.params->appVersionLength+1);

    extBuffer[0] = ctx.params->appNameLength;
    memcpy(&extBuffer[1], ctx.params->appName, ctx.params->appNameLength);
    ptr = insert_packet_extension(ctx.pl, ptr, EX_APPLICATION_NAME, extBuffer, ctx.params->appNameLength+1);
    
    NABTO_LOG_TRACE(LOG, "Sending CT_DEVICE_RELAY_HELLO_REQUEST:");
    NABTO_LOG_BUF(LOG, start, ptr - start);
    nc_attacher_send_to(ctx.drDtls, 0xff, start, ptr-start, &nc_attacher_dr_dtls_send_cb, &ctx);
    ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.drDtls, AT_DEVICE_RELAY, &nc_attacher_dtls_recv_cb, &ctx);
//    ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.drDtls, KEEP_ALIVE, &nc_attacher_dtls_recv_cb, &ctx);
}

void nc_attacher_dr_conn_created_cb(const np_error_code ec, uint8_t channelId, void* data)
{
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.pl->dtlsC.async_connect(ctx.pl, &ctx.drConn, &nc_attacher_dr_dtls_conn_cb, &ctx);
}

void nc_attacher_dr_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
{
    NABTO_LOG_INFO(LOG, "Device relay address resolved with status: %u", ec);
    if (ec != NABTO_EC_OK || recSize == 0) {
        NABTO_LOG_ERROR(LOG, "Failed to resolve device relay host");
        ctx.cb(ec, ctx.cbData);
        return;
    }
    memcpy(&ctx.drChannel.ep.ip, &rec[0], sizeof(struct np_ip_address));
    ctx.drChannel.type = NABTO_CHANNEL_DTLS;
    ctx.drChannel.sock = ctx.sock;
    ctx.pl->conn.async_create(ctx.pl, &ctx.drConn, &ctx.drChannel, &ctx.id, &nc_attacher_dr_conn_created_cb, &ctx);
}

void nc_attacher_lb_dtls_conn_cb(const np_error_code ec, np_dtls_cli_context* crypCtx, void* data)
{
    uint8_t* ptr;
    uint8_t* start;
    uint16_t len;
    uint8_t extBuffer[34];
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    if( ctx.pl->dtlsC.get_alpn_protocol(crypCtx) == NULL ) {
        NABTO_LOG_ERROR(LOG, "Application Layer Protocol Negotiation failed for Device Load Balancer connection");
        ctx.pl->dtlsC.async_close(ctx.pl, crypCtx, &nc_attacher_lb_dtls_closed_cb, &ctx);
        ctx.cb(NABTO_EC_ALPN_FAILED, ctx.cbData);
        return;
    }
    
    ctx.lbDtls = crypCtx;
    ctx.buffer = ctx.pl->buf.allocate();
    ptr = ctx.pl->buf.start(ctx.buffer);
    start = ptr;
    ptr = init_packet_header(ptr, AT_DEVICE_LB);
    *(start+1) = CT_DEVICE_LB_REQUEST;

    extBuffer[0] = (uint8_t)strlen(NABTO_VERSION);
    memcpy(&extBuffer[1], NABTO_VERSION, strlen(NABTO_VERSION));
    ptr = insert_packet_extension(ctx.pl, ptr, EX_NABTO_VERSION, extBuffer, strlen(NABTO_VERSION)+1);

    extBuffer[0] = ctx.params->appVersionLength;
    memcpy(&extBuffer[1], ctx.params->appVersion, ctx.params->appVersionLength);
    ptr = insert_packet_extension(ctx.pl, ptr, EX_APPLICATION_VERSION, extBuffer, ctx.params->appVersionLength+1);

    extBuffer[0] = ctx.params->appNameLength;
    memcpy(&extBuffer[1], ctx.params->appName, ctx.params->appNameLength);
    ptr = insert_packet_extension(ctx.pl, ptr, EX_APPLICATION_NAME, extBuffer, ctx.params->appNameLength+1);
    
    NABTO_LOG_TRACE(LOG, "Sending device lb Request:");
    NABTO_LOG_BUF(LOG, start, ptr - start);
    nc_attacher_send_to(ctx.lbDtls, 0xff, start, ptr-start, &nc_attacher_lb_dtls_send_cb, &ctx);
    //ctx.pl->dtlsC.async_send_to(ctx.pl, ctx.lbDtls, 0xff, start, ptr - start, &nc_attacher_lb_dtls_send_cb, &ctx);
    ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.lbDtls, AT_DEVICE_LB, &nc_attacher_dtls_recv_cb, &ctx);
}

void nc_attacher_lb_conn_created_cb(const np_error_code ec, uint8_t channelId, void* data)
{
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.pl->dtlsC.async_connect(ctx.pl, &ctx.lbConn, &nc_attacher_lb_dtls_conn_cb, &ctx);
}

void nc_attacher_lb_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
{
    if (ec != NABTO_EC_OK || recSize == 0) {
        NABTO_LOG_ERROR(LOG, "Failed to resolve attach dispatcher host");
        ctx.cb(ec, ctx.cbData);
        return;
    }
    // TODO: get load_balancer_port from somewhere
    ctx.lbChannel.ep.port = LOAD_BALANCER_PORT;
    // TODO: Pick a record which matches the supported protocol IPv4/IPv6 ?
    for (int i = 0; i < recSize; i++) {
    }
    memcpy(&ctx.lbChannel.ep.ip, &rec[0], sizeof(struct np_ip_address));
    ctx.lbChannel.type = NABTO_CHANNEL_DTLS;
    ctx.lbChannel.sock = ctx.sock;
    ctx.pl->conn.async_create(ctx.pl, &ctx.lbConn, &ctx.lbChannel, &ctx.id, &nc_attacher_lb_conn_created_cb, &ctx);
}

void nc_attacher_sock_created_cb(const np_error_code ec, np_udp_socket* sock, void* data)
{
    ctx.sock = sock;
    ctx.pl->dns.async_resolve(ctx.pl, ctx.dns, &nc_attacher_lb_dns_cb, &ctx);
}

/**
 * Dispatching function for incoming packets
 */
void nc_attacher_dtls_recv_cb(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                              np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    uint8_t* start = ctx.pl->buf.start(buf);
    NABTO_LOG_TRACE(LOG, "Received data from dtls:");
    NABTO_LOG_BUF(LOG, ctx.pl->buf.start(buf), bufferSize);
    switch ((enum application_data_type)start[0]) {
        case AT_DEVICE_RELAY:
            ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.drDtls, AT_DEVICE_RELAY, &nc_attacher_dtls_recv_cb, &ctx);
            nc_attacher_dr_handle_event(ec, buf, bufferSize, data);
            return;
        case AT_DEVICE_LB:
            ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.lbDtls, AT_DEVICE_LB, &nc_attacher_dtls_recv_cb, &ctx);
            nc_attacher_lb_handle_event(ec, buf, bufferSize, data);
            return;
        default:
            NABTO_LOG_ERROR(LOG, "Attacher received a packet which was neither AT_DEVICE_RELAY or AT_DEVICE_LB");
            return;
    }
}

/** 
 * API functions
 */
np_error_code nc_attacher_async_attach(struct np_platform* pl, const struct nc_attach_parameters* params,
                                       nc_attached_callback cb, void* data)
{
    ctx.pl = pl;
    ctx.cb = cb;
    ctx.cbData = data;
    ctx.params = params;
    
    memcpy(ctx.dns, ctx.params->hostname, ctx.params->hostnameLength);
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
void nc_attacher_dr_dtls_send_cb(const np_error_code ec, void* data) {
    NABTO_LOG_TRACE(LOG, "dr_dtls_send_cb invoked");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "Failed to send attach device hello");
        ctx.cb(ec, ctx.cbData);
        return;
    }
}

void nc_attacher_lb_dtls_closed_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(LOG, "lb dtls connection closed callback");
}

void nc_attacher_dr_dtls_closed_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(LOG, "an dtls connection closed callback");
}

void nc_attacher_lb_dtls_send_cb(const np_error_code ec, void* data) {
    NABTO_LOG_TRACE(LOG, "dtlsSendCb invoked");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "Failed to send attach dispatcher request");
        ctx.cb(ec, ctx.cbData);
        return;
    }
}

