
#include "nc_attacher.h"

#include <core/nc_keep_alive.h>
#include <core/nc_packet.h>
#include <platform/np_logging.h>
#include <core/nc_version.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

// TODO: Move this definition to some configuration
#define NABTO_MAX_AN_EPS 2

struct nc_attach_an_endpoint {
    uint16_t port;
    uint8_t az;
    uint8_t fp[16];
    char dns[256];
    uint8_t dnsLen;
};

struct nc_attach_context {
    struct np_platform* pl;
    const struct nc_attach_parameters* params;
    uint32_t sessionId;
    struct nc_attach_an_endpoint anEps[NABTO_MAX_AN_EPS];
    uint8_t activeAnEps;
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
    struct np_connection_id id;
    struct np_connection_channel anChannel;
    struct np_connection_channel adChannel;
    struct keep_alive_context kactx;
    char dns[256];
    uint8_t dnsLen;
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


void nc_attacher_ka_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(LOG,"Attacher received keep alive callback with error code: %u", ec);
}

void nc_attacher_an_handle_event(const np_error_code ec, np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    uint8_t type;
    uint8_t fp[16];
    np_error_code fpEc;
    if(ec != NABTO_EC_OK) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    fpEc = ctx.pl->dtlsC.get_fingerprint(ctx.pl, ctx.anDtls, fp);
    if (fpEc != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "get_fingerprint failed");
        NABTO_LOG_BUF(LOG, fp, 16);
        NABTO_LOG_BUF(LOG, ctx.anEps[0].fp, 16);
        ctx.cb(fpEc, ctx.cbData);
        return;
    }
    if(memcmp(fp, ctx.anEps[0].fp, 16) != 0) {
        NABTO_LOG_ERROR(LOG, "Device relay connected with invalid fingerprint");
        NABTO_LOG_BUF(LOG, fp, 16);
        NABTO_LOG_BUF(LOG, ctx.anEps[0].fp, 16);
        ctx.cb(NABTO_EC_INVALID_PEER_FINGERPRINT, ctx.cbData);
        return;
    }
    type= ctx.pl->buf.start(buf)[1];
    NABTO_LOG_TRACE(LOG, "ATTACH packet received");
    NABTO_LOG_BUF(LOG, ctx.pl->buf.start(buf), bufferSize);
    if (type == CT_DEVICE_RELAY_HELLO_RESPONSE) {
        NABTO_LOG_INFO(LOG, "Device is now ATTACHED");
        nc_keep_alive_init(ctx.pl, &ctx.kactx, ctx.anDtls, &nc_attacher_ka_cb, &ctx);
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
        ptr = ptr + NABTO_PACKET_HEADER_SIZE; // skip header;
        NABTO_LOG_TRACE(LOG, "starting while with %u <= %u", ptr-start+4, bufferSize);
        ctx.activeAnEps = 0;
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
                // TODO: remember this:
                //ctx.anChannel.ep.port = uint16_read(ptr+4);
                //dns = ptr+8;
                //dnsLen = uint16_read(ptr+6);
                if (ctx.activeAnEps < NABTO_MAX_AN_EPS) {
                    ctx.anEps[ctx.activeAnEps].port = uint16_read(ptr+4);
                    ctx.anEps[ctx.activeAnEps].az = *(ptr+6);
                    memcpy(ctx.anEps[ctx.activeAnEps].fp, ptr+7, 16);
                    ctx.anEps[ctx.activeAnEps].dnsLen = *(ptr+23);
                    memcpy(ctx.anEps[ctx.activeAnEps].dns, ptr+24, ctx.anEps[ctx.activeAnEps].dnsLen);
                    ctx.anEps[ctx.activeAnEps].dns[ctx.anEps[ctx.activeAnEps].dnsLen] = '\0';
                    NABTO_LOG_TRACE(LOG, "Found DNS extension with port: %u, az: %u, dnsLen: %u, dns: %s, fp:",
                                    ctx.anEps[ctx.activeAnEps].port, ctx.anEps[ctx.activeAnEps].az,
                                    ctx.anEps[ctx.activeAnEps].dnsLen, ctx.anEps[ctx.activeAnEps].dns);
                    NABTO_LOG_BUF(LOG, ctx.anEps[ctx.activeAnEps].fp, 16);
                    ctx.activeAnEps++;
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
        if (ctx.activeAnEps == 0 || !sessionFound) {
            NABTO_LOG_ERROR(LOG, "Failed to find DTLS_EP or SESSION_ID extension in DEVICE_LB_RESPONSE");
            ctx.cb(NABTO_EC_MALFORMED_PACKET, ctx.cbData);
            return;
        }
        // TODO: For now we simply attach to the first AN in the array
        ctx.sessionId = sessionId;
        ctx.anChannel.ep.port = ctx.anEps[0].port;
        ctx.pl->dns.async_resolve(ctx.pl, ctx.anEps[0].dns, &nc_attacher_an_dns_cb, &ctx);
        ctx.pl->dtlsC.async_close(ctx.pl, ctx.adDtls, &nc_attacher_lb_dtls_closed_cb, &ctx);
        
    } else if (*(start+1) == CT_DEVICE_LB_REDIRECT) {
        NABTO_LOG_TRACE(LOG, "CT_DEVICE_LB_REDIRECT");
        ptr = ptr + NABTO_PACKET_HEADER_SIZE; // skip header;
        while (true) {
            uint16_t extType = uint16_read(ptr);
            uint16_t extLen = uint16_read(ptr+2);
            if (extType == EX_UDP_DNS_EP) {
                ctx.adChannel.ep.port = uint16_read(ptr+4);
                dns = ptr+8;
                dnsLen = uint16_read(ptr+6);
                NABTO_LOG_TRACE(LOG, "Found DNS extension with port: %u, dns: %s", ctx.adChannel.ep.port, (char*)dns);
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

void nc_attacher_an_dtls_conn_cb(const np_error_code ec, np_dtls_cli_context* crypCtx, void* data)
{
    uint8_t attachIndex = 0;
    uint8_t* ptr = ctx.pl->buf.start(ctx.buffer);
    uint8_t* start = ptr;
    uint8_t extBuffer[37];
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.anDtls = crypCtx;
    ptr = init_packet_header(ptr, AT_DEVICE_RELAY);
    *(start+1) = CT_DEVICE_RELAY_HELLO_REQUEST;
    // TODO: insert extensions: SESSION_ID, ATTACH_INDEX, NABTO_VERSION, APP_VERSION, APP_NAME
    ptr = insert_packet_extension(ctx.pl, ptr, EX_SESSION_ID, (uint8_t*)&ctx.sessionId, 4);
    // TODO: only using first AN_EP for now, expand to multi attach
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
    ctx.pl->dtlsC.async_send_to(ctx.pl, ctx.anDtls, 0xff, start, ptr - start, &nc_attacher_an_dtls_send_cb, &ctx);
    ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.anDtls, AT_DEVICE_RELAY, &nc_attacher_dtls_recv_cb, &ctx);
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
    ctx.adDtls = crypCtx;
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
    ctx.pl->dtlsC.async_send_to(ctx.pl, ctx.adDtls, 0xff, start, ptr - start, &nc_attacher_lb_dtls_send_cb, &ctx);
    ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.adDtls, AT_DEVICE_LB, &nc_attacher_dtls_recv_cb, &ctx);
}

void nc_attacher_lb_conn_created_cb(const np_error_code ec, uint8_t channelId, void* data)
{
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.pl->dtlsC.async_connect(ctx.pl, &ctx.adConn, &nc_attacher_lb_dtls_conn_cb, &ctx);
}

void nc_attacher_lb_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
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
    ctx.pl->conn.async_create(ctx.pl, &ctx.adConn, &ctx.adChannel, &ctx.id, &nc_attacher_lb_conn_created_cb, &ctx);
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
            nc_attacher_an_handle_event(ec, buf, bufferSize, data);
            ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.anDtls, AT_DEVICE_RELAY, &nc_attacher_dtls_recv_cb, &ctx);
            return;
        case AT_DEVICE_LB:
            nc_attacher_lb_handle_event(ec, buf, bufferSize, data);
            ctx.pl->dtlsC.async_recv_from(ctx.pl, ctx.adDtls, AT_DEVICE_LB, &nc_attacher_dtls_recv_cb, &ctx);
            return;
        default:
            NABTO_LOG_ERROR(LOG, "Attacher received a packet which was neither AT_DEVICE_RELAY or AT_DEVICE_LB");
            return;
    }
}

/** 
 * API functions
 */
np_error_code nc_attacher_async_attach(struct np_platform* pl, const struct nc_attach_parameters* params, nc_attached_callback cb, void* data)
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
void nc_attacher_an_dtls_send_cb(const np_error_code ec, void* data) {
    NABTO_LOG_TRACE(LOG, "an_dtls_send_cb invoked");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "Failed to send attach device hello");
        ctx.cb(ec, ctx.cbData);
        return;
    }
}

void nc_attacher_lb_dtls_closed_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(LOG, "dtls connection closed callback");
}

void nc_attacher_lb_dtls_send_cb(const np_error_code ec, void* data) {
    NABTO_LOG_TRACE(LOG, "dtlsSendCb invoked");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "Failed to send attach dispatcher request");
        ctx.cb(ec, ctx.cbData);
        return;
    }
}

