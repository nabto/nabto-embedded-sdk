#include "nm_dtls_cli.h"
#include "nm_dtls_util.h"

#include <platform/np_logging.h>
#include <core/nc_version.h>
#include <core/nc_udp_dispatch.h>

#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
#include <mbedtls/timing.h>

#include <string.h>
#include <stdlib.h>

#define NABTO_SSL_RECV_BUFFER_SIZE 4096
#define SERVER_NAME "localhost"
#define LOG NABTO_LOG_MODULE_DTLS_CLI
#define DEBUG_LEVEL 0

struct np_dtls_cli_context {
    struct np_platform* pl;
    struct nm_dtls_util_connection_ctx ctx;
    struct nc_udp_dispatch_context* udp;
    struct np_udp_endpoint ep;
    struct np_event connEv;
    np_dtls_cli_connect_callback connectCb;
    void* connectData;

    bool sending;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
};

// Global public/private key used for everything initialized with module init
mbedtls_x509_crt publicKey;
mbedtls_pk_context privateKey;

const char* nm_dtls_cli_alpnList[] = {NABTO_PROTOCOL_VERSION , NULL};


np_error_code nm_dtls_async_connect(struct np_platform* pl, struct nc_udp_dispatch_context* udp,
                                    struct np_udp_endpoint ep, np_dtls_cli_connect_callback cb, void* data);

// Function called by mbedtls when data should be sent to the network
int nm_dtls_mbedtls_send(void* ctx, const unsigned char* buffer, size_t bufferSize);
// Function called by mbedtls when it wants data from the network
int nm_dtls_mbedtls_recv(void* ctx, unsigned char* buffer, size_t bufferSize);
// Function called by mbedtls which creates timeout events
void nm_dtls_mbedtls_timing_set_delay(void* ctx, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds);
// Function called by mbedtls to determine when the next timeout event occurs
int nm_dtls_mbedtls_timing_get_delay(void* ctx);
// Function used to handle events during the connection phase
void nm_dtls_event_do_one(void* data);

// Handle packet from udp
np_error_code nm_dtls_cli_handle_packet(struct np_platform* pl, struct np_dtls_cli_context* ctx,
                                   np_communication_buffer* buffer, uint16_t bufferSize);

// callback function called by the connection module when data is ready from the network
//void nm_dtls_udp_received_callback(const np_error_code ec, struct np_udp_endpoint ep,
//                                   np_communication_buffer* buffer,
//                                   uint16_t bufferSize, void* data);

void nm_dtls_event_send_to(void* data);
void nm_dtls_do_close(void* data, np_error_code ec);

// setup function for the mbedtls context
np_error_code nm_dtls_setup_dtls_ctx(np_dtls_cli_context* ctx);

// Get the packet counters for given dtls_cli_context
np_error_code nm_dtls_get_packet_count(np_dtls_cli_context* ctx, uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = ctx->ctx.recvCount;
    *sentCount = ctx->ctx.sentCount;
    return NABTO_EC_OK;
}

// Get the result of the application layer protocol negotiation
const char*  nm_dtls_get_alpn_protocol(np_dtls_cli_context* ctx) {
    return mbedtls_ssl_get_alpn_protocol(&ctx->ctx.ssl);
}

// Start keep alive on the dtls connection
np_error_code nm_dtls_cli_start_keep_alive(struct np_dtls_cli_context* ctx, uint32_t interval, uint8_t retryInt, uint8_t maxRetries)
{
    return nc_keep_alive_start(ctx->pl, &ctx->ctx.keepAliveCtx, interval, retryInt, maxRetries);
}

// cancel recv_from callbacks
np_error_code nm_dtls_cancel_recv_from(struct np_platform* pl, np_dtls_cli_context* ctx,
                                       enum application_data_type type)
{
    int i;
    for (i = 0; i < NABTO_DTLS_MAX_RECV_CBS; i++) {
        if (ctx->ctx.recvCbs[i].type == type) {
            ctx->ctx.recvCbs[i].cb = NULL;
        }
    }
    return NABTO_EC_OK;
}

void nm_dtls_cli_ka_cb(const np_error_code ec, void* data)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*)data;
    NABTO_LOG_INFO(LOG,"DTLS CLI received keep alive callback with error code: %u", ec);
    if (ctx->ctx.state == CLOSING) {
        return;
    }
    ctx->ctx.state = CLOSING;
    nm_dtls_do_close(data, ec);
}

// Printing function used by mbedtls for logging
static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);
    uint32_t severity;
    switch (level) {
        case 1:
            severity = NABTO_LOG_SEVERITY_ERROR;
            break;
        case 2:
            severity = NABTO_LOG_SEVERITY_INFO;
            break;
        default:
            severity = NABTO_LOG_SEVERITY_TRACE;
            break;
    }
    
    NABTO_LOG_RAW(severity, NABTO_LOG_MODULE_DTLS_CLI, line, file, str );
}

/*
 * Initialize the np_platform to use this particular dtls cli module
 */
np_error_code nm_dtls_init(struct np_platform* pl,
                           const unsigned char* publicKeyL, size_t publicKeySize,
                           const unsigned char* privateKeyL, size_t privateKeySize)
{
    int ret = 0;
    pl->dtlsC.async_connect = &nm_dtls_async_connect;
    pl->dtlsC.async_send_to = &nm_dtls_async_send_to;
    pl->dtlsC.async_recv_from = &nm_dtls_async_recv_from;
    pl->dtlsC.async_close = &nm_dtls_async_close;
    pl->dtlsC.cancel_recv_from = &nm_dtls_cancel_recv_from;
    pl->dtlsC.get_fingerprint = &nm_dtls_get_fingerprint;
    pl->dtlsC.get_alpn_protocol = &nm_dtls_get_alpn_protocol;
    pl->dtlsC.get_packet_count = &nm_dtls_get_packet_count;
    pl->dtlsC.start_keep_alive = &nm_dtls_cli_start_keep_alive;
    pl->dtlsC.handle_packet = &nm_dtls_cli_handle_packet;
    
    mbedtls_x509_crt_init( &publicKey );
    mbedtls_pk_init( &privateKey );
    ret = mbedtls_x509_crt_parse( &publicKey, publicKeyL, publicKeySize+1);
    if( ret != 0 ) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_x509_crt_parse returned %d", ret );
        return NABTO_EC_FAILED;
    }
    ret =  mbedtls_pk_parse_key( &privateKey, privateKeyL, privateKeySize+1, NULL, 0 );
    if( ret != 0 ) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_pk_parse_key returned %d", ret );
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;
}

/**
 * get peers fingerprint for given DTLS client context
 */
np_error_code nm_dtls_get_fingerprint(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t* fp)
{
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ctx->ctx.ssl);
    if (!crt) {
        return NABTO_EC_FAILED;
    }
    return nm_dtls_util_fp_from_crt(crt, fp);
}


/*
 * asyncroniously start a dtls connection
 */
np_error_code nm_dtls_async_connect(struct np_platform* pl, struct nc_udp_dispatch_context* udp,
                                    struct np_udp_endpoint ep, np_dtls_cli_connect_callback cb, void* data)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*)malloc(sizeof(np_dtls_cli_context));
    np_error_code ec;
    memset(ctx, 0, sizeof(np_dtls_cli_context));
    ctx->udp = udp;
    ctx->ep = ep;
    ctx->pl = pl;
    ctx->ctx.state = CONNECTING;
    ctx->sending = false;
    nc_udp_dispatch_set_dtls_cli_context(udp, ctx);
    ctx->connectCb = cb;
    ctx->connectData = data;
    ctx->ctx.sslRecvBuf = pl->buf.allocate();
    ctx->ctx.sslSendBuffer = pl->buf.allocate();
    ec = nm_dtls_setup_dtls_ctx(ctx);
    if(ec == NABTO_EC_OK) {
        np_event_queue_post(pl, &ctx->connEv, &nm_dtls_event_do_one, ctx);
        nc_keep_alive_init_cli(ctx->pl, &ctx->ctx.keepAliveCtx, ctx, &nm_dtls_cli_ka_cb, ctx);
    }
    return ec;
}

/*
 * Handle events for the connection phase
 */
void nm_dtls_event_do_one(void* data)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*)data;
    int ret;
    if(ctx->ctx.state == CONNECTING) {
        ret = mbedtls_ssl_handshake( &ctx->ctx.ssl );
        if( ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
            //Keep State CONNECTING
            NABTO_LOG_TRACE(LOG, "Keeping CONNECTING state");
        } else {
            if( ret != 0 )
            {
                NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_handshake returned -0x%04x", -ret );
                ctx->connectCb(NABTO_EC_FAILED, NULL, ctx->connectData);
                np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
                nc_udp_dispatch_clear_dtls_cli_context(ctx->udp);
                free(ctx);
                return;
            }
            NABTO_LOG_INFO(LOG, "State changed to DATA");
            ctx->ctx.state = DATA;
            ctx->connectCb(NABTO_EC_OK, ctx, ctx->connectData);
        }
        return;
    } else if(ctx->ctx.state == DATA) {
        ret = mbedtls_ssl_read( &ctx->ctx.ssl, ctx->pl->buf.start(ctx->ctx.sslRecvBuf), ctx->pl->buf.size(ctx->ctx.sslRecvBuf) );
        if (ret == 0) {
            // EOF
            ctx->ctx.state = CLOSING;
            NABTO_LOG_INFO(LOG, "Received EOF, state = CLOSING");
        } else if (ret > 0) {
            uint64_t seq = *((uint64_t*)ctx->ctx.ssl.in_ctr);
            uint8_t* ptr = ctx->pl->buf.start(ctx->ctx.sslRecvBuf);
            ctx->ctx.recvCount++;
            if (ptr[0] == AT_KEEP_ALIVE) {
                if (ptr[1] == CT_KEEP_ALIVE_REQUEST) {
                    NABTO_LOG_TRACE(LOG, "Keep alive request, responding imidiately");
                    ptr[1] = CT_KEEP_ALIVE_RESPONSE;
                    ctx->ctx.sendCb = NULL;
                    ctx->ctx.sendBuffer = ptr;
                    ctx->ctx.sendBufferSize = 16 + NABTO_PACKET_HEADER_SIZE;
                    nm_dtls_event_send_to(ctx);
                    return;
                }
            }
            int i;
            for(i = 0; i < NABTO_DTLS_MAX_RECV_CBS; i++) {
                if (ctx->ctx.recvCbs[i].type == ptr[0] && ctx->ctx.recvCbs[i].cb != NULL) {
                    NABTO_LOG_TRACE(LOG, "found Callback function");
                    np_dtls_received_callback cb = ctx->ctx.recvCbs[i].cb;
                    ctx->ctx.recvCbs[i].cb = NULL;
                    cb(NABTO_EC_OK, ctx->ctx.currentChannelId, seq,
                       ctx->ctx.sslRecvBuf, ret, ctx->ctx.recvCbs[i].data);
                    return;
                }
            }
        }else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                  ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // OK
        } else {
            char buf[128];
            mbedtls_strerror(ret, buf, 128);
            NABTO_LOG_INFO(LOG, "Received ERROR -0x%04x : %s ", -ret, buf);
            ctx->ctx.state = CLOSING;
            nm_dtls_do_close(ctx, NABTO_EC_FAILED);
        }
        return;
    }
        
}

void nm_dtls_event_send_to(void* data)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    NABTO_LOG_TRACE(LOG, "event_send_to with ctx->ctx.sendCb: %x", ctx->ctx.sendCb);
    int ret = mbedtls_ssl_write( &ctx->ctx.ssl, (unsigned char *) ctx->ctx.sendBuffer, ctx->ctx.sendBufferSize );
    if (ctx->ctx.sendCb == NULL) {
        ctx->ctx.sentCount++;
        return;
    }
    np_dtls_send_to_callback cb = ctx->ctx.sendCb;
    ctx->ctx.sendCb = NULL;
    if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        // packet too large
        cb(NABTO_EC_MALFORMED_PACKET, ctx->ctx.sendCbData);
    } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // should not be possible.
        cb(NABTO_EC_FAILED, ctx->ctx.sendCbData);
    } else if (ret < 0) {
        // unknown error
        cb(NABTO_EC_FAILED, ctx->ctx.sendCbData);
    } else {
        ctx->ctx.sentCount++;
        cb(NABTO_EC_OK, ctx->ctx.sendCbData);
    }
}

np_error_code nm_dtls_async_send_to(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t channelId,
                                    uint8_t* buffer, uint16_t bufferSize, np_dtls_send_to_callback cb, void* data)
{
    NABTO_LOG_TRACE(LOG, "async_send_to with ctx->ctx.sendCb: %x", ctx->ctx.sendCb);
    if (ctx->ctx.sendCb != NULL) {
        NABTO_LOG_TRACE(LOG, "Send in progress try again");
        return NABTO_EC_SEND_IN_PROGRESS;
    }
    ctx->ctx.sendCb = cb;
    ctx->ctx.sendCbData = data;
    ctx->ctx.sendBuffer = buffer;
    ctx->ctx.sendBufferSize = bufferSize;
    // If channel id is 0xff send on whatever channel is currently active
    if(channelId != 0xff) {
        ctx->ctx.sendChannel = channelId;
    }
    NABTO_LOG_TRACE(LOG, "enqueing send event");
    np_event_queue_post(ctx->pl, &ctx->ctx.sendEv, &nm_dtls_event_send_to, ctx);
    return NABTO_EC_OK;
}

np_error_code nm_dtls_async_recv_from(struct np_platform* pl, np_dtls_cli_context* ctx, enum application_data_type type,
                                      np_dtls_received_callback cb, void* data)
{
    int i;
    if (ctx->ctx.state == CLOSING) {
        return NABTO_EC_CONNECTION_CLOSING;
    }
    for(i = 0; i < NABTO_DTLS_MAX_RECV_CBS; i++) {
        if (ctx->ctx.recvCbs[i].cb == NULL) {
            ctx->ctx.recvCbs[i].cb = cb;
            ctx->ctx.recvCbs[i].data = data;
            ctx->ctx.recvCbs[i].type = type;
            np_event_queue_post(ctx->pl, &ctx->ctx.recvEv, &nm_dtls_event_do_one, ctx);
            return NABTO_EC_OK;
        }
    }
    return NABTO_EC_OUT_OF_RECV_CALLBACKS;
}

void nm_dtls_do_close(void* data, np_error_code ec){
    int i;
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    np_dtls_close_callback cb = ctx->ctx.closeCb;
    void* cbData = ctx->ctx.closeCbData;
    NABTO_LOG_TRACE(LOG, "Closing DTLS Client Connection");
    nc_keep_alive_stop(ctx->pl, &ctx->ctx.keepAliveCtx);
    mbedtls_ssl_close_notify(&ctx->ctx.ssl);

    for(i = 0; i < NABTO_DTLS_MAX_RECV_CBS; i++) {
        if (ctx->ctx.recvCbs[i].cb != NULL) {
            NABTO_LOG_TRACE(LOG, "found Callback function");
            np_dtls_received_callback cb = ctx->ctx.recvCbs[i].cb;
            ctx->ctx.recvCbs[i].cb = NULL;
            cb(NABTO_EC_CONNECTION_CLOSING, 0, 0, NULL, 0, ctx->ctx.recvCbs[i].data);
        }
    }
   
    mbedtls_ssl_free( &ctx->ctx.ssl );
    mbedtls_ssl_config_free( &ctx->conf );
    mbedtls_ctr_drbg_free( &ctx->ctr_drbg );
    mbedtls_entropy_free( &ctx->entropy );
    nc_udp_dispatch_clear_dtls_cli_context(ctx->udp);
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
    np_event_queue_cancel_event(ctx->pl, &ctx->connEv);
    np_event_queue_cancel_event(ctx->pl, &ctx->ctx.sendEv);
    np_event_queue_cancel_event(ctx->pl, &ctx->ctx.recvEv);
    np_event_queue_cancel_event(ctx->pl, &ctx->ctx.closeEv);
    free(ctx);
    ctx = NULL;
    if (cb == NULL) {
        return;
    }
    cb(NABTO_EC_OK, cbData);
}

void nm_dtls_event_close(void* data) {
    nm_dtls_do_close(data, NABTO_EC_CONNECTION_CLOSING);
}

np_error_code nm_dtls_async_close(struct np_platform* pl, np_dtls_cli_context* ctx,
                                  np_dtls_close_callback cb, void* data)
{
    ctx->ctx.closeCb = cb;
    ctx->ctx.closeCbData = data;
    ctx->ctx.state = CLOSING;
    np_event_queue_post(ctx->pl, &ctx->ctx.closeEv, &nm_dtls_event_close, ctx);
    /* if (!ctx->sending) { */
    /*     np_event_queue_post(ctx->pl, &ctx->closeEv, &nm_dtls_event_close, ctx); */
    /* } */
    return NABTO_EC_OK;
}

np_error_code nm_dtls_cli_handle_packet(struct np_platform* pl, struct np_dtls_cli_context* ctx,
                                   np_communication_buffer* buffer, uint16_t bufferSize)
{
    NABTO_LOG_INFO(LOG, "connection data received callback");
    memcpy(ctx->ctx.recvBuffer, ctx->pl->buf.start(buffer), bufferSize);
    ctx->ctx.recvBufferSize = bufferSize;
    nm_dtls_event_do_one(ctx);
    return NABTO_EC_OK;
}

void nm_dtls_udp_send_callback(const np_error_code ec, void* data)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (data == NULL) {
        return;
    }
    ctx->sending = false;
    ctx->ctx.sslSendBufferSize = 0;
    if(ctx->ctx.state == CLOSING) {
        nm_dtls_event_close(ctx);
//        np_event_queue_post(ctx->pl, &ctx->closeEv, &nm_dtls_event_close, ctx);
        return;
    }
    nm_dtls_event_do_one(data);
}

int nm_dtls_mbedtls_send(void* data, const unsigned char* buffer, size_t bufferSize)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (ctx->ctx.sslSendBufferSize == 0) {
        ctx->sending = true;
        memcpy(ctx->pl->buf.start(ctx->ctx.sslSendBuffer), buffer, bufferSize);
//        NABTO_LOG_TRACE(LOG, "mbedtls wants write:");
//        NABTO_LOG_BUF(LOG, buffer, bufferSize);
        ctx->ctx.sslSendBufferSize = bufferSize;
        nc_udp_dispatch_async_send_to(ctx->udp, &ctx->ep,
                                      ctx->ctx.sslSendBuffer, bufferSize,
                                      &nm_dtls_udp_send_callback, ctx);
        return bufferSize;
    } else {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
}

int nm_dtls_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (ctx->ctx.recvBufferSize == 0) {
        NABTO_LOG_INFO(LOG, "Empty buffer, returning WANT_READ");
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        NABTO_LOG_TRACE(LOG, "mbtls wants read %u bytes into buffersize: %u", ctx->ctx.recvBufferSize, bufferSize);
        size_t maxCp = bufferSize > ctx->ctx.recvBufferSize ? ctx->ctx.recvBufferSize : bufferSize;
        memcpy(buffer, ctx->ctx.recvBuffer, maxCp);
        NABTO_LOG_INFO(LOG, "returning %i bytes to mbedtls:", maxCp);
//        NABTO_LOG_BUF(LOG, buffer, maxCp);
        ctx->ctx.recvBufferSize = 0;
        return maxCp;
    }
}

void nm_dtls_timed_event_do_one(const np_error_code ec, void* data) {
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (ctx->ctx.state == CLOSING) {
        return;
    }
    nm_dtls_event_do_one(data);
}

void nm_dtls_mbedtls_timing_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (finalMilliseconds == 0) {
        // disable current timer
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        ctx->ctx.finalTp = 0;
    } else {
        ctx->pl->ts.set_future_timestamp(&ctx->ctx.intermediateTp, intermediateMilliseconds);
        ctx->pl->ts.set_future_timestamp(&ctx->ctx.finalTp, finalMilliseconds);
        np_event_queue_post_timed_event(ctx->pl, &ctx->ctx.tEv, finalMilliseconds, &nm_dtls_timed_event_do_one, ctx);
    }
}

int nm_dtls_mbedtls_timing_get_delay(void* data)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (ctx->ctx.finalTp) {
        if (ctx->pl->ts.passed_or_now(&ctx->ctx.finalTp)) {
            return 2;
        } else if (ctx->pl->ts.passed_or_now(&ctx->ctx.intermediateTp)) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return -1;
    }
}

np_error_code nm_dtls_setup_dtls_ctx(np_dtls_cli_context* ctx)
{
    int ret;
    const char *pers = "dtls_client";
    mbedtls_ssl_init( &ctx->ctx.ssl );
    mbedtls_ssl_config_init( &ctx->conf );
    mbedtls_ctr_drbg_init( &ctx->ctr_drbg );
    mbedtls_entropy_init( &ctx->entropy );
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
    
    if( ( ret = mbedtls_ctr_drbg_seed( &ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 ) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ctr_drbg_seed returned %d", ret ); 
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        nc_udp_dispatch_clear_dtls_cli_context(ctx->udp);
        free(ctx);
        return NABTO_EC_FAILED;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &ctx->conf,
                   MBEDTLS_SSL_IS_CLIENT,
                   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                   MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_config_defaults returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        nc_udp_dispatch_clear_dtls_cli_context(ctx->udp);
        free(ctx);
        return NABTO_EC_FAILED;
    }
    mbedtls_ssl_conf_alpn_protocols(&ctx->conf, nm_dtls_cli_alpnList );
    mbedtls_ssl_conf_authmode( &ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    ret = mbedtls_ssl_conf_own_cert(&ctx->conf, &publicKey, &privateKey);
    if (ret != 0) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_conf_own_cert returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        nc_udp_dispatch_clear_dtls_cli_context(ctx->udp);
        free(ctx);
        return NABTO_EC_FAILED;
    }
    
    mbedtls_ssl_conf_rng( &ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg );
    mbedtls_ssl_conf_dbg( &ctx->conf, my_debug, stdout );
    if( ( ret = mbedtls_ssl_setup( &ctx->ctx.ssl, &ctx->conf ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_setup returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        nc_udp_dispatch_clear_dtls_cli_context(ctx->udp);
        free(ctx);
        return NABTO_EC_FAILED;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ctx->ctx.ssl, SERVER_NAME ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_set_hostname returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        nc_udp_dispatch_clear_dtls_cli_context(ctx->udp);
        free(ctx);
        return NABTO_EC_FAILED;
    }

    mbedtls_ssl_set_bio( &ctx->ctx.ssl, ctx,
                         nm_dtls_mbedtls_send, nm_dtls_mbedtls_recv, NULL );
    mbedtls_ssl_set_timer_cb( &ctx->ctx.ssl, ctx, nm_dtls_mbedtls_timing_set_delay,
                                            nm_dtls_mbedtls_timing_get_delay );
    return NABTO_EC_OK;
}
