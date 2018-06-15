#include "nm_dtls.h"
#include <platform/np_logging.h>

#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
#include <mbedtls/timing.h>

#include <string.h>
#include <stdlib.h>

#define SERVER_NAME "localhost"

enum sslState {
    CONNECTING,
    DATA,
    CLOSING
};

struct np_crypto_context {
    struct np_connection* conn;
    struct np_platform* pl;
    struct np_event connEv;
    struct np_event sendEv;
    struct np_event recvEv;
    struct np_event closeEv;
    struct np_timed_event tEv;
    np_crypto_connect_callback connectCb;
    void* connectData;
    np_crypto_send_to_callback sendCb;
    void* sendData;
    
    np_crypto_received_callback recvAttachCb;
    void* recvAttachData;
    np_crypto_received_callback recvAttachDispatchCb;
    void* recvAttachDispatchData;
    np_crypto_received_callback recvRelayCb;
    void* recvRelayData;
    np_crypto_received_callback recvKeepAliveCb;
    void* recvKeepAliveData;
    
    np_crypto_close_callback closeCb;
    void* closeData;
    uint8_t* sendBuffer;
    uint16_t sendBufferSize;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_timing_delay_context timer;
    mbedtls_pk_context pkey;
    uint8_t recvBuffer[4096];
    size_t recvBufferSize;
    np_communication_buffer* sslRecvBuf;
    size_t sslRecvBufSize;
    np_communication_buffer* sslSendBuffer;
    size_t sslSendBufferSize;
    enum sslState state;
    np_timestamp intermediateTp;
    np_timestamp finalTp;
    uint8_t currentChannelId;
};

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
// callback function called by the connection module when data is ready from the network
void nm_dtls_connection_received_callback(const np_error_code ec, struct np_connection* conn,
                                          uint8_t channelId,  np_communication_buffer* buffer,
                                          uint16_t bufferSize, void* data);
// setup function for the mbedtls context
np_error_code nm_dtls_setup_dtls_ctx(np_crypto_context* ctx);

// cancel recv_from callbacks
np_error_code nm_dtls_cancel_recv_from(struct np_platform* pl, np_crypto_context* ctx,
                                       enum application_data_type type)
{
    switch (type) {
        case ATTACH_DISPATCH:
            ctx->recvAttachDispatchCb = NULL;
            break;
        case ATTACH:
            ctx->recvAttachCb = NULL;
            break;
        case RELAY:
            ctx->recvRelayCb = NULL;
            break;
        case KEEP_ALIVE:
            ctx->recvKeepAliveCb = NULL;
            break;
        default:
            return NABTO_EC_INVALID_PACKET_TYPE;
    }
    return NABTO_EC_OK;
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
    
    NABTO_LOG_RAW(severity, NABTO_LOG_MODULE_CRYPTO, line, file, str );
}

/*
 * Initialize the np_platform to use this particular crypto module
 */
void nm_dtls_init(struct np_platform* pl)
{
    pl->cryp.async_connect = &nm_dtls_async_connect;
    pl->cryp.async_send_to = &nm_dtls_async_send_to;
    pl->cryp.async_recv_from = &nm_dtls_async_recv_from;
    pl->cryp.async_close = &nm_dtls_async_close;
}

/*
 * asyncroniously start a dtls connection
 */
np_error_code nm_dtls_async_connect(struct np_platform* pl, struct np_connection* conn,
                                    np_crypto_connect_callback cb, void* data)
{
    np_crypto_context* ctx = (np_crypto_context*)malloc(sizeof(np_crypto_context));
    np_error_code ec;
    memset(ctx, 0, sizeof(np_crypto_context));
    ctx->conn = conn;
    ctx->pl = pl;
    ctx->state = CONNECTING;
    ctx->pl->conn.async_recv_from(ctx->pl, ctx->conn, &nm_dtls_connection_received_callback, ctx);
    ctx->connectCb = cb;
    ctx->connectData = data;
    ctx->sslRecvBuf = pl->buf.allocate();
    ctx->sslSendBuffer = pl->buf.allocate();
    ec = nm_dtls_setup_dtls_ctx(ctx);
    if(ec == NABTO_EC_OK) {
        np_event_queue_post(pl, &ctx->connEv, &nm_dtls_event_do_one, ctx);
    }
    return ec;
}

/*
 * Handle events for the connection phase
 */
void nm_dtls_event_do_one(void* data)
{
    np_crypto_context* ctx = (np_crypto_context*)data;
    int ret;
    if(ctx->state == CONNECTING) {
        ret = mbedtls_ssl_handshake( &ctx->ssl );
        if( ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
            //Keep State CONNECTING
            NABTO_LOG_TRACE(NABTO_LOG_MODULE_CRYPTO, "Keeping CONNECTING state");
        } else {
            if( ret != 0 )
            {
                NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO,  " failed  ! mbedtls_ssl_handshake returned -0x%04x", -ret );
                ctx->connectCb(NABTO_EC_FAILED, NULL, ctx->connectData);
                np_event_queue_cancel_timed_event(ctx->pl, &ctx->tEv);
                ctx->pl->conn.cancel_async_recv(ctx->pl, ctx->conn);
                free(ctx);
                return;
            }
            NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "State changed to DATA");
            ctx->state = DATA;
            ctx->connectCb(NABTO_EC_OK, ctx, ctx->connectData);
        }
        return;
    } else if(ctx->state == DATA) {
        ret = mbedtls_ssl_read( &ctx->ssl, ctx->pl->buf.start(ctx->sslRecvBuf), ctx->pl->buf.size(ctx->sslRecvBuf) );
        if (ret == 0) {
            // EOF
            ctx->state = CLOSING;
            NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "Received EOF, state = CLOSING");
        } else if (ret > 0) {
            NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "Received data, invoking callback");
            uint64_t seq = *((uint64_t*)ctx->ssl.in_ctr);
            switch((enum application_data_type)ctx->pl->buf.start(ctx->sslRecvBuf)[0]) {
                case ATTACH_DISPATCH:
                    NABTO_LOG_TRACE(NABTO_LOG_MODULE_CRYPTO, "Attach Dispatch packet");
                    if(ctx->recvAttachDispatchCb) {
                        NABTO_LOG_TRACE(NABTO_LOG_MODULE_CRYPTO, "found Callback function");
                        ctx->recvAttachDispatchCb(NABTO_EC_OK, ctx->currentChannelId, seq, ctx->sslRecvBuf, ret, ctx->recvAttachDispatchData);
                        ctx->recvAttachDispatchCb = NULL;
                    }
                    break;
                case ATTACH:
                    NABTO_LOG_TRACE(NABTO_LOG_MODULE_CRYPTO, "Attach packet");
                    if(ctx->recvAttachCb) {
                        NABTO_LOG_TRACE(NABTO_LOG_MODULE_CRYPTO, "found Callback function");
                        ctx->recvAttachCb(NABTO_EC_OK, ctx->currentChannelId, seq, ctx->sslRecvBuf, ret, ctx->recvAttachData);
                        ctx->recvAttachCb = NULL;
                    }
                    break;
                case RELAY:
                    NABTO_LOG_TRACE(NABTO_LOG_MODULE_CRYPTO, "Relay packet");
                    if (ctx->recvRelayCb) {
                        NABTO_LOG_TRACE(NABTO_LOG_MODULE_CRYPTO, "found Callback function");
                        ctx->recvRelayCb(NABTO_EC_OK, ctx->currentChannelId, seq, ctx->sslRecvBuf, ret, ctx->recvRelayData);
                        ctx->recvRelayCb = NULL;
                    }
                    break;
                case KEEP_ALIVE:
                    NABTO_LOG_TRACE(NABTO_LOG_MODULE_CRYPTO, "keep alive packet");
                    if (ctx->recvKeepAliveCb) {
                        NABTO_LOG_TRACE(NABTO_LOG_MODULE_CRYPTO, "found Callback function");
                        ctx->recvKeepAliveCb(NABTO_EC_OK, ctx->currentChannelId, seq, ctx->sslRecvBuf, ret, ctx->recvKeepAliveData);
                        ctx->recvKeepAliveCb = NULL;
                    }
                    break;
                default:
                    NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "Received packet with unknown application data type");
                    NABTO_LOG_BUF(NABTO_LOG_MODULE_CRYPTO, ctx->pl->buf.start(ctx->sslRecvBuf), ret);
                    break;
            }
        }else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                  ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // OK
        } else {
            NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "Received ERROR: %i", ret);
            // TODO: ERROR handlig
        }
        return;
    }
        
}

void nm_dtls_event_send_to(void* data)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    int ret = mbedtls_ssl_write( &ctx->ssl, (unsigned char *) ctx->sendBuffer, ctx->sendBufferSize );
    if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        // TODO: packet too large
        ctx->sendCb(NABTO_EC_MALFORMED_PACKET, ctx->sendData);
    } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // TODO: should not be possible.
        ctx->sendCb(NABTO_EC_FAILED, ctx->sendData);
    } else if (ret < 0) {
        // TODO: unknown error
        ctx->sendCb(NABTO_EC_FAILED, ctx->sendData);
    } else {
        ctx->sendCb(NABTO_EC_OK, ctx->sendData);
    }
}

np_error_code nm_dtls_async_send_to(struct np_platform* pl, np_crypto_context* ctx, uint8_t* buffer,
                                    uint16_t bufferSize, np_crypto_send_to_callback cb, void* data)
{
    ctx->sendCb = cb;
    ctx->sendData = data;
    ctx->sendBuffer = buffer;
    ctx->sendBufferSize = bufferSize;
    np_event_queue_post(ctx->pl, &ctx->sendEv, &nm_dtls_event_send_to, ctx);
    return NABTO_EC_OK;
}

np_error_code nm_dtls_async_recv_from(struct np_platform* pl, np_crypto_context* ctx, enum application_data_type type,
                                      np_crypto_received_callback cb, void* data)
{
    switch(type) {
        case ATTACH:
            ctx->recvAttachCb = cb;
            ctx->recvAttachData = data;
            break;
        case ATTACH_DISPATCH:
            ctx->recvAttachDispatchCb = cb;
            ctx->recvAttachDispatchData = data;
            break;
        case RELAY:
            ctx->recvRelayCb = cb;
            ctx->recvRelayData = data;
            break;
        case KEEP_ALIVE:
            ctx->recvKeepAliveCb = cb;
            ctx->recvKeepAliveData = data;
            break;
        default:
            NABTO_LOG_ERROR(NABTO_LOG_MODULE_CRYPTO, "Tried to register recv callback for unknown application data type");
            return NABTO_EC_FAILED;
    }
    np_event_queue_post(ctx->pl, &ctx->recvEv, &nm_dtls_event_do_one, ctx);
    return NABTO_EC_OK;
}

void nm_dtls_event_close(void* data){
    np_crypto_context* ctx = (np_crypto_context*) data;
    mbedtls_ssl_close_notify(&ctx->ssl);
    mbedtls_x509_crt_free( &ctx->cacert );
    mbedtls_ssl_free( &ctx->ssl );
    mbedtls_ssl_config_free( &ctx->conf );
    mbedtls_ctr_drbg_free( &ctx->ctr_drbg );
    mbedtls_entropy_free( &ctx->entropy );
    np_crypto_close_callback cb = ctx->closeCb;
    void* cbData = ctx->closeData;
    free(ctx);
    ctx = NULL;
    cb(NABTO_EC_OK, cbData);
}

np_error_code nm_dtls_async_close(struct np_platform* pl, np_crypto_context* ctx,
                                  np_crypto_close_callback cb, void* data)
{
    ctx->closeCb = cb;
    ctx->closeData = data;
    ctx->state = CLOSING;
    np_event_queue_post(ctx->pl, &ctx->closeEv, &nm_dtls_event_close, ctx);
    return NABTO_EC_OK;
}

void nm_dtls_connection_received_callback(const np_error_code ec, struct np_connection* conn,
                                          uint8_t channelId, np_communication_buffer* buffer,
                                          uint16_t bufferSize, void* data)
{
    if ( data == NULL) {
        return;
    }
    NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "connection data received callback");
    if (ec == NABTO_EC_OK) {
        np_crypto_context* ctx = (np_crypto_context*) data;
        ctx->currentChannelId = channelId;
        memcpy(ctx->recvBuffer, ctx->pl->buf.start(buffer), bufferSize);
        ctx->recvBufferSize = bufferSize;
        ctx->pl->conn.async_recv_from(ctx->pl, ctx->conn, &nm_dtls_connection_received_callback, ctx);
        np_event_queue_post(ctx->pl, &ctx->connEv, &nm_dtls_event_do_one, ctx);
    } else {
        // TODO: how to handle connection errors?
    }
}

void nm_dtls_connection_send_callback(const np_error_code ec, void* data)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    if (data == NULL) {
        return;
    }
    ctx->sslSendBufferSize = 0;
    if(ctx->state == CLOSING) {
        return;
    }
    nm_dtls_event_do_one(data);
}

int nm_dtls_mbedtls_send(void* data, const unsigned char* buffer, size_t bufferSize)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    if (ctx->sslSendBufferSize == 0) {
        memcpy(ctx->pl->buf.start(ctx->sslSendBuffer), buffer, bufferSize);
        ctx->sslSendBufferSize = bufferSize;
        ctx->pl->conn.async_send_to(ctx->pl, ctx->conn, ctx->currentChannelId, ctx->sslSendBuffer, bufferSize, &nm_dtls_connection_send_callback, ctx);
        return bufferSize;
    } else {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
}

int nm_dtls_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    if (ctx->recvBufferSize == 0) {
        NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "Empty buffer, returning WANT_READ");
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "returning data");
        size_t maxCp = bufferSize > ctx->recvBufferSize ? ctx->recvBufferSize : bufferSize;
        memcpy(buffer, ctx->recvBuffer, maxCp);
        NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "%i bytes", maxCp);
        ctx->recvBufferSize = 0;
        return maxCp;
    }
}

void nm_dtls_timed_event_do_one(const np_error_code ec, void* data) {
    nm_dtls_event_do_one(data);
}

void nm_dtls_mbedtls_timing_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    if (finalMilliseconds == 0) {
        // disable current timer
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->tEv);
        ctx->finalTp = 0;
    } else {
        ctx->pl->ts.set_future_timestamp(&ctx->intermediateTp, intermediateMilliseconds);
        ctx->pl->ts.set_future_timestamp(&ctx->finalTp, finalMilliseconds);
        np_event_queue_post_timed_event(ctx->pl, &ctx->tEv, finalMilliseconds, &nm_dtls_timed_event_do_one, ctx);
    }
}

int nm_dtls_mbedtls_timing_get_delay(void* data)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    if (ctx->finalTp) {
        if (ctx->pl->ts.passed_or_now(&ctx->finalTp)) {
            return 2;
        } else if (ctx->pl->ts.passed_or_now(&ctx->intermediateTp)) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return -1;
    }
}

np_error_code nm_dtls_setup_dtls_ctx(np_crypto_context* ctx)
{
    int ret;
    const char *pers = "dtls_client";
    mbedtls_ssl_init( &ctx->ssl );
    mbedtls_ssl_config_init( &ctx->conf );
    mbedtls_x509_crt_init( &ctx->cacert );
    mbedtls_ctr_drbg_init( &ctx->ctr_drbg );
    mbedtls_entropy_init( &ctx->entropy );
    mbedtls_debug_set_threshold( 0 );
    
    if( ( ret = mbedtls_ctr_drbg_seed( &ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 ) {
        NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO,  " failed  ! mbedtls_ctr_drbg_seed returned %d", ret ); 
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->tEv);
        ctx->pl->conn.cancel_async_recv(ctx->pl, ctx->conn);
        free(ctx);
        return NABTO_EC_FAILED;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &ctx->conf,
                   MBEDTLS_SSL_IS_CLIENT,
                   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                   MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO,  " failed  ! mbedtls_ssl_config_defaults returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->tEv);
        ctx->pl->conn.cancel_async_recv(ctx->pl, ctx->conn);
        free(ctx);
        return NABTO_EC_FAILED;
    }

    mbedtls_ssl_conf_authmode( &ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
//    mbedtls_ssl_conf_ca_chain( &ctx->conf, &ctx->cacert, NULL );
    
    mbedtls_ssl_conf_rng( &ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg );
    mbedtls_ssl_conf_dbg( &ctx->conf, my_debug, stdout );
    if( ( ret = mbedtls_ssl_setup( &ctx->ssl, &ctx->conf ) ) != 0 )
    {
        NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO,  " failed  ! mbedtls_ssl_setup returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->tEv);
        ctx->pl->conn.cancel_async_recv(ctx->pl, ctx->conn);
        free(ctx);
        return NABTO_EC_FAILED;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ctx->ssl, SERVER_NAME ) ) != 0 )
    {
        NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO,  " failed  ! mbedtls_ssl_set_hostname returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->tEv);
        ctx->pl->conn.cancel_async_recv(ctx->pl, ctx->conn);
        free(ctx);
        return NABTO_EC_FAILED;
    }

    mbedtls_ssl_set_bio( &ctx->ssl, ctx,
                         nm_dtls_mbedtls_send, nm_dtls_mbedtls_recv, NULL );
    mbedtls_ssl_set_timer_cb( &ctx->ssl, ctx, nm_dtls_mbedtls_timing_set_delay,
                                            nm_dtls_mbedtls_timing_get_delay );
    return NABTO_EC_OK;
}
