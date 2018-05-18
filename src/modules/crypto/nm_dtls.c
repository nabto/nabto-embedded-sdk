#include "nm_dtls.h"
#include <platform/np_logging.h>

//#include <mbedtls/config.h>
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

#define mbedtls_printf(...) NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, __VA_ARGS__)

enum sslState {
    CONNECTING,
    VERIFY,
    DATA,
    CLOSING
};

struct np_crypto_context {
    struct np_connection* conn;
    struct np_platform* pl;
    struct np_event ev;
    struct np_timed_event tEv;
    np_crypto_connect_callback connectCb;
    void* connectData;
    np_crypto_send_to_callback sendCb;
    void* sendData;
    np_crypto_received_callback recvCb;
    void* recvData;
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
    uint8_t sslSendBuffer[4096];
    size_t sslSendBufferSize;
    enum sslState state;
    np_timestamp intermediateTp;
    np_timestamp finalTp;
};

int nm_dtls_mbedtls_send(void* ctx, const unsigned char* buffer, size_t bufferSize);
int nm_dtls_mbedtls_recv(void* ctx, unsigned char* buffer, size_t bufferSize);
void nm_dtls_mbedtls_timing_set_delay(void* ctx, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds);
int nm_dtls_mbedtls_timing_get_delay(void* ctx);
void nm_dtls_event_connect(void* data);
void nm_dtls_connection_received_callback(const np_error_code ec, struct np_connection* conn,
                                          np_communication_buffer* buffer, uint16_t bufferSize, void* data);
np_error_code nm_dtls_setup_dtls_ctx(np_crypto_context* ctx);

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO,"%s:%d %s", file, line,  str );
}

void nm_dtls_init(struct np_platform* pl)
{
    pl->cryp.async_connect = &nm_dtls_async_connect;
    pl->cryp.async_send_to = &nm_dtls_async_send_to;
    pl->cryp.async_recv_from = &nm_dtls_async_recv_from;
    pl->cryp.async_close = &nm_dtls_async_close;
}

np_error_code nm_dtls_async_connect(struct np_platform* pl, struct np_connection* conn,
                                    np_crypto_connect_callback cb, void* data)
{
    np_crypto_context* ctx = (np_crypto_context*)malloc(sizeof(np_crypto_context));
    np_error_code ec;
    ctx->conn = conn;
    ctx->recvBufferSize = 0;
    ctx->pl = pl;
    ctx->state = CONNECTING;
    ctx->pl->conn.async_recv_from(ctx->pl, ctx->conn, &nm_dtls_connection_received_callback, ctx);
    ctx->connectCb = cb;
    ctx->connectData = data;
    ctx->sslSendBufferSize = 0;
    ec = nm_dtls_setup_dtls_ctx(ctx);
    if(ec == NABTO_EC_OK) {
        np_event_queue_post(pl, &ctx->ev, &nm_dtls_event_connect, ctx);
    }
    return ec;
}

void nm_dtls_event_connect(void* data)
{
    np_crypto_context* ctx = (np_crypto_context*)data;
    int ret;
    uint32_t flags;
    if(ctx->state == CONNECTING) {
        ret = mbedtls_ssl_handshake( &ctx->ssl );
        if( ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
            //Keep State CONNECTING
            NABTO_LOG_TRACE(NABTO_LOG_MODULE_CRYPTO, "Keeping CONNECTING state");
        } else {
            if( ret != 0 )
            {
                mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%04x\n\n", -ret );
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
    }
}

void nm_dtls_event_send_to(void* data)
{
    NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "!!!!!writing to ssl!!!!!");
    np_crypto_context* ctx = (np_crypto_context*) data;
    int ret = mbedtls_ssl_write( &ctx->ssl, (unsigned char *) ctx->sendBuffer, ctx->sendBufferSize );
    if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        // TODO packet too large
        ctx->sendCb(NABTO_EC_FAILED, ctx->sendData);
    } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // TODO should not be possible.
        ctx->sendCb(NABTO_EC_FAILED, ctx->sendData);
    } else if (ret < 0) {
        // TODO unknown error
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
    NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "posting send func %i", np_event_queue_has_ready_event(ctx->pl));
    np_event_queue_post(ctx->pl, &ctx->ev, &nm_dtls_event_send_to, ctx);
    NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "after posting send func %i", np_event_queue_has_ready_event(ctx->pl));
    return NABTO_EC_OK;
}

void nm_dtls_event_recv_from(void*data)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    np_communication_buffer* buf = ctx->pl->buf.allocate();
    NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "reading from ssl");
    int ret = mbedtls_ssl_read( &ctx->ssl, ctx->pl->buf.start(buf), ctx->pl->buf.size(buf) );
    if (ret == 0) {
        // EOF
        ctx->state = CLOSING;
    } else if (ret > 0) {
        ctx->recvCb(NABTO_EC_OK, buf, ret, ctx->recvData);
    }else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
              ret == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        // OK
    } else {
        // TODO ERROR
    }
    
}    

np_error_code nm_dtls_async_recv_from(struct np_platform* pl, np_crypto_context* ctx,
                                      np_crypto_received_callback cb, void* data)
{
    ctx->recvCb = cb;
    ctx->recvData = data;
    np_event_queue_post(ctx->pl, &ctx->ev, &nm_dtls_event_recv_from, ctx);
    return NABTO_EC_OK;
}

np_error_code nm_dtls_async_close(struct np_platform* pl, np_crypto_context* ctx,
                                  np_crypto_close_callback cb, void* data)
{

    return NABTO_EC_OK;
}

void nm_dtls_connection_received_callback(const np_error_code ec, struct np_connection* conn,
                                          np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    if ( data == NULL) {
        return;
    }
    NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "connection received callback");
    if (ec == NABTO_EC_OK) {
        np_crypto_context* ctx = (np_crypto_context*) data;
        memcpy(ctx->recvBuffer, ctx->pl->buf.start(buffer), bufferSize);
        ctx->recvBufferSize = bufferSize;
        if (ctx->state == CONNECTING || ctx->state == VERIFY) {
            ctx->pl->conn.async_recv_from(ctx->pl, ctx->conn, &nm_dtls_connection_received_callback, ctx);
            np_event_queue_post(ctx->pl, &ctx->ev, &nm_dtls_event_connect, ctx);
        } else if (ctx->state == DATA) {
            ctx->pl->conn.async_recv_from(ctx->pl, ctx->conn, &nm_dtls_connection_received_callback, ctx);
            np_event_queue_post(ctx->pl, &ctx->ev, &nm_dtls_event_recv_from, ctx);
        }
    } else {

    }
}

void nm_dtls_connection_send_callback(const np_error_code ec, void* data)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    ctx->sslSendBufferSize = 0;
}

int nm_dtls_mbedtls_send(void* data, const unsigned char* buffer, size_t bufferSize)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    if (ctx->sslSendBufferSize == 0) {
        memcpy(ctx->sslSendBuffer, buffer, bufferSize);
        ctx->sslSendBufferSize = bufferSize;
        ctx->pl->conn.async_send_to(ctx->pl, ctx->conn, ctx->sslSendBuffer, bufferSize, &nm_dtls_connection_send_callback, ctx);
        return bufferSize;
    } else {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
}

int nm_dtls_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    if (ctx->recvBufferSize == 0) {
        NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "bufferSize = 0");
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

void nm_dtls_timed_event_connect(const np_error_code ec, void* data) {
    NABTO_LOG_INFO(NABTO_LOG_MODULE_CRYPTO, "received timed event");
    nm_dtls_event_connect(data);
}

void nm_dtls_mbedtls_timing_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds)
{
    np_crypto_context* ctx = (np_crypto_context*) data;
    if (finalMilliseconds == 0) {
        // disable current timer
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->tEv);
    } else {
        ctx->pl->ts.set_future_timestamp(&ctx->intermediateTp, intermediateMilliseconds);
        ctx->pl->ts.set_future_timestamp(&ctx->finalTp, finalMilliseconds);
        np_event_queue_post_timed_event(ctx->pl, &ctx->tEv, finalMilliseconds, &nm_dtls_timed_event_connect, ctx);
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
    mbedtls_debug_set_threshold( 1 );
    
    if( ( ret = mbedtls_ctr_drbg_seed( &ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 ) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret ); 
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
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->tEv);
        ctx->pl->conn.cancel_async_recv(ctx->pl, ctx->conn);
        free(ctx);
        return NABTO_EC_FAILED;
    }

/*    ret = mbedtls_x509_crt_parse( &ctx->cacert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret < 0 ) {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->tEv);
        ctx->pl->conn.cancel_async_recv(ctx->pl, ctx->conn);
        free(ctx);
        return NABTO_EC_FAILED;
    }
*/

    
    mbedtls_ssl_conf_authmode( &ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
//    mbedtls_ssl_conf_ca_chain( &ctx->conf, &ctx->cacert, NULL );
    
    mbedtls_ssl_conf_rng( &ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg );
    mbedtls_ssl_conf_dbg( &ctx->conf, my_debug, stdout );
    if( ( ret = mbedtls_ssl_setup( &ctx->ssl, &ctx->conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->tEv);
        ctx->pl->conn.cancel_async_recv(ctx->pl, ctx->conn);
        free(ctx);
        return NABTO_EC_FAILED;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ctx->ssl, SERVER_NAME ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
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
