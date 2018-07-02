#include "nm_dtls_srv.h"

#include <platform/np_logging.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
//#include <mbedtls/ssl_cookie.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/timing.h>

#include <string.h>
#include <stdlib.h>
#define NABTO_SSL_RECV_BUFFER_SIZE 4096

#define LOG NABTO_LOG_MODULE_DTLS_SRV
#define DEBUG_LEVEL 4

const char test_priv_key[] =
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIPwHCOmh7kIAFfGHK7C5QqJvY/MvXVJv2IGHayFZBDfMoAoGCCqGSM49\r\n"
"AwEHoUQDQgAE3STG13/95B6UFDiwjoVzKCj3rAIaEZIy9nelN8yyZEc654vepzk3\r\n"
"jL1pjCx4mgM/5xCqxFI0ctHZehFkmZrInQ==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

const char test_pub_key_crt[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIB7TCCAZSgAwIBAgIJAK9g+0WW5dPhMAoGCCqGSM49BAMCMFIxCzAJBgNVBAYT\r\n"
"AkRLMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\r\n"
"aXRzIFB0eSBMdGQxCzAJBgNVBAMMAk1NMB4XDTE4MDUwNDA4MzQwMVoXDTIwMDUw\r\n"
"MzA4MzQwMVowUjELMAkGA1UEBhMCREsxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf\r\n"
"BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDELMAkGA1UEAwwCTU0wWTAT\r\n"
"BgcqhkjOPQIBBggqhkjOPQMBBwNCAATdJMbXf/3kHpQUOLCOhXMoKPesAhoRkjL2\r\n"
"d6U3zLJkRzrni96nOTeMvWmMLHiaAz/nEKrEUjRy0dl6EWSZmsido1MwUTAdBgNV\r\n"
"HQ4EFgQUCx61qb7QZCunFl16Lr9Yszx07OgwHwYDVR0jBBgwFoAUCx61qb7QZCun\r\n"
"Fl16Lr9Yszx07OgwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiB9\r\n"
"oh2pYe+WgV6I+bV8LIiexQlgXZjh/ZEjds1TCuHAGQIgAsQ6zTkvEMy/1d6cU4FB\r\n"
"HB2dRWSdQGN3E4gle5w5/dg=\r\n"
"-----END CERTIFICATE-----\r\n";


enum sslState {
    CONNECTING,
    DATA,
    CLOSING
};

struct np_dtls_srv_connection {
    struct np_connection* conn;
    enum sslState state;
    mbedtls_ssl_context ssl;

    np_communication_buffer* sslRecvBuf;
    size_t sslRecvBufSize;
    np_communication_buffer* sslSendBuffer;
    size_t sslSendBufferSize;
    uint8_t recvBuffer[NABTO_SSL_RECV_BUFFER_SIZE];
    size_t recvBufferSize;
    uint8_t* sendBuffer;
    size_t sendBufferSize;

    uint8_t sendChannel;
    uint8_t currentChannelId;
    np_dtls_srv_received_callback recvCb;
    void* recvCbData;
    np_dtls_srv_send_to_callback sendCb;
    void* sendCbData;
    np_dtls_srv_close_callback closeCb;
    void* closeCbData;
    
    struct np_event sendEv;
    struct np_event recvEv;
    struct np_event closeEv;
    struct np_timed_event tEv;
    np_timestamp intermediateTp;
    np_timestamp finalTp;
};

struct nm_dtls_srv_context {
    struct np_platform* pl;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
//    mbedtls_ssl_cookie_ctx cookie_ctx;
    mbedtls_x509_crt publicKey;
    mbedtls_pk_context privateKey;
//    mbedtls_x509_crt cacert;
//    mbedtls_timing_delay_context timer;
//    mbedtls_pk_context pkey;
};

struct nm_dtls_srv_context server;
np_error_code nm_dtls_srv_init_config();
static void nm_dtls_srv_tls_logger( void *ctx, int level, const char *file, int line, const char *str );
void nm_dtls_srv_connection_send_callback(const np_error_code ec, void* data);
void nm_dtls_srv_do_one(void* data);

// Function called by mbedtls when data should be sent to the network
int nm_dtls_srv_mbedtls_send(void* ctx, const unsigned char* buffer, size_t bufferSize);
// Function called by mbedtls when it wants data from the network
int nm_dtls_srv_mbedtls_recv(void* ctx, unsigned char* buffer, size_t bufferSize);
// Function called by mbedtls which creates timeout events
void nm_dtls_srv_mbedtls_timing_set_delay(void* ctx, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds);
// Function called by mbedtls to determine when the next timeout event occurs
int nm_dtls_srv_mbedtls_timing_get_delay(void* ctx);
// callback function called by the connection module when data is ready from the network
void nm_dtls_srv_connection_received_callback(const np_error_code ec, struct np_connection* conn,
                                              uint8_t channelId,  np_communication_buffer* buffer,
                                              uint16_t bufferSize, void* data);


np_error_code nm_dtls_srv_init(struct np_platform* pl)
{
    pl->dtlsS.create = &nm_dtls_srv_create;
    pl->dtlsS.async_send_to = &nm_dtls_srv_async_send_to;
    pl->dtlsS.async_recv_from = &nm_dtls_srv_async_recv_from;
    pl->dtlsS.cancel_recv_from = &nm_dtls_srv_cancel_recv_from;
    pl->dtlsS.async_close = &nm_dtls_srv_async_close;
    server.pl = pl;
    return nm_dtls_srv_init_config();
}

np_error_code nm_dtls_srv_create(struct np_platform* pl, np_connection* conn, np_dtls_srv_connection** dtls)
{
    int ret;
    *dtls = (np_dtls_srv_connection*)malloc(sizeof(np_dtls_srv_connection));
    if(!dtls) {
        return NABTO_EC_FAILED;
    }
    memset(*dtls, 0, sizeof(np_dtls_srv_connection));
    (*dtls)->conn = conn;
    (*dtls)->sslRecvBuf = server.pl->buf.allocate();
    (*dtls)->sslSendBuffer = server.pl->buf.allocate();

    NABTO_LOG_TRACE(LOG, "DTLS was allocated at: %u");

    //mbedtls connection initialization
    mbedtls_ssl_init( &((*dtls)->ssl) );
    if( ( ret = mbedtls_ssl_setup( &((*dtls)->ssl), &server.conf ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_setup returned %d", ret );
        return NABTO_EC_FAILED;
    }

    mbedtls_ssl_set_timer_cb( &((*dtls)->ssl), (*dtls), &nm_dtls_srv_mbedtls_timing_set_delay,
                              &nm_dtls_srv_mbedtls_timing_get_delay );

    mbedtls_ssl_session_reset( &((*dtls)->ssl) );
    
//    ret = mbedtls_ssl_set_client_transport_id(&((*dtls)->ssl), (const unsigned char*)conn, sizeof(np_connection));
//    if (ret != 0) {
//        NABTO_LOG_ERROR(LOG, "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret);
//        return NABTO_EC_FAILED;
//    }
    
    ret = mbedtls_ssl_set_hs_own_cert(&((*dtls)->ssl), &server.publicKey, &server.privateKey);
    if (ret != 0) {
        NABTO_LOG_ERROR(LOG, "failed ! mbedtls_ssl_set_hs_own_cert returned %d", ret);
        return NABTO_EC_FAILED;
    }

    mbedtls_ssl_set_bio( &((*dtls)->ssl), (*dtls),
                         &nm_dtls_srv_mbedtls_send, &nm_dtls_srv_mbedtls_recv, NULL );
    server.pl->conn.async_recv_from(server.pl, (*dtls)->conn, &nm_dtls_srv_connection_received_callback, (*dtls));

    return NABTO_EC_OK;
}

void nm_dtls_srv_do_one(void* data)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*)data;
    if (ctx->state == CONNECTING) {
        int ret;
        ret = mbedtls_ssl_handshake( &ctx->ssl );
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // keep state as CONNECTING
            NABTO_LOG_TRACE(LOG, "Keeping CONNECTING state");
        } else if (ret == 0) {
            NABTO_LOG_INFO(LOG, "State changed to DATA");
            ctx->state = DATA;
        } else {
            NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_handshake returned -0x%04x", -ret );
            // TODO: How to handle connection errors ?
//ctx->connectCb(NABTO_EC_FAILED, NULL, ctx->connectData);
            np_event_queue_cancel_timed_event(server.pl, &ctx->tEv);
            server.pl->conn.cancel_async_recv(server.pl, ctx->conn);
            free(ctx);
            return;
        }
    } else if (ctx->state == DATA) {
        int ret;
        ret = mbedtls_ssl_read(&ctx->ssl, server.pl->buf.start(ctx->sslRecvBuf), server.pl->buf.size(ctx->sslRecvBuf) );
        if (ret == 0) {
            // EOF
            ctx->state = CLOSING;
            NABTO_LOG_INFO(LOG, "Received EOF, state = CLOSING");
        } else if (ret > 0) {
            uint64_t seq = *((uint64_t*)ctx->ssl.in_ctr);
            if(ctx->recvCb) {
                NABTO_LOG_TRACE(LOG, "found Callback function");
                np_dtls_srv_received_callback cb = ctx->recvCb;
                ctx->recvCb = NULL;
                cb(NABTO_EC_OK, ctx->currentChannelId, seq, ctx->sslRecvBuf, ret, ctx->recvCbData);
            }
          
        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                   ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // OK
        } else {
            // TODO: error handling
            NABTO_LOG_ERROR(LOG, "Received ERROR: %i", ret);
            ctx->state = CLOSING;
        }
    }

}

void nm_dtls_srv_event_send_to(void* data)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    int ret = mbedtls_ssl_write( &ctx->ssl, (unsigned char *) ctx->sendBuffer, ctx->sendBufferSize );
    if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        // TODO: packet too large
        ctx->sendCb(NABTO_EC_MALFORMED_PACKET, ctx->sendCbData);
    } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // TODO: should not be possible.
        ctx->sendCb(NABTO_EC_FAILED, ctx->sendCbData);
    } else if (ret < 0) {
        // TODO: unknown error
        ctx->sendCb(NABTO_EC_FAILED, ctx->sendCbData);
    } else {
        ctx->sendCb(NABTO_EC_OK, ctx->sendCbData);
    }
}

np_error_code nm_dtls_srv_async_send_to(struct np_platform* pl, np_dtls_srv_connection* ctx, uint8_t channelId,
                                        uint8_t* buffer, uint16_t bufferSize,
                                        np_dtls_srv_send_to_callback cb, void* data)
{
    ctx->sendCb = cb;
    ctx->sendCbData = data;
    ctx->sendBuffer = buffer;
    ctx->sendBufferSize = bufferSize;
    // If channel id is 0xff send on whatever channel is currently active
    if(channelId != 0xff) {
        ctx->sendChannel = channelId;
    }
    np_event_queue_post(server.pl, &ctx->sendEv, &nm_dtls_srv_event_send_to, ctx);

    return NABTO_EC_OK;
}

np_error_code nm_dtls_srv_async_recv_from(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                          np_dtls_srv_received_callback cb, void* data)
{
    NABTO_LOG_ERROR(LOG, "values are: %u, %u, %u, %u", pl, ctx, cb, data);
    NABTO_LOG_ERROR(LOG, "value %i", ctx->recvCb);
    ctx->recvCb = cb;
    ctx->recvCbData = data;
    np_event_queue_post(server.pl, &ctx->recvEv, &nm_dtls_srv_do_one, ctx);
    return NABTO_EC_OK;
}

np_error_code nm_dtls_srv_cancel_recv_from(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                           enum application_data_type type)
{
    ctx->recvCb = NULL;
    return NABTO_EC_OK;
}

void nm_dtls_srv_event_close(void* data){
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    mbedtls_ssl_close_notify(&ctx->ssl);
    mbedtls_ssl_free( &ctx->ssl );
    np_dtls_srv_close_callback cb = ctx->closeCb;
    void* cbData = ctx->closeCbData;
    free(ctx);
    ctx = NULL;
    cb(NABTO_EC_OK, cbData);
}

np_error_code nm_dtls_srv_async_close(struct np_platform* pl, np_dtls_srv_connection* ctx,
                                      np_dtls_srv_close_callback cb, void* data)
{
    ctx->closeCb = cb;
    ctx->closeCbData = data;
    ctx->state = CLOSING;
    np_event_queue_post(server.pl, &ctx->closeEv, &nm_dtls_srv_event_close, ctx);
    return NABTO_EC_OK;
}

void nm_dtls_srv_connection_received_callback(const np_error_code ec, struct np_connection* conn,
                                              uint8_t channelId, np_communication_buffer* buffer,
                                              uint16_t bufferSize, void* data)
{
    if ( data == NULL) {
        return;
    }
    NABTO_LOG_INFO(LOG, "connection data received callback");
    if (ec == NABTO_EC_OK) {
        np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
        ctx->currentChannelId = channelId;
        memcpy(ctx->recvBuffer, server.pl->buf.start(buffer), bufferSize);
        ctx->recvBufferSize = bufferSize;
        server.pl->conn.async_recv_from(server.pl, ctx->conn, &nm_dtls_srv_connection_received_callback, ctx);
        nm_dtls_srv_do_one(ctx);
    } else {
        // TODO: how to handle connection errors?
        NABTO_LOG_ERROR(LOG, "np_connection returned error code: %u", ec);
    }
}

np_error_code nm_dtls_srv_init_config()
{
    const char *pers = "dtls_server";
    int ret;
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
    mbedtls_ssl_config_init( &server.conf );
//    mbedtls_ssl_cookie_init( &server.cookie_ctx );
    mbedtls_entropy_init( &server.entropy );
    mbedtls_ctr_drbg_init( &server.ctr_drbg );
    mbedtls_x509_crt_init( &server.publicKey );
    mbedtls_pk_init( &server.privateKey );

    if( ( ret = mbedtls_ssl_config_defaults( &server.conf,
                                             MBEDTLS_SSL_IS_SERVER,
                                             MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_config_defaults returned %i", ret);
        return NABTO_EC_FAILED;
    }
    if( ( ret = mbedtls_ctr_drbg_seed( &server.ctr_drbg, mbedtls_entropy_func, &server.entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ctr_drbg_seed returned %d", ret );
        return NABTO_EC_FAILED;
    }
    mbedtls_ssl_conf_dbg( &server.conf, nm_dtls_srv_tls_logger, stdout );
    mbedtls_ssl_conf_rng( &server.conf, mbedtls_ctr_drbg_random, &server.ctr_drbg );

//    ret = mbedtls_ssl_cookie_setup( &server.cookie_ctx, mbedtls_ctr_drbg_random, &server.ctr_drbg );
//    if( ret != 0)
//    {
//        NABTO_LOG_ERROR(LOG, "mbedtls_ssl_cookie_setup returned %d", ret );
//        return NABTO_EC_FAILED;
//    }

//    mbedtls_ssl_conf_dtls_cookies( &server.conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
//                                   &server.cookie_ctx );
    ret = mbedtls_x509_crt_parse( &server.publicKey, (const unsigned char*)test_pub_key_crt, strlen(test_pub_key_crt)+1);
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG, "mbedtls_x509_crt_parse returned %d ", ret);
        return NABTO_EC_FAILED;
    }

    NABTO_LOG_TRACE(LOG, "parsing privateKey: %s", test_priv_key);
    ret =  mbedtls_pk_parse_key( &server.privateKey, (const unsigned char*)test_priv_key, strlen(test_priv_key)+1, NULL, 0 );
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG,"mbedtls_pk_parse_key returned %d", ret);
        return NABTO_EC_FAILED;
    }
//    mbedtls_ssl_conf_ca_chain( &server.conf, server.publicKey.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &server.conf, &server.publicKey, &server.privateKey ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG,"mbedtls_ssl_conf_own_cert returned %d", ret);
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;
}
static void nm_dtls_srv_tls_logger( void *ctx, int level,
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
    // TODO: fix this ugly hack to remove \n after all mbedtls log strings
    char ns[strlen(str)];
    memset(ns, 0, strlen(str));
    memcpy(ns, str, strlen(str));
    ns[strlen(str)-1] = '\0';
    NABTO_LOG_RAW(severity, LOG, line, file, ns );
}

// Function called by mbedtls when data should be sent to the network
int nm_dtls_srv_mbedtls_send(void* data, const unsigned char* buffer, size_t bufferSize)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    if (ctx->sslSendBufferSize == 0) {
        memcpy(server.pl->buf.start(ctx->sslSendBuffer), buffer, bufferSize);
        NABTO_LOG_TRACE(LOG, "mbedtls wants write:");
        NABTO_LOG_BUF(LOG, buffer, bufferSize);
        ctx->sslSendBufferSize = bufferSize;
        if(ctx->sendChannel != ctx->currentChannelId) {
            server.pl->conn.async_send_to(server.pl, ctx->conn, ctx->sendChannel, ctx->sslSendBuffer, bufferSize, &nm_dtls_srv_connection_send_callback, ctx);
            ctx->sendChannel = ctx->currentChannelId;
        } else {
            server.pl->conn.async_send_to(server.pl, ctx->conn, ctx->currentChannelId, ctx->sslSendBuffer, bufferSize, &nm_dtls_srv_connection_send_callback, ctx);
        }
        return bufferSize;
    } else {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

}

void nm_dtls_srv_connection_send_callback(const np_error_code ec, void* data)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Connection Async Send failed with code: %u", ec);
        return;
    }
    if (data == NULL) {
        return;
    }
    ctx->sslSendBufferSize = 0;
    if(ctx->state == CLOSING) {
        return;
    }
    nm_dtls_srv_do_one(ctx);
}


// Function called by mbedtls when it wants data from the network
int nm_dtls_srv_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    if (ctx->recvBufferSize == 0) {
        NABTO_LOG_INFO(LOG, "Empty buffer, returning WANT_READ");
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        NABTO_LOG_TRACE(LOG, "mbtls wants read %u bytes into buffersize: %u", ctx->recvBufferSize, bufferSize);
        size_t maxCp = bufferSize > ctx->recvBufferSize ? ctx->recvBufferSize : bufferSize;
        memcpy(buffer, ctx->recvBuffer, maxCp);
        NABTO_LOG_INFO(LOG, "returning %i bytes to mbedtls:", maxCp);
//        NABTO_LOG_BUF(LOG, buffer, maxCp);
        ctx->recvBufferSize = 0;
        return maxCp;
    }
}

void nm_dtls_srv_timed_event_do_one(const np_error_code ec, void* data) {
    nm_dtls_srv_do_one(data);
}

// Function called by mbedtls which creates timeout events
void nm_dtls_srv_mbedtls_timing_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    if (finalMilliseconds == 0) {
        // disable current timer  
        np_event_queue_cancel_timed_event(server.pl, &ctx->tEv);
        ctx->finalTp = 0;
    } else {
        server.pl->ts.set_future_timestamp(&ctx->intermediateTp, intermediateMilliseconds);
        server.pl->ts.set_future_timestamp(&ctx->finalTp, finalMilliseconds);
        np_event_queue_post_timed_event(server.pl, &ctx->tEv, finalMilliseconds, &nm_dtls_srv_timed_event_do_one, ctx);
    }
}

// Function called by mbedtls to determine when the next timeout event occurs
int nm_dtls_srv_mbedtls_timing_get_delay(void* data)
{
    np_dtls_srv_connection* ctx = (np_dtls_srv_connection*) data;
    if (ctx->finalTp) {
        if (server.pl->ts.passed_or_now(&ctx->finalTp)) {
            return 2;
        } else if (server.pl->ts.passed_or_now(&ctx->intermediateTp)) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return -1;
    }
}
