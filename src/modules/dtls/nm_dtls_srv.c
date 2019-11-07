#include "nm_dtls_srv.h"
#include "nm_dtls_util.h"
#include "nm_dtls_timer.h"

#include <platform/np_logging.h>
#include <core/nc_version.h>

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
#include <stdio.h>

#define LOG NABTO_LOG_MODULE_DTLS_SRV
#define DEBUG_LEVEL 0

const char* nm_dtls_srv_alpnList[] = {NABTO_PROTOCOL_VERSION , NULL};

struct np_dtls_srv_connection {
    struct np_platform* pl;
    enum sslState state;
    mbedtls_ssl_context ssl;
    uint8_t currentChannelId;
    uint8_t* recvBuffer;
    size_t recvBufferSize;
    np_communication_buffer* sslRecvBuf;
    np_communication_buffer* sslSendBuffer;
    size_t sslSendBufferSize;
    struct nm_dtls_timer timer;
    struct np_event closeEv;

    np_dtls_close_callback closeCb;
    void* closeCbData;

    uint32_t recvCount;
    uint32_t sentCount;

    struct np_dtls_srv_send_context sendSentinel;
    struct np_event startSendEvent;
    struct np_event deferredEventEvent;
    enum np_dtls_srv_event deferredEvent;

    np_dtls_srv_sender sender;
    np_dtls_srv_data_handler dataHandler;
    np_dtls_srv_event_handler eventHandler;
    void* senderData;
    bool sending;
    uint8_t channelId;
};

struct np_dtls_srv {
    struct np_platform* pl;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt publicKey;
    mbedtls_pk_context privateKey;
};

// insert chunk into end of double linked list.
void nm_dtls_srv_insert_send_data(struct np_dtls_srv_connection* connection, struct np_dtls_srv_send_context* chunk)
{
    struct np_dtls_srv_send_context* before = connection->sendSentinel.prev;
    struct np_dtls_srv_send_context* after = &connection->sendSentinel;

    before->next = chunk;
    chunk->next = after;
    after->prev = chunk;
    chunk->prev = before;
}

void nm_dtls_srv_remove_send_data(struct np_dtls_srv_send_context* elm)
{
    struct np_dtls_srv_send_context* before = elm->prev;
    struct np_dtls_srv_send_context* after = elm->next;
    before->next = after;
    after->prev = before;
}

static np_error_code nm_dtls_srv_create(struct np_platform* pl, struct np_dtls_srv** server);
static void nm_dtls_srv_destroy(struct np_dtls_srv* server);


static np_error_code nm_dtls_srv_init_config(struct np_dtls_srv* server,
                                             const unsigned char* publicKeyL, size_t publicKeySize,
                                             const unsigned char* privateKeyL, size_t privateKeySize);

static np_error_code nm_dtls_srv_set_keys(struct np_dtls_srv* server,
                                          const unsigned char* publicKeyL, size_t publicKeySize,
                                          const unsigned char* privateKeyL, size_t privateKeySize);

static np_error_code nm_dtls_srv_create_connection(struct np_dtls_srv* server, struct np_dtls_srv_connection** dtls,
                                                   np_dtls_srv_sender sender,
                                                   np_dtls_srv_data_handler dataHandler,
                                                   np_dtls_srv_event_handler eventHandler, void* data);
static void nm_dtls_srv_destroy_connection(struct np_dtls_srv_connection* connection);

static np_error_code nm_dtls_srv_async_send_data(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                                 struct np_dtls_srv_send_context* sendCtx);

static np_error_code nm_dtls_srv_async_close(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                             np_dtls_close_callback cb, void* data);

static np_error_code nm_dtls_srv_get_fingerprint(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                                 uint8_t* fp);


//static void nm_dtls_srv_tls_logger( void *ctx, int level, const char *file, int line, const char *str );
void nm_dtls_srv_connection_send_callback(const np_error_code ec, void* data);
void nm_dtls_srv_do_one(void* data);
void nm_dtls_srv_start_send(struct np_dtls_srv_connection* ctx);
void nm_dtls_srv_start_send_deferred(void* data);

// Function called by mbedtls when data should be sent to the network
int nm_dtls_srv_mbedtls_send(void* ctx, const unsigned char* buffer, size_t bufferSize);
// Function called by mbedtls when it wants data from the network
int nm_dtls_srv_mbedtls_recv(void* ctx, unsigned char* buffer, size_t bufferSize);

static void nm_dtls_srv_timed_event_do_one(const np_error_code ec, void* userData);

void nm_dtls_srv_event_send_to(void* data);
void deferred_event_callback(struct np_dtls_srv_connection* ctx, enum np_dtls_srv_event event);
void nm_dtls_srv_do_event_callback(void* data);




// Get the packet counters for given dtls_cli_context
np_error_code nm_dtls_srv_get_packet_count(struct np_dtls_srv_connection* ctx, uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = ctx->recvCount;
    *sentCount = ctx->sentCount;
    return NABTO_EC_OK;
}

// Get the result of the application layer protocol negotiation
const char*  nm_dtls_srv_get_alpn_protocol(struct np_dtls_srv_connection* ctx) {
    return mbedtls_ssl_get_alpn_protocol(&ctx->ssl);
}

np_error_code nm_dtls_srv_handle_packet(struct np_platform* pl, struct np_dtls_srv_connection*ctx,
                                        uint8_t channelId, uint8_t* buffer, uint16_t bufferSize);

np_error_code nm_dtls_srv_init(struct np_platform* pl)
{
    pl->dtlsS.create = &nm_dtls_srv_create;
    pl->dtlsS.destroy = &nm_dtls_srv_destroy;
    pl->dtlsS.set_keys = &nm_dtls_srv_set_keys;
    pl->dtlsS.create_connection = &nm_dtls_srv_create_connection;
    pl->dtlsS.destroy_connection = &nm_dtls_srv_destroy_connection;
    pl->dtlsS.async_send_data = &nm_dtls_srv_async_send_data;
    pl->dtlsS.async_close = &nm_dtls_srv_async_close;
    pl->dtlsS.get_fingerprint = &nm_dtls_srv_get_fingerprint;
    pl->dtlsS.get_alpn_protocol = &nm_dtls_srv_get_alpn_protocol;
    pl->dtlsS.get_packet_count = &nm_dtls_srv_get_packet_count;
    pl->dtlsS.handle_packet = &nm_dtls_srv_handle_packet;
    return NABTO_EC_OK;
}

/**
 * get peers fingerprint for given DTLS client context
 */
np_error_code nm_dtls_srv_get_fingerprint(struct np_platform* pl, struct np_dtls_srv_connection* ctx, uint8_t* fp)
{
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ctx->ssl);
    if (crt == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to get peer cert from mbedtls");
        NABTO_LOG_ERROR(LOG, "Verification returned %u", mbedtls_ssl_get_verify_result(&ctx->ssl));
        return NABTO_EC_UNKNOWN;
    }
    return nm_dtls_util_fp_from_crt(crt, fp);
}

np_error_code nm_dtls_srv_create(struct np_platform* pl, struct np_dtls_srv** server)
{
    *server = calloc(1, sizeof(struct np_dtls_srv));
    if (*server == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    (*server)->pl = pl;
    mbedtls_ssl_config_init( &(*server)->conf );
    mbedtls_entropy_init( &(*server)->entropy );
    mbedtls_ctr_drbg_init( &(*server)->ctr_drbg );
    mbedtls_x509_crt_init( &(*server)->publicKey );
    mbedtls_pk_init( &(*server)->privateKey );
    return NABTO_EC_OK;
}

void nm_dtls_srv_destroy(struct np_dtls_srv* server)
{
    mbedtls_ssl_config_free( &server->conf );
    mbedtls_entropy_free( &server->entropy );
    mbedtls_ctr_drbg_free( &server->ctr_drbg );
    mbedtls_x509_crt_free( &server->publicKey );
    mbedtls_pk_free( &server->privateKey );

    free(server);
}

np_error_code nm_dtls_srv_set_keys(struct np_dtls_srv* server,
                                   const unsigned char* publicKeyL, size_t publicKeySize,
                                   const unsigned char* privateKeyL, size_t privateKeySize)
{
    return nm_dtls_srv_init_config(server, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
}

np_error_code nm_dtls_srv_create_connection(struct np_dtls_srv* server,
                                            struct np_dtls_srv_connection** dtls,
                                            np_dtls_srv_sender sender,
                                            np_dtls_srv_data_handler dataHandler,
                                            np_dtls_srv_event_handler eventHandler, void* data)
{
    int ret;
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*)calloc(1, sizeof(struct np_dtls_srv_connection));
    if(!ctx) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->sslRecvBuf = server->pl->buf.allocate();
    ctx->sslSendBuffer = server->pl->buf.allocate();
    if (!ctx->sslRecvBuf || !ctx->sslSendBuffer) {
        free(ctx);
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->pl = server->pl;
    ctx->sender = sender;
    ctx->dataHandler = dataHandler;
    ctx->eventHandler = eventHandler;
    ctx->senderData = data;
    ctx->channelId = NP_DTLS_SRV_DEFAULT_CHANNEL_ID;
    ctx->sending = false;

    ctx->sendSentinel.next = &ctx->sendSentinel;
    ctx->sendSentinel.prev = &ctx->sendSentinel;
    np_event_queue_init_event(&ctx->startSendEvent);

    nm_dtls_timer_init(&ctx->timer, ctx->pl, &nm_dtls_srv_timed_event_do_one, ctx);

    NABTO_LOG_TRACE(LOG, "New DTLS srv connection was allocated.");
    //mbedtls connection initialization
    mbedtls_ssl_init( &ctx->ssl );
    if( ( ret = mbedtls_ssl_setup( &ctx->ssl, &server->conf ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_setup returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }



    mbedtls_ssl_set_timer_cb(&ctx->ssl, &ctx->timer, &nm_dtls_timer_set_delay,
                              &nm_dtls_timer_get_delay );

    mbedtls_ssl_session_reset( &ctx->ssl );

//    ret = mbedtls_ssl_set_client_transport_id(&ctx->ssl, (const unsigned char*)conn, sizeof(np_connection));
//    if (ret != 0) {
//        NABTO_LOG_ERROR(LOG, "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret);
//        return NABTO_EC_UNKNOWN;
//    }

    mbedtls_ssl_set_hs_authmode( &ctx->ssl, MBEDTLS_SSL_VERIFY_OPTIONAL );

    ret = mbedtls_ssl_set_hs_own_cert(&ctx->ssl, &server->publicKey, &server->privateKey);
    if (ret != 0) {
        NABTO_LOG_ERROR(LOG, "failed ! mbedtls_ssl_set_hs_own_cert returned %d", ret);
        return NABTO_EC_UNKNOWN;
    }

    mbedtls_ssl_set_bio( &ctx->ssl, ctx,
                         &nm_dtls_srv_mbedtls_send, &nm_dtls_srv_mbedtls_recv, NULL );

    *dtls = ctx;
    return NABTO_EC_OK;
}

static void nm_dtls_srv_destroy_connection(struct np_dtls_srv_connection* connection)
{
    struct np_platform* pl = connection->pl;
    struct np_dtls_srv_connection* ctx = connection;
    ctx->state = CLOSING;
    // remove the first element until the list is empty
    while(ctx->sendSentinel.next != &ctx->sendSentinel) {
        struct np_dtls_srv_send_context* first = ctx->sendSentinel.next;
        nm_dtls_srv_remove_send_data(first);
        first->cb(NABTO_EC_CONNECTION_CLOSING, first->data);
    }
    nm_dtls_timer_cancel(&ctx->timer);
    np_event_queue_cancel_event(ctx->pl, &ctx->closeEv);
    np_event_queue_cancel_event(ctx->pl, &ctx->startSendEvent);
    pl->buf.free(connection->sslRecvBuf);
    pl->buf.free(connection->sslSendBuffer);
    mbedtls_ssl_free(&connection->ssl);
    free(connection);
}

np_error_code nm_dtls_srv_handle_packet(struct np_platform* pl, struct np_dtls_srv_connection*ctx,
                                        uint8_t channelId, uint8_t* buffer, uint16_t bufferSize)
{
    ctx->currentChannelId = channelId;
    ctx->recvBuffer = buffer;
    ctx->recvBufferSize = bufferSize;
    ctx->channelId = channelId;
    nm_dtls_srv_do_one(ctx);
    ctx->channelId = NP_DTLS_SRV_DEFAULT_CHANNEL_ID;
    ctx->recvBuffer = NULL;
    ctx->recvBufferSize = 0;
    return NABTO_EC_OK;
}


void nm_dtls_srv_do_one(void* data)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*)data;
    struct np_platform* pl = ctx->pl;
    if (ctx->state == CONNECTING) {
        int ret;
        ret = mbedtls_ssl_handshake( &ctx->ssl );
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // keep state as CONNECTING
        } else if (ret == 0) {
            NABTO_LOG_TRACE(LOG, "State changed to DATA");

            ctx->state = DATA;
            deferred_event_callback(ctx, NP_DTLS_SRV_EVENT_HANDSHAKE_COMPLETE);
        } else {
            NABTO_LOG_ERROR(LOG,  " failed  ! mbedtls_ssl_handshake returned -0x%04x", -ret );
            nm_dtls_timer_cancel(&ctx->timer);
            return;
        }
    } else if (ctx->state == DATA) {
        int ret;
        ret = mbedtls_ssl_read(&ctx->ssl, ctx->pl->buf.start(ctx->sslRecvBuf), ctx->pl->buf.size(ctx->sslRecvBuf) );
        if (ret == 0) {
            // EOF
            ctx->state = CLOSING;
            NABTO_LOG_TRACE(LOG, "Received EOF, state = CLOSING");
        } else if (ret > 0) {
            uint64_t seq = *((uint64_t*)ctx->ssl.in_ctr);
            ctx->recvCount++;
            ctx->dataHandler(ctx->currentChannelId, seq,
                             pl->buf.start(ctx->sslRecvBuf), ret, ctx->senderData);
            return;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                   ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // OK
        } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            // expected to happen on a connection,
            ctx->state = CLOSING;
            deferred_event_callback(ctx, NP_DTLS_SRV_EVENT_CLOSED);
        } else {
            NABTO_LOG_ERROR(LOG, "Received ERROR: %i", ret);
            ctx->state = CLOSING;
            deferred_event_callback(ctx, NP_DTLS_SRV_EVENT_CLOSED);
        }
    }
}

void deferred_event_callback(struct np_dtls_srv_connection* ctx, enum np_dtls_srv_event event)
{
    struct np_platform* pl = ctx->pl;
    ctx->deferredEvent = event;
    np_event_queue_post(pl, &ctx->deferredEventEvent, &nm_dtls_srv_do_event_callback, ctx);
}

void nm_dtls_srv_do_event_callback(void* data)
{
    struct np_dtls_srv_connection* ctx = data;
    if (ctx->state == CLOSING && ctx->sending) {
        np_event_queue_post(ctx->pl, &ctx->deferredEventEvent, &nm_dtls_srv_do_event_callback, ctx);
    } else {
        ctx->eventHandler(ctx->deferredEvent, ctx->senderData);
    }
}

void nm_dtls_srv_start_send(struct np_dtls_srv_connection* ctx)
{
    np_event_queue_post_maybe_double(ctx->pl, &ctx->startSendEvent, &nm_dtls_srv_start_send_deferred, ctx);
}

void nm_dtls_srv_start_send_deferred(void* data)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    if (ctx->sending) {
        return;
    }

    if (ctx->sendSentinel.next == &ctx->sendSentinel) {
        // empty send queue
        return;
    }

    struct np_dtls_srv_send_context* next = ctx->sendSentinel.next;
    nm_dtls_srv_remove_send_data(next);

    ctx->channelId = next->channelId;
    int ret = mbedtls_ssl_write( &ctx->ssl, (unsigned char *) next->buffer, next->bufferSize );
    ctx->channelId = NP_DTLS_SRV_DEFAULT_CHANNEL_ID;
    if (next->cb == NULL) {
        ctx->sentCount++;
    } else if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        // packet too large
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i (Packet too large)", ret);
        next->cb(NABTO_EC_MALFORMED_PACKET, next->data);
    } else if (ret < 0) {
        // unknown error
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i", ret);
        next->cb(NABTO_EC_UNKNOWN, next->data);
    } else {
        ctx->sentCount++;
        next->cb(NABTO_EC_OK, next->data);
    }
}

np_error_code nm_dtls_srv_async_send_data(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                          struct np_dtls_srv_send_context* sendCtx)
{
    if (ctx->state == CLOSING) {
        return NABTO_EC_CONNECTION_CLOSING;
    }
    nm_dtls_srv_insert_send_data(ctx, sendCtx);
    nm_dtls_srv_start_send(ctx);
    return NABTO_EC_OK;
}

void nm_dtls_srv_event_close(void* data){
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    if (ctx->sending) {
        np_event_queue_post(ctx->pl, &ctx->closeEv, &nm_dtls_srv_event_close, ctx);
        return;
    }
    nm_dtls_timer_cancel(&ctx->timer);
    np_event_queue_cancel_event(ctx->pl, &ctx->closeEv);
    np_event_queue_cancel_event(ctx->pl, &ctx->startSendEvent);
    np_event_queue_cancel_event(ctx->pl, &ctx->deferredEventEvent);

    np_dtls_close_callback cb = ctx->closeCb;
    void* cbData = ctx->closeCbData;
    ctx->closeCb = NULL;
    if(cb != NULL) {
        cb(NABTO_EC_OK, cbData);
    }
}

np_error_code nm_dtls_srv_async_close(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                      np_dtls_close_callback cb, void* data)
{
    if (!ctx || ctx->state == CLOSING) {
        return NABTO_EC_OK;
    }
    ctx->closeCb = cb;
    ctx->closeCbData = data;
    ctx->state = CLOSING;
    mbedtls_ssl_close_notify(&ctx->ssl);
    np_event_queue_post(ctx->pl, &ctx->closeEv, &nm_dtls_srv_event_close, ctx);
    return NABTO_EC_OK;
}

#if defined(MBEDTLS_DEBUG_C)
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
    NABTO_LOG_RAW(severity, LOG, line, file, str );
}
#endif


np_error_code nm_dtls_srv_init_config(struct np_dtls_srv* server,
                                      const unsigned char* publicKeyL, size_t publicKeySize,
                                      const unsigned char* privateKeyL, size_t privateKeySize)
{
    const char *pers = "dtls_server";
    int ret;
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    if( ( ret = mbedtls_ssl_config_defaults( &server->conf,
                                             MBEDTLS_SSL_IS_SERVER,
                                             MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_config_defaults returned %i", ret);
        return NABTO_EC_UNKNOWN;
    }

    mbedtls_ssl_conf_alpn_protocols(&server->conf, nm_dtls_srv_alpnList );

    if( ( ret = mbedtls_ctr_drbg_seed( &server->ctr_drbg, mbedtls_entropy_func, &server->entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ctr_drbg_seed returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }
    mbedtls_ssl_conf_rng( &server->conf, mbedtls_ctr_drbg_random, &server->ctr_drbg );

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg( &server->conf, &nm_dtls_srv_tls_logger, stdout );
#endif

    ret = mbedtls_x509_crt_parse( &server->publicKey, (const unsigned char*)publicKeyL, publicKeySize+1);
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG, "mbedtls_x509_crt_parse returned %d ", ret);
        return NABTO_EC_UNKNOWN;
    }

    ret =  mbedtls_pk_parse_key( &server->privateKey, (const unsigned char*)privateKeyL, privateKeySize+1, NULL, 0 );
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG,"mbedtls_pk_parse_key returned %d", ret);
        return NABTO_EC_UNKNOWN;
    }

    if( ( ret = mbedtls_ssl_conf_own_cert( &server->conf, &server->publicKey, &server->privateKey ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG,"mbedtls_ssl_conf_own_cert returned %d", ret);
        return NABTO_EC_UNKNOWN;
    }
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
    mbedtls_ssl_conf_dtls_cookies(&server->conf, NULL, NULL, NULL);
#endif

    return NABTO_EC_OK;
}

// Function called by mbedtls when data should be sent to the network
int nm_dtls_srv_mbedtls_send(void* data, const unsigned char* buffer, size_t bufferSize)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    struct np_platform* pl = ctx->pl;
    if (!ctx->sending) {
        memcpy(ctx->pl->buf.start(ctx->sslSendBuffer), buffer, bufferSize);
        ctx->sslSendBufferSize = bufferSize;
        ctx->sending = true;
        ctx->sender(ctx->channelId, pl->buf.start(ctx->sslSendBuffer), bufferSize, &nm_dtls_srv_connection_send_callback, ctx, ctx->senderData);

        return bufferSize;
    } else {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
}

void nm_dtls_srv_connection_send_callback(const np_error_code ec, void* data)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    if (data == NULL) {
        return;
    }
    ctx->sending = false;
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Connection Async Send failed with code: %u", ec);
        return;
    }
    ctx->sslSendBufferSize = 0;
    if(ctx->state == CLOSING) {
        return;
    }
    nm_dtls_srv_do_one(ctx);
    nm_dtls_srv_start_send(ctx);
}


// Function called by mbedtls when it wants data from the network
int nm_dtls_srv_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    if (ctx->recvBufferSize == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        size_t maxCp = bufferSize > ctx->recvBufferSize ? ctx->recvBufferSize : bufferSize;
        memcpy(buffer, ctx->recvBuffer, maxCp);
        ctx->recvBufferSize = 0;
        return maxCp;
    }
}

void nm_dtls_srv_timed_event_do_one(const np_error_code ec, void* data) {
    nm_dtls_srv_do_one(data);
}
