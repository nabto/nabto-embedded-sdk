#include <nabto/nabto_device_config.h>
#include "nm_mbedtls_srv.h"
#include "nm_mbedtls_util.h"
#include "nm_mbedtls_timer.h"
#include "nm_mbedtls_common.h"

#include <platform/np_logging.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_completion_event.h>
#include <platform/np_allocator.h>
#include <core/nc_version.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
//#include <mbedtls/ssl_cookie.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/timing.h>
#include <mbedtls/ssl_ciphersuites.h>

#include <string.h>

#include <stdio.h>

#if !defined(NABTO_DEVICE_DTLS_CLIENT_ONLY)


#define LOG NABTO_LOG_MODULE_DTLS_SRV

static const int allowedCipherSuitesList[] = { MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM, 0 };

const char* nm_mbedtls_srv_alpnList[] = {NABTO_PROTOCOL_VERSION , NULL};

struct np_dtls_srv_connection {
    struct np_platform* pl;
    enum sslState state;
    mbedtls_ssl_context ssl;
    uint8_t currentChannelId;
    uint8_t* recvBuffer;
    size_t recvBufferSize;
    struct np_communication_buffer* sslSendBuffer;
    struct nm_mbedtls_timer timer;

    np_dtls_close_callback closeCb;
    void* closeCbData;

    uint32_t recvCount;
    uint32_t sentCount;

    struct np_completion_event senderEvent;

    struct nn_llist sendList;
    struct np_event* startSendEvent;

    bool receiving;
    bool destroyed;

    np_dtls_sender sender;
    np_dtls_data_handler dataHandler;
    np_dtls_event_handler eventHandler;
    void* senderData;
    uint8_t channelId;

    struct np_completion_event* closeCompletionEvent;
};

struct np_dtls_srv {
    struct np_platform* pl;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt publicKey;
    mbedtls_pk_context privateKey;
};

static np_error_code nm_mbedtls_srv_create(struct np_platform* pl, struct np_dtls_srv** server);
static void nm_mbedtls_srv_destroy(struct np_dtls_srv* server);


static np_error_code nm_mbedtls_srv_init_config(struct np_dtls_srv* server,
                                             const unsigned char* publicKeyL, size_t publicKeySize,
                                             const unsigned char* privateKeyL, size_t privateKeySize);

static np_error_code nm_mbedtls_srv_set_keys(struct np_dtls_srv* server,
                                          const unsigned char* publicKeyL, size_t publicKeySize,
                                          const unsigned char* privateKeyL, size_t privateKeySize);

static np_error_code nm_mbedtls_srv_create_connection(struct np_dtls_srv* server, struct np_dtls_srv_connection** dtls,
                                                   np_dtls_sender sender,
                                                   np_dtls_data_handler dataHandler,
                                                   np_dtls_event_handler eventHandler, void* data);
static void nm_mbedtls_srv_destroy_connection(struct np_dtls_srv_connection* connection);

static np_error_code nm_mbedtls_srv_async_send_data(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                                 struct np_dtls_send_context* sendCtx);

static np_error_code nm_mbedtls_srv_async_close(struct np_platform *pl, struct np_dtls_srv_connection *ctx,
                                                struct np_completion_event *completionEvent);

static np_error_code nm_mbedtls_srv_get_fingerprint(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                                 uint8_t* fp);
static np_error_code nm_mbedtls_srv_get_server_fingerprint(struct np_dtls_srv* server, uint8_t* fp);

//static void nm_mbedtls_srv_tls_logger( void *ctx, int level, const char *file, int line, const char *str );
void nm_mbedtls_srv_connection_send_callback(const np_error_code ec, void* data);
void nm_mbedtls_srv_do_one(void* data);
void nm_mbedtls_srv_start_send(struct np_dtls_srv_connection* ctx);
void nm_mbedtls_srv_start_send_deferred(void* data);
static void nm_mbedtls_srv_do_free_connection(struct np_dtls_srv_connection *conn);

// Function called by mbedtls when data should be sent to the network
int nm_mbedtls_srv_mbedtls_send(void* ctx, const unsigned char* buffer, size_t bufferSize);
// Function called by mbedtls when it wants data from the network
int nm_mbedtls_srv_mbedtls_recv(void* ctx, unsigned char* buffer, size_t bufferSize);

static void nm_mbedtls_srv_timed_event_do_one(void* userData);

void nm_mbedtls_srv_event_send_to(void* data);
void event_callback(struct np_dtls_srv_connection* ctx, enum np_dtls_event event);
void nm_mbedtls_srv_do_event_callback(void* data);

static void nm_mbedtls_srv_is_closed(struct np_dtls_srv_connection* ctx);


// Get the packet counters for given dtls_cli_context
np_error_code nm_mbedtls_srv_get_packet_count(struct np_dtls_srv_connection* ctx, uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = ctx->recvCount;
    *sentCount = ctx->sentCount;
    return NABTO_EC_OK;
}

// Get the result of the application layer protocol negotiation
const char*  nm_mbedtls_srv_get_alpn_protocol(struct np_dtls_srv_connection* ctx) {
    return mbedtls_ssl_get_alpn_protocol(&ctx->ssl);
}

np_error_code nm_mbedtls_srv_handle_packet(struct np_platform* pl, struct np_dtls_srv_connection*ctx,
                                        uint8_t channelId, uint8_t* buffer, uint16_t bufferSize);

np_error_code nm_mbedtls_srv_init(struct np_platform* pl)
{
    pl->dtlsS.create = &nm_mbedtls_srv_create;
    pl->dtlsS.destroy = &nm_mbedtls_srv_destroy;
    pl->dtlsS.set_keys = &nm_mbedtls_srv_set_keys;
    pl->dtlsS.get_server_fingerprint = &nm_mbedtls_srv_get_server_fingerprint;
    pl->dtlsS.create_connection = &nm_mbedtls_srv_create_connection;
    pl->dtlsS.destroy_connection = &nm_mbedtls_srv_destroy_connection;
    pl->dtlsS.async_send_data = &nm_mbedtls_srv_async_send_data;
    pl->dtlsS.async_close = &nm_mbedtls_srv_async_close;
    pl->dtlsS.get_fingerprint = &nm_mbedtls_srv_get_fingerprint;
    pl->dtlsS.get_alpn_protocol = &nm_mbedtls_srv_get_alpn_protocol;
    pl->dtlsS.get_packet_count = &nm_mbedtls_srv_get_packet_count;
    pl->dtlsS.handle_packet = &nm_mbedtls_srv_handle_packet;
    return NABTO_EC_OK;
}

/**
 * get peers fingerprint for given DTLS client context
 */
np_error_code nm_mbedtls_srv_get_fingerprint(struct np_platform* pl, struct np_dtls_srv_connection* ctx, uint8_t* fp)
{
    (void)pl;
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ctx->ssl);
    if (crt == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to get peer cert from mbedtls");
        NABTO_LOG_ERROR(LOG, "Verification returned %u", mbedtls_ssl_get_verify_result(&ctx->ssl));
        return NABTO_EC_UNKNOWN;
    }
    return nm_mbedtls_util_fp_from_crt(crt, fp);
}

np_error_code nm_mbedtls_srv_get_server_fingerprint(struct np_dtls_srv* server, uint8_t* fp)
{
    return nm_mbedtls_util_fp_from_crt(&server->publicKey, fp);
}

np_error_code nm_mbedtls_srv_create(struct np_platform* pl, struct np_dtls_srv** server)
{
    (void)pl;
    *server = np_calloc(1, sizeof(struct np_dtls_srv));
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

void nm_mbedtls_srv_destroy(struct np_dtls_srv* server)
{
    mbedtls_ssl_config_free( &server->conf );
    mbedtls_entropy_free( &server->entropy );
    mbedtls_ctr_drbg_free( &server->ctr_drbg );
    mbedtls_x509_crt_free( &server->publicKey );
    mbedtls_pk_free( &server->privateKey );

    np_free(server);
}

np_error_code nm_mbedtls_srv_set_keys(struct np_dtls_srv* server,
                                   const unsigned char* publicKeyL, size_t publicKeySize,
                                   const unsigned char* privateKeyL, size_t privateKeySize)
{
    return nm_mbedtls_srv_init_config(server, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
}

np_error_code nm_mbedtls_srv_create_connection(struct np_dtls_srv* server,
                                            struct np_dtls_srv_connection** dtls,
                                            np_dtls_sender sender,
                                            np_dtls_data_handler dataHandler,
                                            np_dtls_event_handler eventHandler, void* data)
{
    int ret;
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*)np_calloc(1, sizeof(struct np_dtls_srv_connection));
    if(!ctx) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->pl = server->pl;
    ctx->sender = sender;
    ctx->dataHandler = dataHandler;
    ctx->eventHandler = eventHandler;
    ctx->senderData = data;
    ctx->channelId = NP_DTLS_DEFAULT_CHANNEL_ID;

    ctx->destroyed = false;
    ctx->receiving = false;

    nn_llist_init(&ctx->sendList);

    struct np_platform* pl = ctx->pl;

    np_error_code ec;
    ec = np_event_queue_create_event(&pl->eq, &nm_mbedtls_srv_start_send_deferred, ctx, &ctx->startSendEvent);
    if(ec != NABTO_EC_OK) {
        return ec;
    }

    ec = nm_mbedtls_timer_init(&ctx->timer, ctx->pl, &nm_mbedtls_srv_timed_event_do_one, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(&pl->eq, &ctx->senderEvent,
                                  &nm_mbedtls_srv_connection_send_callback, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    NABTO_LOG_TRACE(LOG, "New DTLS srv connection was allocated.");
    //mbedtls connection initialization
    mbedtls_ssl_init( &ctx->ssl );
    if( ( ret = mbedtls_ssl_setup( &ctx->ssl, &server->conf ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_setup returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }



    mbedtls_ssl_set_timer_cb(&ctx->ssl, &ctx->timer, &nm_mbedtls_timer_set_delay,
                              &nm_mbedtls_timer_get_delay );

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
                         &nm_mbedtls_srv_mbedtls_send, &nm_mbedtls_srv_mbedtls_recv, NULL );

    *dtls = ctx;
    return NABTO_EC_OK;
}

void nm_mbedtls_srv_do_free_connection(struct np_dtls_srv_connection* conn)
{
// remove the first element until the list is empty
    if (!nn_llist_empty(&conn->sendList)) {
        NABTO_LOG_ERROR(LOG, "invalid state the sendlist must be empty when calling destroy.");
    }
    while(!nn_llist_empty(&conn->sendList)) {
        struct nn_llist_iterator it = nn_llist_begin(&conn->sendList);
        struct np_dtls_send_context* first = nn_llist_get_item(&it);
        nn_llist_erase(&it);
        np_completion_event_resolve(&first->ev, NABTO_EC_CONNECTION_CLOSING);
    }
    nm_mbedtls_timer_cancel(&conn->timer);
    nm_mbedtls_timer_deinit(&conn->timer);
    struct np_event_queue* eq = &conn->pl->eq;
    np_event_queue_destroy_event(eq, conn->startSendEvent);
    np_completion_event_deinit(&conn->senderEvent);
    mbedtls_ssl_free(&conn->ssl);
    np_free(conn);

}

static void nm_mbedtls_srv_destroy_connection(struct np_dtls_srv_connection* conn)
{
    conn->destroyed = true;
    if (conn->sslSendBuffer == NULL && !conn->receiving) {
        nm_mbedtls_srv_do_free_connection(conn);
    }
}

np_error_code nm_mbedtls_srv_handle_packet(struct np_platform* pl, struct np_dtls_srv_connection*ctx,
                                        uint8_t channelId, uint8_t* buffer, uint16_t bufferSize)
{
    (void)pl;
    ctx->currentChannelId = channelId;
    ctx->recvBuffer = buffer;
    ctx->recvBufferSize = bufferSize;
    ctx->channelId = channelId;
    ctx->receiving = true;
    nm_mbedtls_srv_do_one(ctx);
    ctx->channelId = NP_DTLS_DEFAULT_CHANNEL_ID;
    ctx->recvBuffer = NULL;
    ctx->recvBufferSize = 0;
    ctx->receiving = false;
    if (ctx->destroyed && ctx->sslSendBuffer == NULL) {
        nm_mbedtls_srv_do_free_connection(ctx);
    }
    return NABTO_EC_OK;
}

static uint64_t uint64_from_bigendian( uint8_t* bytes )
{
    return( ( (uint64_t) bytes[0] << 56 ) |
            ( (uint64_t) bytes[1] << 48 ) |
            ( (uint64_t) bytes[2] << 40 ) |
            ( (uint64_t) bytes[3] << 32 ) |
            ( (uint64_t) bytes[4] << 24 ) |
            ( (uint64_t) bytes[5] << 16 ) |
            ( (uint64_t) bytes[6] <<  8 ) |
            ( (uint64_t) bytes[7]       ) );
}

void nm_mbedtls_srv_do_one(void* data)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*)data;
    if (ctx->state == CONNECTING) {
        int ret;
        ret = mbedtls_ssl_handshake( &ctx->ssl );
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // keep state as CONNECTING
        } else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            nm_mbedtls_timer_cancel(&ctx->timer);
            event_callback(ctx, NP_DTLS_EVENT_CLOSED);
        } else if (ret == 0) {
            NABTO_LOG_TRACE(LOG, "State changed to DATA");

            ctx->state = DATA;
            event_callback(ctx, NP_DTLS_EVENT_HANDSHAKE_COMPLETE);
        } else {
            NABTO_LOG_ERROR(LOG,  " failed  ! mbedtls_ssl_handshake returned -0x%04x", -ret );
            nm_mbedtls_timer_cancel(&ctx->timer);
            event_callback(ctx, NP_DTLS_EVENT_CLOSED);
            return;
        }
    } else if (ctx->state == DATA) {
        int ret;
        uint8_t* recvBuffer;
        ret = nm_mbedtls_recv_data(&ctx->ssl, &recvBuffer);
        if (ret == 0) {
            // EOF
            event_callback(ctx, NP_DTLS_EVENT_CLOSED);
            NABTO_LOG_TRACE(LOG, "Received EOF");
        } else if (ret > 0) {
            // we need the sequence number from the dtls packet.
            // the sequence number consists of an epoch and a sequence number in that epoch. 8 bytes in total.
            uint64_t seq = uint64_from_bigendian(ctx->ssl.MBEDTLS_PRIVATE(in_ctr));
            ctx->recvCount++;
            ctx->dataHandler(ctx->currentChannelId, seq, recvBuffer, (uint16_t)ret, ctx->senderData);
            np_free(recvBuffer);
        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                   ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // OK
        } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            // expected to happen on a connection,
            event_callback(ctx, NP_DTLS_EVENT_CLOSED);
        } else {
            NABTO_LOG_ERROR(LOG, "Received ERROR: %i", ret);
            event_callback(ctx, NP_DTLS_EVENT_CLOSED);
        }
    }
}

void event_callback(struct np_dtls_srv_connection* ctx, enum np_dtls_event event)
{
    ctx->eventHandler(event, ctx->senderData);
    // struct np_platform* pl = ctx->pl;
    // ctx->deferredEvent = event;
    // np_event_queue_post(&pl->eq, ctx->deferredEventEvent);
}

void nm_mbedtls_srv_start_send(struct np_dtls_srv_connection* ctx)
{
    np_event_queue_post_maybe_double(&ctx->pl->eq, ctx->startSendEvent);
}

void nm_mbedtls_srv_start_send_deferred(void* data)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    if (ctx->sslSendBuffer != NULL) {
        return;
    }

    if (nn_llist_empty(&ctx->sendList)) {
        // empty send queue
        nm_mbedtls_srv_is_closed(ctx);
        return;
    }

    struct nn_llist_iterator it = nn_llist_begin(&ctx->sendList);
    struct np_dtls_send_context* next = nn_llist_get_item(&it);
    nn_llist_erase(&it);

    ctx->channelId = next->channelId;
    int ret = mbedtls_ssl_write( &ctx->ssl, (unsigned char *) next->buffer, next->bufferSize );
    ctx->channelId = NP_DTLS_DEFAULT_CHANNEL_ID;
    if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        // packet too large
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i (Packet too large)", ret);
        np_completion_event_resolve(&next->ev, NABTO_EC_MALFORMED_PACKET);
    } else if (ret < 0) {
        // unknown error
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i", ret);
        np_completion_event_resolve(&next->ev, NABTO_EC_UNKNOWN);
    } else {
        ctx->sentCount++;
        np_completion_event_resolve(&next->ev, NABTO_EC_OK);
    }
}

np_error_code nm_mbedtls_srv_async_send_data(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                          struct np_dtls_send_context* sendCtx)
{
    (void)pl;
    if (ctx->state == CLOSING) {
        return NABTO_EC_CONNECTION_CLOSING;
    }
    nn_llist_append(&ctx->sendList, &sendCtx->sendListNode, sendCtx);
    nm_mbedtls_srv_start_send(ctx);
    return NABTO_EC_OK;
}

void nm_mbedtls_srv_is_closed(struct np_dtls_srv_connection* ctx)
{
    if (ctx->state != CLOSING) {
        return;
    }
    if (ctx->sslSendBuffer != NULL) {
        return;
    }
    if (!nn_llist_empty(&ctx->sendList)) {
        return;
    }
    /**
     * When all outstanding data is sent all we can resolve the close completion
     * event which will probably trigger that the connection is destroyed.
     */
    if (ctx->closeCompletionEvent != NULL) {
        struct np_completion_event* completionEvent = ctx->closeCompletionEvent;
        ctx->closeCompletionEvent = NULL;
        np_completion_event_resolve(completionEvent, NABTO_EC_OK);
    }
    event_callback(ctx, NP_DTLS_EVENT_CLOSED);
}

np_error_code nm_mbedtls_srv_async_close(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                         struct np_completion_event* completionEvent)
{
    (void)pl;
    if (ctx->closeCompletionEvent != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    if (ctx->state == CLOSING) {
        return NABTO_EC_OK;
    }
    ctx->closeCompletionEvent = completionEvent;
    ctx->state = CLOSING;
    nm_mbedtls_timer_cancel(&ctx->timer);
    mbedtls_ssl_close_notify(&ctx->ssl);
    nm_mbedtls_srv_is_closed(ctx);
    return NABTO_EC_OPERATION_STARTED;
}

np_error_code nm_mbedtls_srv_init_config(struct np_dtls_srv* server,
                                      const unsigned char* publicKeyL, size_t publicKeySize,
                                      const unsigned char* privateKeyL, size_t privateKeySize)
{
    const char *pers = "dtls_server";
    int ret;

    if( ( ret = mbedtls_ssl_config_defaults( &server->conf,
                                             MBEDTLS_SSL_IS_SERVER,
                                             MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_config_defaults returned %i", ret);
        return NABTO_EC_UNKNOWN;
    }

    mbedtls_ssl_conf_ciphersuites(&server->conf,
                                  allowedCipherSuitesList);

    mbedtls_ssl_conf_alpn_protocols(&server->conf, nm_mbedtls_srv_alpnList );

    if( ( ret = mbedtls_ctr_drbg_seed( &server->ctr_drbg, mbedtls_entropy_func, &server->entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ctr_drbg_seed returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }
    mbedtls_ssl_conf_rng( &server->conf, mbedtls_ctr_drbg_random, &server->ctr_drbg );

    nm_mbedtls_util_check_logging(&server->conf);

    ret = mbedtls_x509_crt_parse( &server->publicKey, (const unsigned char*)publicKeyL, publicKeySize+1);
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG, "mbedtls_x509_crt_parse returned %d ", ret);
        return NABTO_EC_UNKNOWN;
    }

    const unsigned char* p = privateKeyL;
    size_t pLen = privateKeySize+1;
#if MBEDTLS_VERSION_MAJOR >= 3
    ret =  mbedtls_pk_parse_key( &server->privateKey, p, pLen, NULL, 0, mbedtls_ctr_drbg_random, &server->ctr_drbg);
#else
    ret =  mbedtls_pk_parse_key( &server->privateKey, p, pLen, NULL, 0);
#endif
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

    mbedtls_ssl_conf_handshake_timeout(&server->conf, 1000, 16000);

    return NABTO_EC_OK;
}

// Function called by mbedtls when data should be sent to the network
int nm_mbedtls_srv_mbedtls_send(void* data, const unsigned char* buffer, size_t bufferSize)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    struct np_platform* pl = ctx->pl;
    if (ctx->sslSendBuffer == NULL) {
        ctx->sslSendBuffer = ctx->pl->buf.allocate();
        if (ctx->sslSendBuffer == NULL) {
            NABTO_LOG_ERROR(LOG, "Could not allocate buffer for sending data from the dtls server, dropping the packet.");
            // if we return WANT_WRITE there is no mechanism which ensures a retransmission occurs.
            return (int)bufferSize;
        }
        memcpy(ctx->pl->buf.start(ctx->sslSendBuffer), buffer, (uint16_t)bufferSize);

        np_error_code ec = ctx->sender(ctx->channelId, pl->buf.start(ctx->sslSendBuffer), (uint16_t)bufferSize, &ctx->senderEvent, ctx->senderData);
        if (ec != NABTO_EC_OK) {
            NABTO_LOG_ERROR(LOG, "Could not send the packet from the dtls server, dropping the packet.");
            pl->buf.free(ctx->sslSendBuffer);
            ctx->sslSendBuffer = NULL;
            // if we return WANT_WRITE there is no mechanism which ensures a retransmission occurs.
            return (int)bufferSize;
        }
        return (int)bufferSize;
    } else {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
}

void nm_mbedtls_srv_connection_send_callback(const np_error_code ec, void* data)
{
    (void)ec;
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    if (data == NULL) {
        return;
    }
    ctx->pl->buf.free(ctx->sslSendBuffer);
    ctx->sslSendBuffer = NULL;

    if(ctx->state == CLOSING && ctx->destroyed) {
        nm_mbedtls_srv_do_free_connection(ctx);
        return;
    }

    nm_mbedtls_srv_do_one(ctx);
    nm_mbedtls_srv_start_send(ctx);
}


// Function called by mbedtls when it wants data from the network
int nm_mbedtls_srv_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    if (ctx->recvBufferSize == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        size_t maxCp = bufferSize > ctx->recvBufferSize ? ctx->recvBufferSize : bufferSize;
        memcpy(buffer, ctx->recvBuffer, maxCp);
        ctx->recvBufferSize = 0;
        return (int)maxCp;
    }
}

void nm_mbedtls_srv_timed_event_do_one(void* data) {
    nm_mbedtls_srv_do_one(data);
}

#endif
