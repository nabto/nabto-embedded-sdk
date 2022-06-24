#include "nm_wolfssl_srv.h"
#include "nm_wolfssl_util.h"
#include "nm_wolfssl_timer.h"
#include "nm_wolfssl_common.h"

#include <platform/np_logging.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_completion_event.h>
#include <platform/np_allocator.h>
#include <core/nc_version.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <string.h>

#include <stdio.h>

#define LOG NABTO_LOG_MODULE_DTLS_SRV
#define DEBUG_LEVEL 0

static const int MIN_TIMEOUT = 1000;
static const int MAX_TIMEOUT = 16000;

static const char* allowedCipherSuitesList = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM";

const char* alpnList = NABTO_PROTOCOL_VERSION;

struct np_dtls_srv_connection {
    struct np_platform* pl;
    enum sslState state;
    WOLFSSL* ssl;
    uint8_t currentChannelId;
    uint8_t* recvBuffer;
    size_t recvBufferSize;

    // The sequence number in the last received dtls packet.
    uint64_t lastRecvSequenceNumber;

    struct np_communication_buffer* sslSendBuffer;

    struct np_event* timerEvent;

    np_dtls_close_callback closeCb;
    void* closeCbData;

    uint32_t recvCount;
    uint32_t sentCount;

    struct nn_llist sendList;
    struct np_event* startSendEvent;

    np_dtls_srv_sender sender;
    np_dtls_srv_data_handler dataHandler;
    np_dtls_srv_event_handler eventHandler;
    void* senderData;
    uint8_t channelId;

    struct np_completion_event* closeCompletionEvent;
};

struct np_dtls_srv {
    struct np_platform* pl;
    WOLFSSL_CTX* ctx;
};

static np_error_code nm_wolfssl_srv_create(struct np_platform* pl, struct np_dtls_srv** server);
static void nm_wolfssl_srv_destroy(struct np_dtls_srv* server);


static np_error_code nm_wolfssl_srv_init_config(struct np_dtls_srv* server,
                                             const unsigned char* publicKeyL, size_t publicKeySize,
                                             const unsigned char* privateKeyL, size_t privateKeySize);

static np_error_code nm_wolfssl_srv_set_keys(struct np_dtls_srv* server,
                                          const unsigned char* certificate, size_t certificateSize,
                                          const unsigned char* privateKeyL, size_t privateKeySize);

static np_error_code nm_wolfssl_srv_create_connection(struct np_dtls_srv* server, struct np_dtls_srv_connection** dtls,
                                                   np_dtls_srv_sender sender,
                                                   np_dtls_srv_data_handler dataHandler,
                                                   np_dtls_srv_event_handler eventHandler, void* data);
static void nm_wolfssl_srv_destroy_connection(struct np_dtls_srv_connection* connection);

static np_error_code nm_wolfssl_srv_async_send_data(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                                 struct np_dtls_srv_send_context* sendCtx);

static np_error_code nm_wolfssl_srv_async_close(struct np_platform *pl, struct np_dtls_srv_connection *ctx,
                                                struct np_completion_event *completionEvent);

static np_error_code nm_wolfssl_srv_get_fingerprint(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                                 uint8_t* fp);
static np_error_code nm_wolfssl_srv_get_server_fingerprint(struct np_dtls_srv* server, uint8_t* fp);

static void set_timeout(struct np_dtls_srv_connection* ctx);
static void handle_timeout(void* data);

//static void nm_wolfssl_srv_tls_logger( void *ctx, int level, const char *file, int line, const char *str );
void nm_wolfssl_srv_connection_send_callback(const np_error_code ec, void* data);
void nm_wolfssl_srv_do_one(void* data);
void nm_wolfssl_srv_start_send(struct np_dtls_srv_connection* ctx);
void nm_wolfssl_srv_start_send_deferred(void* data);

// Function called by wolfssl when data should be sent to the network
static int wolfssl_send(WOLFSSL* ssl, char* buffer, int bufferSize, void* ctx);
// Function called by wolfssl when it wants data from the network
static int wolfssl_recv(WOLFSSL* ssl, char* buffer, int bufferSize, void* ctx);

void nm_wolfssl_srv_event_send_to(void* data);
void event_callback(struct np_dtls_srv_connection* ctx, enum np_dtls_srv_event event);
void nm_wolfssl_srv_do_event_callback(void* data);

static void nm_wolfssl_srv_is_closed(struct np_dtls_srv_connection* ctx);

static int verify_callback(int foo, WOLFSSL_X509_STORE_CTX *chain)
{
    // TODO verify the self signed certificate.
    (void)foo;
    (void)chain;
    return WOLFSSL_SUCCESS;
}

// Get the packet counters for given dtls_cli_context
np_error_code nm_wolfssl_srv_get_packet_count(struct np_dtls_srv_connection* ctx, uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = ctx->recvCount;
    *sentCount = ctx->sentCount;
    return NABTO_EC_OK;
}

// Get the result of the application layer protocol negotiation
const char*  nm_wolfssl_srv_get_alpn_protocol(struct np_dtls_srv_connection* ctx) {
    // if the alpn negotiation failed the connect was blocked and we never get here.
    return NABTO_PROTOCOL_VERSION;
}

np_error_code nm_wolfssl_srv_handle_packet(struct np_platform* pl, struct np_dtls_srv_connection*ctx,
                                        uint8_t channelId, uint8_t* buffer, uint16_t bufferSize);

np_error_code nm_wolfssl_srv_init(struct np_platform* pl)
{
    pl->dtlsS.create = &nm_wolfssl_srv_create;
    pl->dtlsS.destroy = &nm_wolfssl_srv_destroy;
    pl->dtlsS.set_keys = &nm_wolfssl_srv_set_keys;
    pl->dtlsS.get_server_fingerprint = &nm_wolfssl_srv_get_server_fingerprint;
    pl->dtlsS.create_connection = &nm_wolfssl_srv_create_connection;
    pl->dtlsS.destroy_connection = &nm_wolfssl_srv_destroy_connection;
    pl->dtlsS.async_send_data = &nm_wolfssl_srv_async_send_data;
    pl->dtlsS.async_close = &nm_wolfssl_srv_async_close;
    pl->dtlsS.get_fingerprint = &nm_wolfssl_srv_get_fingerprint;
    pl->dtlsS.get_alpn_protocol = &nm_wolfssl_srv_get_alpn_protocol;
    pl->dtlsS.get_packet_count = &nm_wolfssl_srv_get_packet_count;
    pl->dtlsS.handle_packet = &nm_wolfssl_srv_handle_packet;
    return NABTO_EC_OK;
}

/**
 * get peers fingerprint for given DTLS client context
 */
np_error_code nm_wolfssl_srv_get_fingerprint(struct np_platform* pl, struct np_dtls_srv_connection* ctx, uint8_t* fp)
{
    WOLFSSL_X509 *crt = wolfSSL_get_peer_certificate(ctx->ssl);
    if (!crt) {
        return NABTO_EC_UNKNOWN;
    }
    return nm_wolfssl_util_fp_from_crt(crt, fp);
}

np_error_code nm_wolfssl_srv_get_server_fingerprint(struct np_dtls_srv* server, uint8_t* fp)
{
    // TODO this is only used in password authentication. Consider not getting
    //the fingerprint from the server but from the device context directly using
    //nm_wolfssl_get_fingerprint_from_private_key return
    //nm_dtls_util_fp_from_crt(&server->publicKey, fp);
    return NABTO_EC_NOT_IMPLEMENTED;
}

np_error_code nm_wolfssl_srv_create(struct np_platform* pl, struct np_dtls_srv** server)
{
    (void)pl;
    *server = np_calloc(1, sizeof(struct np_dtls_srv));
    if (*server == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    (*server)->pl = pl;
    WOLFSSL_METHOD *method = wolfTLSv1_2_server_method();
    (*server)->ctx = wolfSSL_CTX_new(method);

    return NABTO_EC_OK;
}

void nm_wolfssl_srv_destroy(struct np_dtls_srv* server)
{
    wolfSSL_CTX_free(server->ctx);
    np_free(server);
}

np_error_code nm_wolfssl_srv_set_keys(struct np_dtls_srv* server,
                                   const unsigned char* certificate, size_t certificateSize,
                                   const unsigned char* privateKeyL, size_t privateKeySize)
{
    return nm_wolfssl_srv_init_config(server, certificate, certificateSize, privateKeyL, privateKeySize);
}

np_error_code nm_wolfssl_srv_create_connection(struct np_dtls_srv* server,
                                            struct np_dtls_srv_connection** dtls,
                                            np_dtls_srv_sender sender,
                                            np_dtls_srv_data_handler dataHandler,
                                            np_dtls_srv_event_handler eventHandler, void* data)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*)np_calloc(1, sizeof(struct np_dtls_srv_connection));
    if(!ctx) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->pl = server->pl;
    ctx->sender = sender;
    ctx->dataHandler = dataHandler;
    ctx->eventHandler = eventHandler;
    ctx->senderData = data;
    ctx->channelId = NP_DTLS_SRV_DEFAULT_CHANNEL_ID;

    nn_llist_init(&ctx->sendList);

    struct np_platform* pl = ctx->pl;

    np_error_code ec;
    ec = np_event_queue_create_event(&pl->eq, &nm_wolfssl_srv_start_send_deferred, ctx, &ctx->startSendEvent);
    if(ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_event_queue_create_event(&pl->eq, handle_timeout, ctx, &ctx->timerEvent);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    NABTO_LOG_TRACE(LOG, "New DTLS srv connection was allocated.");

    //wolfssl connection initialization

    ctx->ssl = wolfSSL_new(server->ctx);

    if (wolfSSL_UseALPN(ctx->ssl, (char *)(alpnList), strlen(alpnList), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
    {
        NABTO_LOG_ERROR(LOG, "cannot set alpn list");
        return NABTO_EC_FAILED;
    }

    if (wolfSSL_dtls_set_timeout_init(ctx->ssl, MIN_TIMEOUT) != WOLFSSL_SUCCESS) {
        NABTO_LOG_ERROR(LOG, "Cannot set min timeout for DTLS client connection");
        return NABTO_EC_FAILED;
    };
    if (wolfSSL_dtls_set_timeout_max(ctx->ssl, MAX_TIMEOUT) != WOLFSSL_SUCCESS) {
        NABTO_LOG_ERROR(LOG, "Cannot set max timeout for DTLS client connection");
        return NABTO_EC_FAILED;
    }

    wolfSSL_SetIOReadCtx(ctx->ssl, ctx);
    wolfSSL_SetIOWriteCtx(ctx->ssl, ctx);

    *dtls = ctx;
    return NABTO_EC_OK;
}

static void nm_wolfssl_srv_destroy_connection(struct np_dtls_srv_connection* connection)
{
    struct np_platform* pl = connection->pl;
    struct np_dtls_srv_connection* ctx = connection;
    // remove the first element until the list is empty
    if (!nn_llist_empty(&ctx->sendList)) {
        NABTO_LOG_ERROR(LOG, "invalid state the sendlist must be empty when calling destroy.");
    }
    while(!nn_llist_empty(&ctx->sendList)) {
        struct nn_llist_iterator it = nn_llist_begin(&ctx->sendList);
        struct np_dtls_srv_send_context* first = nn_llist_get_item(&it);
        nn_llist_erase(&it);
        first->cb(NABTO_EC_CONNECTION_CLOSING, first->data);
    }

    struct np_event_queue* eq = &pl->eq;
    np_event_queue_destroy_event(&ctx->pl->eq, ctx->timerEvent);

    np_event_queue_destroy_event(eq, ctx->startSendEvent);
    wolfSSL_free(connection->ssl);
    np_free(connection);
}

np_error_code nm_wolfssl_srv_handle_packet(struct np_platform* pl, struct np_dtls_srv_connection*ctx,
                                        uint8_t channelId, uint8_t* buffer, uint16_t bufferSize)
{
    (void)pl;
    ctx->currentChannelId = channelId;
    ctx->recvBuffer = buffer;
    ctx->recvBufferSize = bufferSize;
    ctx->channelId = channelId;
    nm_wolfssl_srv_do_one(ctx);
    ctx->channelId = NP_DTLS_SRV_DEFAULT_CHANNEL_ID;
    ctx->recvBuffer = NULL;
    ctx->recvBufferSize = 0;
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

void nm_wolfssl_srv_do_one(void* data)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*)data;
    if (ctx->state == CONNECTING) {
        int ret;
        ret = wolfSSL_connect(ctx->ssl);

        if (ret == WOLFSSL_ERROR_WANT_READ) {
            set_timeout(ctx);
        } else if (ret == WOLFSSL_ERROR_WANT_WRITE)
        {
            // keep state as CONNECTING
        }
        else if (ret == WOLFSSL_SUCCESS) {
            NABTO_LOG_TRACE(LOG, "State changed to DATA");

            ctx->state = DATA;
            event_callback(ctx, NP_DTLS_SRV_EVENT_HANDSHAKE_COMPLETE);
        } else {
            NABTO_LOG_ERROR(LOG,  " failed  ! wolfssl_ssl_handshake returned -0x%04x", -ret );
            np_event_queue_cancel_event(&ctx->pl->eq, ctx->timerEvent);
            event_callback(ctx, NP_DTLS_SRV_EVENT_CLOSED);
            return;
        }
    } else if (ctx->state == DATA) {
        int ret;
        uint8_t recvBuffer[1500];
        ret = wolfSSL_read(ctx->ssl, recvBuffer, sizeof(recvBuffer) );
        if (ret == 0) {
            // EOF
            event_callback(ctx, NP_DTLS_SRV_EVENT_CLOSED);
            NABTO_LOG_TRACE(LOG, "Received EOF");
        }
        else if (ret > 0) {
            // we need the sequence number from the dtls packet.
            // the sequence number consists of an epoch and a sequence number in that epoch. 8 bytes in total.
            uint64_t seq = ctx->lastRecvSequenceNumber; //uint64_from_bigendian(ctx->ssl.in_ctr);
            ctx->recvCount++;
            ctx->dataHandler(ctx->currentChannelId, seq, recvBuffer, (uint16_t)ret, ctx->senderData);
            return;
        } else if (ret == WOLFSSL_ERROR_WANT_READ ||
                  ret == WOLFSSL_ERROR_WANT_WRITE)
        {
            // OK
        }
        // TODO
        //} else if (ret == WOLFSSL_ERROR_ wolfssl_ERR_SSL_PEER_CLOSE_NOTIFY) {
            // expected to happen on a connection,
        //    event_callback(ctx, NP_DTLS_SRV_EVENT_CLOSED);
        //}
        else {
            NABTO_LOG_ERROR(LOG, "Received ERROR: %i", ret);
            event_callback(ctx, NP_DTLS_SRV_EVENT_CLOSED);
        }
    }
}

void set_timeout(struct np_dtls_srv_connection* ctx)
{
    int timeout = wolfSSL_dtls_get_current_timeout(ctx->ssl);
    if (timeout >= 0) {
        np_event_queue_post_timed_event(&ctx->pl->eq, ctx->timerEvent, (uint32_t)(timeout*1000));
    }
}

void handle_timeout(void* data)
{
    struct np_dtls_srv_connection* ctx = data;
    int ec = wolfSSL_dtls_got_timeout(ctx->ssl);
    if (ec == WOLFSSL_SUCCESS) {
        set_timeout(ctx);
    } else if (ec == SSL_FATAL_ERROR) {
        // too many retries, timeout.
        event_callback(ctx, NP_DTLS_SRV_EVENT_CLOSED);
    } else {
        // NOT_COMPILED_IN etc
        NABTO_LOG_ERROR(LOG, "Unhandled wolfSSL_dtls_got_timeout error code.");
    }

}

void event_callback(struct np_dtls_srv_connection* ctx, enum np_dtls_srv_event event)
{
    ctx->eventHandler(event, ctx->senderData);
}

void nm_wolfssl_srv_start_send(struct np_dtls_srv_connection* ctx)
{
    np_event_queue_post_maybe_double(&ctx->pl->eq, ctx->startSendEvent);
}

void nm_wolfssl_srv_start_send_deferred(void* data)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    if (ctx->sslSendBuffer != NULL) {
        return;
    }

    if (nn_llist_empty(&ctx->sendList)) {
        // empty send queue
        nm_wolfssl_srv_is_closed(ctx);
        return;
    }

    struct nn_llist_iterator it = nn_llist_begin(&ctx->sendList);
    struct np_dtls_srv_send_context* next = nn_llist_get_item(&it);
    nn_llist_erase(&it);

    ctx->channelId = next->channelId;
    int ret = wolfSSL_write( ctx->ssl, next->buffer, (int)next->bufferSize );
    ctx->channelId = NP_DTLS_SRV_DEFAULT_CHANNEL_ID;
    if (next->cb == NULL) {
        ctx->sentCount++;
    }
    // todo handle too large packets
    //else if (ret == wolfssl_ERR_SSL_BAD_INPUT_DATA) {
        // packet too large
    //    NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i (Packet too large)", ret);
    //    next->cb(NABTO_EC_MALFORMED_PACKET, next->data);
    //}
    else if (ret < 0) {
        // unknown error
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i", ret);
        next->cb(NABTO_EC_UNKNOWN, next->data);
    } else {
        ctx->sentCount++;
        next->cb(NABTO_EC_OK, next->data);
    }
}

np_error_code nm_wolfssl_srv_async_send_data(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                          struct np_dtls_srv_send_context* sendCtx)
{
    (void)pl;
    if (ctx->state == CLOSING) {
        return NABTO_EC_CONNECTION_CLOSING;
    }
    nn_llist_append(&ctx->sendList, &sendCtx->sendListNode, sendCtx);
    nm_wolfssl_srv_start_send(ctx);
    return NABTO_EC_OK;
}

void nm_wolfssl_srv_is_closed(struct np_dtls_srv_connection* ctx)
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
}

np_error_code nm_wolfssl_srv_async_close(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
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
    np_event_queue_cancel_event(&pl->eq, ctx->timerEvent);
    wolfSSL_shutdown(ctx->ssl);
    nm_wolfssl_srv_is_closed(ctx);
    return NABTO_EC_OPERATION_STARTED;
}

#if defined(wolfssl_DEBUG_C)
static void nm_wolfssl_srv_tls_logger( void *ctx, int level,
                                    const char *file, int line,
                                    const char *str )
{
    ((void) level);
    ((void) ctx);
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


np_error_code nm_wolfssl_srv_init_config(struct np_dtls_srv* server,
                                      const unsigned char* certificate, size_t certificateSize,
                                      const unsigned char* privateKeyL, size_t privateKeySize)
{
    int ret;
#if defined(wolfssl_DEBUG_C)
    wolfssl_debug_set_threshold( DEBUG_LEVEL );
#endif

    if (wolfSSL_CTX_set_cipher_list(server->ctx, allowedCipherSuitesList) != WOLFSSL_SUCCESS)
    {
        NABTO_LOG_ERROR(LOG, "server can't set custom cipher list");
        return NABTO_EC_FAILED;
    }

#if defined(wolfssl_DEBUG_C)
    wolfssl_ssl_conf_dbg( &server->conf, &nm_wolfssl_srv_tls_logger, NULL );
#endif

    ret = wolfSSL_CTX_use_PrivateKey_buffer(server->ctx, privateKeyL, privateKeySize, WOLFSSL_FILETYPE_PEM);
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG, "wolfSSL_CTX_use_PrivateKey_buffer %d ", ret);
        return NABTO_EC_UNKNOWN;
    }

    ret = wolfSSL_CTX_use_certificate_buffer(server->ctx, certificate, certificateSize, WOLFSSL_FILETYPE_PEM);
    if( ret != WOLFSSL_SUCCESS )
    {
        NABTO_LOG_ERROR(LOG, "wolfSSL_CTX_use_certificate_buffer %d ", ret);
        return NABTO_EC_UNKNOWN;
    }

    wolfSSL_CTX_set_verify(server->ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);

#if defined(wolfssl_SSL_DTLS_HELLO_VERIFY)
    wolfssl_ssl_conf_dtls_cookies(&server->conf, NULL, NULL, NULL);
#endif

    wolfSSL_CTX_SetIORecv(server->ctx, wolfssl_recv);
    wolfSSL_CTX_SetIOSend(server->ctx, wolfssl_send);


    return NABTO_EC_OK;
}

// Function called by wolfssl when data should be sent to the network
int wolfssl_send(WOLFSSL* ssl, char* buffer, int bufferSize, void* data)
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

        np_error_code ec = ctx->sender(ctx->channelId, pl->buf.start(ctx->sslSendBuffer), (uint16_t)bufferSize, &nm_wolfssl_srv_connection_send_callback, ctx, ctx->senderData);
        if (ec != NABTO_EC_OK) {
            NABTO_LOG_ERROR(LOG, "Could not send the packet from the dtls server, dropping the packet.");
            pl->buf.free(ctx->sslSendBuffer);
            ctx->sslSendBuffer = NULL;
            // if we return WANT_WRITE there is no mechanism which ensures a retransmission occurs.
            return (int)bufferSize;
        }
        return (int)bufferSize;
    } else {
        return WOLFSSL_ERROR_WANT_WRITE;
    }
}

void nm_wolfssl_srv_connection_send_callback(const np_error_code ec, void* data)
{
    (void)ec;
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    if (data == NULL) {
        return;
    }
    ctx->pl->buf.free(ctx->sslSendBuffer);
    ctx->sslSendBuffer = NULL;

    nm_wolfssl_srv_do_one(ctx);
    nm_wolfssl_srv_start_send(ctx);
}


// Function called by wolfssl when it wants data from the network
int wolfssl_recv(WOLFSSL* ssl, char* buffer, int bufferSize, void* data)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*) data;
    if (ctx->recvBufferSize == 0) {
        return WOLFSSL_ERROR_WANT_READ;
    } else {
        if (ctx->recvBufferSize >= 12) {
            // the sequence number is byte 4-11
            ctx->lastRecvSequenceNumber = uint64_from_bigendian(ctx->recvBuffer+4);
        }
        size_t maxCp = bufferSize > ctx->recvBufferSize ? ctx->recvBufferSize : bufferSize;
        memcpy(buffer, ctx->recvBuffer, maxCp);
        ctx->recvBufferSize = 0;



        return (int)maxCp;
    }
}
