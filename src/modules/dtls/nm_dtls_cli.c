#include "nm_dtls_cli.h"
#include "nm_dtls_util.h"

#include <platform/np_logging.h>
#include <platform/np_udp.h>

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
#include <stdio.h>

#define NABTO_SSL_RECV_BUFFER_SIZE 4096
#define SERVER_NAME "localhost"
#define LOG NABTO_LOG_MODULE_DTLS_CLI
#define DEBUG_LEVEL 0

struct np_dtls_cli_context {
    struct np_platform* pl;
    struct nm_dtls_util_connection_ctx ctx;
    struct np_event connEv;

    struct np_dtls_cli_send_context sendSentinel;
    struct np_event startSendEvent;

    bool sending;

    np_dtls_cli_sender sender;
    np_dtls_cli_data_handler dataHandler;
    np_dtls_cli_event_handler eventHandler;
    void* senderData;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt publicKey;
    mbedtls_pk_context privateKey;

};

const char* nm_dtls_cli_alpnList[] = {NABTO_PROTOCOL_VERSION , NULL};

static np_error_code nm_dtls_cli_create(struct np_platform* pl, np_dtls_cli_context** client,
                                        np_dtls_cli_sender packetSender, np_dtls_cli_data_handler dataHandler,
                                        np_dtls_cli_event_handler eventHandler, void* data);
static void nm_dtls_cli_destroy(np_dtls_cli_context* connection);
static np_error_code nm_dtls_cli_set_keys(np_dtls_cli_context* ctx,
                                          const unsigned char* publicKeyL, size_t publicKeySize,
                                          const unsigned char* privateKeyL, size_t privateKeySize);

np_error_code nm_dtls_async_send_data(struct np_platform* pl, np_dtls_cli_context* ctx,
                                      struct np_dtls_cli_send_context* sendCtx);

np_error_code nm_dtls_async_close(struct np_platform* pl, np_dtls_cli_context* ctx,
                                  np_dtls_close_callback cb, void* data);

np_error_code nm_dtls_get_fingerprint(struct np_platform* pl, np_dtls_cli_context* ctx, uint8_t* fp);



np_error_code nm_dtls_connect(np_dtls_cli_context* ctx);

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

void nm_dtls_cli_start_send_deferred(void* data);

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

#if defined(MBEDTLS_DEBUG_C)
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
#endif

/*
 * Initialize the np_platform to use this particular dtls cli module
 */
np_error_code nm_dtls_cli_init(struct np_platform* pl)
{
    pl->dtlsC.create = &nm_dtls_cli_create;
    pl->dtlsC.destroy = &nm_dtls_cli_destroy;
    pl->dtlsC.set_keys = &nm_dtls_cli_set_keys;
    pl->dtlsC.connect = &nm_dtls_connect;
    pl->dtlsC.async_send_data = &nm_dtls_async_send_data;
    pl->dtlsC.async_close = &nm_dtls_async_close;
    pl->dtlsC.get_fingerprint = &nm_dtls_get_fingerprint;
    pl->dtlsC.get_alpn_protocol = &nm_dtls_get_alpn_protocol;
    pl->dtlsC.get_packet_count = &nm_dtls_get_packet_count;
    pl->dtlsC.handle_packet = &nm_dtls_cli_handle_packet;

    return NABTO_EC_OK;
}

np_error_code nm_dtls_cli_create(struct np_platform* pl, np_dtls_cli_context** client,
                                 np_dtls_cli_sender packetSender, np_dtls_cli_data_handler dataHandler,
                                 np_dtls_cli_event_handler eventHandler, void* data)
{
    *client = NULL;
    np_dtls_cli_context* ctx = calloc(1, sizeof(struct np_dtls_cli_context));
    *client = ctx;
    ctx->pl = pl;
    mbedtls_ssl_init( &ctx->ctx.ssl );
    mbedtls_ssl_config_init( &ctx->conf );
    mbedtls_ctr_drbg_init( &ctx->ctr_drbg );
    mbedtls_entropy_init( &ctx->entropy );
    mbedtls_x509_crt_init( &ctx->publicKey );
    mbedtls_pk_init( &ctx->privateKey );

    ctx->sender = packetSender;
    ctx->dataHandler = dataHandler;
    ctx->eventHandler = eventHandler;
    ctx->senderData = data;

    ctx->ctx.sslRecvBuf = pl->buf.allocate();
    ctx->ctx.sslSendBuffer = pl->buf.allocate();

    ctx->sendSentinel.next = &ctx->sendSentinel;
    ctx->sendSentinel.prev = &ctx->sendSentinel;

    return NABTO_EC_OK;
}

void nm_dtls_cli_destroy(np_dtls_cli_context* ctx)
{
    struct np_platform* pl = ctx->pl;

    pl->buf.free(ctx->ctx.sslRecvBuf);
    pl->buf.free(ctx->ctx.sslSendBuffer);

    mbedtls_pk_free(&ctx->privateKey);
    mbedtls_x509_crt_free(&ctx->publicKey );
    mbedtls_entropy_free( &ctx->entropy );
    mbedtls_ctr_drbg_free( &ctx->ctr_drbg );
    mbedtls_ssl_config_free( &ctx->conf );
    mbedtls_ssl_free( &ctx->ctx.ssl );

    free(ctx);
}

np_error_code nm_dtls_cli_set_keys(np_dtls_cli_context* ctx,
                                   const unsigned char* publicKeyL, size_t publicKeySize,
                                   const unsigned char* privateKeyL, size_t privateKeySize)
{
    int ret;
    mbedtls_x509_crt_init( &ctx->publicKey );
    mbedtls_pk_init( &ctx->privateKey );
    ret = mbedtls_x509_crt_parse( &ctx->publicKey, publicKeyL, publicKeySize+1);
    if( ret != 0 ) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_x509_crt_parse returned %d", ret );
        return NABTO_EC_FAILED;
    }
    ret =  mbedtls_pk_parse_key( &ctx->privateKey, privateKeyL, privateKeySize+1, NULL, 0 );
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
np_error_code nm_dtls_connect(np_dtls_cli_context* ctx)
{
    np_error_code ec;
    ctx->ctx.state = CONNECTING;
    ctx->sending = false;

    ec = nm_dtls_setup_dtls_ctx(ctx);
    nm_dtls_event_do_one(ctx);
    return ec;
}

/*
 * Handle events for the connection phase
 */
void nm_dtls_event_do_one(void* data)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*)data;
    int ret;
    NABTO_LOG_TRACE(LOG, "doing one");
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
                ctx->eventHandler(NP_DTLS_CLI_EVENT_CLOSED, ctx->senderData);
                np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
                return;
            }
            NABTO_LOG_INFO(LOG, "State changed to DATA");
            ctx->ctx.state = DATA;
            ctx->eventHandler(NP_DTLS_CLI_EVENT_HANDSHAKE_COMPLETE, ctx->senderData);
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
            ctx->ctx.recvCount++;

            ctx->dataHandler(ctx->ctx.currentChannelId, seq, ctx->ctx.sslRecvBuf, ret, ctx->senderData);
            return;
        }else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                  ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // OK
        } else {
#if defined(MBEDTLS_ERROR_C)
            char buf[128];
            mbedtls_strerror(ret, buf, 128);
            NABTO_LOG_INFO(LOG, "Received ERROR -0x%04x : %s ", -ret, buf);
#endif
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
//        NABTO_LOG_ERROR(LOG, "mbedtls_ssl_write returned with error: %i", ret);
//        nm_dtls_event_do_one(ctx);
//        np_event_queue_post(ctx->pl, &ctx->ctx.sendEv, &nm_dtls_event_send_to, ctx);
//        return;
        cb(NABTO_EC_FAILED, ctx->ctx.sendCbData);
    } else if (ret < 0) {
        // unknown error
        NABTO_LOG_ERROR(LOG, "mbedtls_ssl_write returned with error: %i", ret);
        cb(NABTO_EC_FAILED, ctx->ctx.sendCbData);
    } else {
        ctx->ctx.sentCount++;
        cb(NABTO_EC_OK, ctx->ctx.sendCbData);
    }
}

// insert chunk into double linked list after elm.
void nm_dtls_cli_insert_send_data(struct np_dtls_cli_send_context* chunk, struct np_dtls_cli_send_context* elm)
{
    struct np_dtls_cli_send_context* before = elm;
    struct np_dtls_cli_send_context* after = elm->next;

    before->next = chunk;
    chunk->next = after;
    after->prev = chunk;
    chunk->prev = before;
}

void nm_dtls_cli_remove_send_data(struct np_dtls_cli_send_context* elm)
{
    struct np_dtls_cli_send_context* before = elm->prev;
    struct np_dtls_cli_send_context* after = elm->next;
    before->next = after;
    after->prev = before;
}

void nm_dtls_cli_start_send(struct np_dtls_cli_context* ctx)
{
    np_event_queue_post(ctx->pl, &ctx->startSendEvent, &nm_dtls_cli_start_send_deferred, ctx);
}

void nm_dtls_cli_start_send_deferred(void* data)
{
    struct np_dtls_cli_context* ctx = data;
    if (ctx->sending) {
        return;
    }

    if (ctx->sendSentinel.next == &ctx->sendSentinel) {
        // empty send queue
        return;
    }

    struct np_dtls_cli_send_context* next = ctx->sendSentinel.next;
    nm_dtls_cli_remove_send_data(next);

    int ret = mbedtls_ssl_write( &ctx->ctx.ssl, (unsigned char *) next->buffer, next->bufferSize );
    if (next->cb == NULL) {
        ctx->ctx.sentCount++;
    } else if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        // packet too large
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i (Packet too large)", ret);
        next->cb(NABTO_EC_MALFORMED_PACKET, next->data);
    } else if (ret < 0) {
        // unknown error
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i", ret);
        next->cb(NABTO_EC_FAILED, next->data);
    } else {
        ctx->ctx.sentCount++;
        next->cb(NABTO_EC_OK, next->data);
    }

    // can we send more packets?
    nm_dtls_cli_start_send(ctx);
}


np_error_code nm_dtls_async_send_data(struct np_platform* pl, np_dtls_cli_context* ctx,
                                      struct np_dtls_cli_send_context* sendCtx)
{

    if (ctx->ctx.state == CLOSING) {
        return NABTO_EC_CONNECTION_CLOSING;
    }
    NABTO_LOG_TRACE(LOG, "enqueued dtls application data packet");
    nm_dtls_cli_insert_send_data(sendCtx, &ctx->sendSentinel);
    nm_dtls_cli_start_send(ctx);
    return NABTO_EC_OK;
}

void nm_dtls_do_close(void* data, np_error_code ec){
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    np_dtls_close_callback cb = ctx->ctx.closeCb;
    void* cbData = ctx->ctx.closeCbData;
    NABTO_LOG_TRACE(LOG, "Closing DTLS Client Connection");

    if (ctx->ctx.recvCb.cb != NULL) {
        NABTO_LOG_TRACE(LOG, "found Callback function");
        np_dtls_received_callback cb = ctx->ctx.recvCb.cb;
        ctx->ctx.recvCb.cb = NULL;
        cb(NABTO_EC_CONNECTION_CLOSING, 0, 0, NULL, 0, ctx->ctx.recvCb.data);
    }
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
    np_event_queue_cancel_event(ctx->pl, &ctx->connEv);
    np_event_queue_cancel_event(ctx->pl, &ctx->ctx.sendEv);
    np_event_queue_cancel_event(ctx->pl, &ctx->ctx.recvEv);
    np_event_queue_cancel_event(ctx->pl, &ctx->ctx.closeEv);
    if (cb == NULL) {
        NABTO_LOG_ERROR(LOG, "close callback was NULL");
        return;
    }
    NABTO_LOG_ERROR(LOG, "Calling close callback");
    cb(NABTO_EC_OK, cbData);
}

void nm_dtls_event_close(void* data) {
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (ctx->sending) {
        np_event_queue_post(ctx->pl, &ctx->ctx.closeEv, &nm_dtls_event_close, ctx);
        return;
    }
    nm_dtls_do_close(data, NABTO_EC_CONNECTION_CLOSING);
}

np_error_code nm_dtls_async_close(struct np_platform* pl, np_dtls_cli_context* ctx,
                                  np_dtls_close_callback cb, void* data)
{
    if (!ctx || ctx->ctx.state == CLOSING) {
        return NABTO_EC_OK;
    }
    ctx->ctx.closeCb = cb;
    ctx->ctx.closeCbData = data;
    ctx->ctx.state = CLOSING;
    mbedtls_ssl_close_notify(&ctx->ctx.ssl);
    np_event_queue_post(ctx->pl, &ctx->ctx.closeEv, &nm_dtls_event_close, ctx);
    return NABTO_EC_OK;
}

np_error_code nm_dtls_cli_handle_packet(struct np_platform* pl, struct np_dtls_cli_context* ctx,
                                   np_communication_buffer* buffer, uint16_t bufferSize)
{
    NABTO_LOG_TRACE(LOG, "connection data received callback");
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
//        nm_dtls_event_close(ctx);
//        np_event_queue_post(ctx->pl, &ctx->closeEv, &nm_dtls_event_close, ctx);
        return;
    }
    nm_dtls_event_do_one(data);
}

int nm_dtls_mbedtls_send(void* data, const unsigned char* buffer, size_t bufferSize)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (ctx->ctx.sslSendBufferSize == 0) {
        NABTO_LOG_TRACE(LOG, "mbedtls wants send, sending state: %u", ctx->sending);
        ctx->sending = true;
        memcpy(ctx->pl->buf.start(ctx->ctx.sslSendBuffer), buffer, bufferSize);
//        NABTO_LOG_TRACE(LOG, "mbedtls wants write:");
//        NABTO_LOG_BUF(LOG, buffer, bufferSize);
        ctx->ctx.sslSendBufferSize = bufferSize;
        // TODO
        ctx->sender(true, ctx->ctx.sslSendBuffer, bufferSize, &nm_dtls_udp_send_callback, ctx, ctx->senderData);
        return bufferSize;
    } else {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
}

int nm_dtls_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (ctx->ctx.recvBufferSize == 0) {
        NABTO_LOG_TRACE(LOG, "Empty buffer, returning WANT_READ");
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        NABTO_LOG_TRACE(LOG, "mbtls wants read %u bytes into buffersize: %u", ctx->ctx.recvBufferSize, bufferSize);
        size_t maxCp = bufferSize > ctx->ctx.recvBufferSize ? ctx->ctx.recvBufferSize : bufferSize;
        memcpy(buffer, ctx->ctx.recvBuffer, maxCp);
        NABTO_LOG_TRACE(LOG, "returning %i bytes to mbedtls:", maxCp);
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

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    if( ( ret = mbedtls_ctr_drbg_seed( &ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 ) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ctr_drbg_seed returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        return NABTO_EC_FAILED;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &ctx->conf,
                   MBEDTLS_SSL_IS_CLIENT,
                   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                   MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_config_defaults returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        return NABTO_EC_FAILED;
    }
    mbedtls_ssl_conf_alpn_protocols(&ctx->conf, nm_dtls_cli_alpnList );
    mbedtls_ssl_conf_authmode( &ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    ret = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->publicKey, &ctx->privateKey);
    if (ret != 0) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_conf_own_cert returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        return NABTO_EC_FAILED;
    }

    mbedtls_ssl_conf_rng( &ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg );
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg( &ctx->conf, my_debug, stdout );
#endif
    if( ( ret = mbedtls_ssl_setup( &ctx->ctx.ssl, &ctx->conf ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_setup returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        return NABTO_EC_FAILED;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ctx->ctx.ssl, SERVER_NAME ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_set_hostname returned %d", ret );
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->ctx.tEv);
        return NABTO_EC_FAILED;
    }

    mbedtls_ssl_set_bio( &ctx->ctx.ssl, ctx,
                         nm_dtls_mbedtls_send, nm_dtls_mbedtls_recv, NULL );
    mbedtls_ssl_set_timer_cb( &ctx->ctx.ssl, ctx, nm_dtls_mbedtls_timing_set_delay,
                                            nm_dtls_mbedtls_timing_get_delay );
    return NABTO_EC_OK;
}
