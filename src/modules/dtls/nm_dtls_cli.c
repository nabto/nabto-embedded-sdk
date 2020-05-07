#include "nm_dtls_cli.h"
#include "nm_dtls_util.h"
#include "nm_dtls_timer.h"

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
#include <mbedtls/ssl_ciphersuites.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>


#define LOG NABTO_LOG_MODULE_DTLS_CLI
#define DEBUG_LEVEL 0

const int allowedCipherSuitesList[] = { MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM, 0 };

struct np_dtls_cli_context {
    struct np_platform* pl;
    enum sslState state;
    struct np_communication_buffer* sslRecvBuf;
    uint8_t* recvBuffer;
    size_t recvBufferSize;
    struct np_communication_buffer* sslSendBuffer;
    size_t sslSendBufferSize;

    struct nm_dtls_timer timer;

    struct np_event* closeEv;

    uint32_t recvCount;
    uint32_t sentCount;

    struct np_dtls_cli_send_context sendSentinel;
    struct np_event* startSendEvent;

    bool sending;
    bool receiving;
    bool destroyed;

    np_dtls_cli_sender sender;
    np_dtls_cli_data_handler dataHandler;
    np_dtls_cli_event_handler eventHandler;
    void* callbackData;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt publicKey;
    mbedtls_pk_context privateKey;
    mbedtls_ssl_context ssl;

};

const char* nm_dtls_cli_alpnList[] = {NABTO_PROTOCOL_VERSION , NULL};

static np_error_code nm_dtls_cli_create(struct np_platform* pl, np_dtls_cli_context** client,
                                        np_dtls_cli_sender packetSender, np_dtls_cli_data_handler dataHandler,
                                        np_dtls_cli_event_handler eventHandler, void* data);
static void nm_dtls_cli_destroy(np_dtls_cli_context* connection);

static np_error_code nm_dtls_cli_set_sni(np_dtls_cli_context* ctx, const char* sniName);
static np_error_code nm_dtls_cli_set_keys(np_dtls_cli_context* ctx,
                                          const unsigned char* publicKeyL, size_t publicKeySize,
                                          const unsigned char* privateKeyL, size_t privateKeySize);

static np_error_code async_send_data(np_dtls_cli_context* ctx,
                                     struct np_dtls_cli_send_context* sendCtx);

static np_error_code dtls_cli_close(np_dtls_cli_context* ctx);

static np_error_code get_fingerprint(np_dtls_cli_context* ctx, uint8_t* fp);

static np_error_code set_handshake_timeout(np_dtls_cli_context* ctx, uint32_t minTimeout, uint32_t maxTimeout);

static void nm_dtls_timed_event_do_one(const np_error_code ec, void* data);
static np_error_code dtls_cli_init_connection(np_dtls_cli_context* ctx);
static np_error_code nm_dtls_cli_reset(np_dtls_cli_context* ctx);
static np_error_code nm_dtls_connect(np_dtls_cli_context* ctx);

static void nm_dtls_event_close(void* data);

// Function called by mbedtls when data should be sent to the network
int nm_dtls_mbedtls_send(void* ctx, const unsigned char* buffer, size_t bufferSize);
// Function called by mbedtls when it wants data from the network
int nm_dtls_mbedtls_recv(void* ctx, unsigned char* buffer, size_t bufferSize);
// Function used to handle events during the connection phase
void nm_dtls_event_do_one(void* data);

void nm_dtls_cli_remove_send_data(struct np_dtls_cli_send_context* elm);

// Handle packet from udp
static np_error_code handle_packet(struct np_dtls_cli_context* ctx,
                                   uint8_t* buffer, uint16_t bufferSize);

void nm_dtls_cli_start_send_deferred(void* data);

void nm_dtls_do_close(void* data, np_error_code ec);

// setup function for the mbedtls context
np_error_code nm_dtls_setup_dtls_ctx(np_dtls_cli_context* ctx);

void nm_dtls_cli_do_free(np_dtls_cli_context* ctx);

// Get the packet counters for given dtls_cli_context
np_error_code nm_dtls_get_packet_count(np_dtls_cli_context* ctx, uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = ctx->recvCount;
    *sentCount = ctx->sentCount;
    return NABTO_EC_OK;
}

// Get the result of the application layer protocol negotiation
const char*  nm_dtls_get_alpn_protocol(np_dtls_cli_context* ctx) {
    return mbedtls_ssl_get_alpn_protocol(&ctx->ssl);
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
    pl->dtlsC.set_sni = &nm_dtls_cli_set_sni;
    pl->dtlsC.set_keys = &nm_dtls_cli_set_keys;
    pl->dtlsC.connect = &nm_dtls_connect;
    pl->dtlsC.reset = &nm_dtls_cli_reset;
    pl->dtlsC.async_send_data = &async_send_data;
    pl->dtlsC.close = &dtls_cli_close;
    pl->dtlsC.get_fingerprint = &get_fingerprint;
    pl->dtlsC.set_handshake_timeout = &set_handshake_timeout;
    pl->dtlsC.get_alpn_protocol = &nm_dtls_get_alpn_protocol;
    pl->dtlsC.get_packet_count = &nm_dtls_get_packet_count;
    pl->dtlsC.handle_packet = &handle_packet;

    return NABTO_EC_OK;
}

np_error_code nm_dtls_cli_create(struct np_platform* pl, np_dtls_cli_context** client,
                                 np_dtls_cli_sender packetSender, np_dtls_cli_data_handler dataHandler,
                                 np_dtls_cli_event_handler eventHandler, void* data)
{
    *client = NULL;
    np_dtls_cli_context* ctx = calloc(1, sizeof(struct np_dtls_cli_context));
    if (ctx == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->pl = pl;
    mbedtls_ssl_init( &ctx->ssl );
    mbedtls_ssl_config_init( &ctx->conf );
    mbedtls_ctr_drbg_init( &ctx->ctr_drbg );
    mbedtls_entropy_init( &ctx->entropy );
    mbedtls_x509_crt_init( &ctx->publicKey );
    mbedtls_pk_init( &ctx->privateKey );

    ctx->sender = packetSender;
    ctx->dataHandler = dataHandler;
    ctx->eventHandler = eventHandler;
    ctx->callbackData = data;

    ctx->sslRecvBuf = pl->buf.allocate();
    ctx->sslSendBuffer = pl->buf.allocate();
    if (!ctx->sslRecvBuf || !ctx->sslSendBuffer) {
        nm_dtls_cli_do_free(ctx);
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->sendSentinel.next = &ctx->sendSentinel;
    ctx->sendSentinel.prev = &ctx->sendSentinel;
    ctx->destroyed = false;

    np_error_code ec = dtls_cli_init_connection(ctx);
    if (ec != NABTO_EC_OK) {
        nm_dtls_cli_do_free(ctx);
        return ec;
    }
    int ret;
    if( ( ret = mbedtls_ssl_setup( &ctx->ssl, &ctx->conf ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_setup returned %d", ret );
        nm_dtls_cli_do_free(ctx);
        return NABTO_EC_UNKNOWN;
    }

    ec = np_event_queue_create_event(pl, &nm_dtls_cli_start_send_deferred, ctx, &ctx->startSendEvent);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_event_queue_create_event(ctx->pl, &nm_dtls_event_close, ctx, &ctx->closeEv);
    if (ec != NABTO_EC_OK) {
        return ec;
    }


    *client = ctx;
    return NABTO_EC_OK;
}

np_error_code dtls_cli_init_connection(np_dtls_cli_context* ctx)
{
    np_error_code ec;
    ec = nm_dtls_timer_init(&ctx->timer, ctx->pl, &nm_dtls_timed_event_do_one, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    int ret;
    const char *pers = "dtls_client";

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    if( ( ret = mbedtls_ctr_drbg_seed( &ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 ) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ctr_drbg_seed returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &ctx->conf,
                   MBEDTLS_SSL_IS_CLIENT,
                   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                   MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_config_defaults returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }

    mbedtls_ssl_conf_ciphersuites(&ctx->conf,
                                  allowedCipherSuitesList);

    mbedtls_ssl_conf_alpn_protocols(&ctx->conf, nm_dtls_cli_alpnList );
    mbedtls_ssl_conf_authmode( &ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );

    mbedtls_ssl_conf_rng( &ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg );
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg( &ctx->conf, my_debug, stdout );
#endif


#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg( &ctx->conf, my_debug, stdout );
#endif

    mbedtls_ssl_set_bio( &ctx->ssl, ctx,
                         nm_dtls_mbedtls_send, nm_dtls_mbedtls_recv, NULL );

    mbedtls_ssl_set_timer_cb( &ctx->ssl,
                              &ctx->timer,
                              &nm_dtls_timer_set_delay,
                              &nm_dtls_timer_get_delay );
    return NABTO_EC_OK;
}

np_error_code nm_dtls_cli_reset(np_dtls_cli_context* ctx)
{
    mbedtls_ssl_session_reset( &ctx->ssl );
    // remove the first element until the list is empty
    while(ctx->sendSentinel.next != &ctx->sendSentinel) {
        struct np_dtls_cli_send_context* first = ctx->sendSentinel.next;
        nm_dtls_cli_remove_send_data(first);
        first->cb(NABTO_EC_CONNECTION_CLOSING, first->data);
    }
    ctx->sslSendBufferSize = 0;
    ctx->recvBufferSize = 0;

    nm_dtls_timer_cancel(&ctx->timer);
    np_event_queue_cancel_event(ctx->pl, ctx->startSendEvent);
    np_event_queue_cancel_event(ctx->pl, ctx->closeEv);
    return NABTO_EC_OK;
}

void nm_dtls_cli_do_free(np_dtls_cli_context* ctx)
{
    struct np_platform* pl = ctx->pl;
    // remove the first element until the list is empty
    while(ctx->sendSentinel.next != &ctx->sendSentinel) {
        struct np_dtls_cli_send_context* first = ctx->sendSentinel.next;
        nm_dtls_cli_remove_send_data(first);
        first->cb(NABTO_EC_CONNECTION_CLOSING, first->data);
    }

    nm_dtls_timer_cancel(&ctx->timer);
    np_event_queue_cancel_event(ctx->pl, ctx->startSendEvent);
    np_event_queue_cancel_event(ctx->pl, ctx->closeEv);
    np_event_queue_destroy_event(ctx->pl, ctx->startSendEvent);
    np_event_queue_destroy_event(ctx->pl, ctx->closeEv);
    nm_dtls_timer_deinit(&ctx->timer);
    pl->buf.free(ctx->sslRecvBuf);
    pl->buf.free(ctx->sslSendBuffer);

    mbedtls_pk_free(&ctx->privateKey);
    mbedtls_x509_crt_free(&ctx->publicKey );
    mbedtls_entropy_free( &ctx->entropy );
    mbedtls_ctr_drbg_free( &ctx->ctr_drbg );
    mbedtls_ssl_config_free( &ctx->conf );
    mbedtls_ssl_free( &ctx->ssl );

    free(ctx);
}

void nm_dtls_cli_destroy(np_dtls_cli_context* ctx)
{
    ctx->state = CLOSING;
    ctx->destroyed = true;

    if (!ctx->sending && !ctx->receiving) {
        nm_dtls_cli_do_free(ctx);
    }
}

np_error_code nm_dtls_cli_set_sni(np_dtls_cli_context* ctx, const char* sniName)
{
    int ret;
    if( ( ret = mbedtls_ssl_set_hostname( &ctx->ssl, sniName ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_set_hostname returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }
    return NABTO_EC_OK;
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
        return NABTO_EC_UNKNOWN;
    }
    ret =  mbedtls_pk_parse_key( &ctx->privateKey, privateKeyL, privateKeySize+1, NULL, 0 );
    if( ret != 0 ) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_pk_parse_key returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }

    ret = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->publicKey, &ctx->privateKey);
    if (ret != 0) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_conf_own_cert returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }

    return NABTO_EC_OK;
}


/**
 * get peers fingerprint for given DTLS client context
 */
np_error_code get_fingerprint(np_dtls_cli_context* ctx, uint8_t* fp)
{
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ctx->ssl);
    if (!crt) {
        return NABTO_EC_UNKNOWN;
    }
    return nm_dtls_util_fp_from_crt(crt, fp);
}

np_error_code set_handshake_timeout(np_dtls_cli_context* ctx, uint32_t minTimeout, uint32_t maxTimeout)
{
    mbedtls_ssl_conf_handshake_timeout(&ctx->conf, minTimeout, maxTimeout);
    return NABTO_EC_OK;
}

/*
 * asyncroniously start a dtls connection
 */
np_error_code nm_dtls_connect(np_dtls_cli_context* ctx)
{
    ctx->state = CONNECTING;
    ctx->sending = false;

    nm_dtls_event_do_one(ctx);
    return NABTO_EC_OK;
}

/*
 * Handle events for the connection phase
 */
void nm_dtls_event_do_one(void* data)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*)data;
    struct np_platform* pl = ctx->pl;
    int ret;
    if(ctx->state == CONNECTING) {
        ret = mbedtls_ssl_handshake( &ctx->ssl );
        if( ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
            //Keep State CONNECTING
        } else if (ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE &&
                   ctx->ssl.in_msg[1] == MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED)
        {
            ctx->state = CLOSING;
            nm_dtls_timer_cancel(&ctx->timer);
            ctx->eventHandler(NP_DTLS_CLI_EVENT_ACCESS_DENIED, ctx->callbackData);
            return;
        } else {
            if( ret != 0 )
            {
                NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_handshake returned -0x%04x", -ret );
                ctx->state = CLOSING;
                nm_dtls_timer_cancel(&ctx->timer);
                ctx->eventHandler(NP_DTLS_CLI_EVENT_CLOSED, ctx->callbackData);
                return;
            }
            NABTO_LOG_TRACE(LOG, "State changed to DATA");
            ctx->state = DATA;
            ctx->eventHandler(NP_DTLS_CLI_EVENT_HANDSHAKE_COMPLETE, ctx->callbackData);
        }
        return;
    } else if(ctx->state == DATA) {
        ret = mbedtls_ssl_read( &ctx->ssl, ctx->pl->buf.start(ctx->sslRecvBuf), ctx->pl->buf.size(ctx->sslRecvBuf) );
        if (ret == 0) {
            // EOF
            ctx->state = CLOSING;
            NABTO_LOG_TRACE(LOG, "Received EOF, state = CLOSING");
        } else if (ret > 0) {
            ctx->recvCount++;

            ctx->dataHandler(pl->buf.start(ctx->sslRecvBuf), ret, ctx->callbackData);
            return;
        }else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                  ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // OK
        } else if (ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE &&
                   ctx->ssl.in_msg[1] == MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED)
        {
            nm_dtls_timer_cancel(&ctx->timer);
            ctx->eventHandler(NP_DTLS_CLI_EVENT_ACCESS_DENIED, ctx->callbackData);
            return;
        } else {
#if defined(MBEDTLS_ERROR_C)
            char buf[128];
            mbedtls_strerror(ret, buf, 128);
            NABTO_LOG_TRACE(LOG, "Received ERROR -0x%04x : %s ", -ret, buf);
#endif
            ctx->state = CLOSING;
            nm_dtls_do_close(ctx, NABTO_EC_UNKNOWN);
        }
        return;
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
    np_event_queue_post_maybe_double(ctx->pl, ctx->startSendEvent);
}

void nm_dtls_cli_start_send_deferred(void* data)
{
    struct np_dtls_cli_context* ctx = data;
    if (ctx->state == CLOSING) {
        return;
    }
    if (ctx->sending) {
        return;
    }

    if (ctx->sendSentinel.next == &ctx->sendSentinel) {
        // empty send queue
        return;
    }

    struct np_dtls_cli_send_context* next = ctx->sendSentinel.next;
    nm_dtls_cli_remove_send_data(next);

    int ret = mbedtls_ssl_write( &ctx->ssl, (unsigned char *) next->buffer, next->bufferSize );
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

    // can we send more packets?
    nm_dtls_cli_start_send(ctx);
}


np_error_code async_send_data(np_dtls_cli_context* ctx,
                              struct np_dtls_cli_send_context* sendCtx)
{

    if (ctx->state == CLOSING) {
        return NABTO_EC_CONNECTION_CLOSING;
    }
    nm_dtls_cli_insert_send_data(sendCtx, &ctx->sendSentinel);
    nm_dtls_cli_start_send(ctx);
    return NABTO_EC_OK;
}

void nm_dtls_do_close(void* data, np_error_code ec){
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    NABTO_LOG_TRACE(LOG, "Closing DTLS Client Connection");
    np_event_queue_cancel_event(ctx->pl, ctx->closeEv);
    nm_dtls_timer_cancel(&ctx->timer);
    ctx->eventHandler(NP_DTLS_CLI_EVENT_CLOSED, ctx->callbackData);
}

void nm_dtls_event_close(void* data) {
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (ctx->sending) {
        np_event_queue_post(ctx->pl, ctx->closeEv);
        return;
    }
    nm_dtls_do_close(data, NABTO_EC_CONNECTION_CLOSING);
}

np_error_code dtls_cli_close(np_dtls_cli_context* ctx)
{
    if (!ctx ) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    if ( ctx->state != CLOSING) {
        ctx->state = CLOSING;
        mbedtls_ssl_close_notify(&ctx->ssl);
        np_event_queue_post(ctx->pl, ctx->closeEv);
    }
    return NABTO_EC_OK;
}

np_error_code handle_packet(struct np_dtls_cli_context* ctx,
                            uint8_t* buffer, uint16_t bufferSize)
{
    ctx->recvBuffer = buffer;
    ctx->recvBufferSize = bufferSize;
    ctx->receiving = true;
    nm_dtls_event_do_one(ctx);
    ctx->recvBuffer = NULL;
    ctx->recvBufferSize = 0;
    ctx->receiving = false;
    if (ctx->destroyed && !ctx->sending) {
        nm_dtls_cli_do_free(ctx);
    }
    return NABTO_EC_OK;
}

void nm_dtls_udp_send_callback(const np_error_code ec, void* data)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (data == NULL) {
        return;
    }
    ctx->sending = false;
    ctx->sslSendBufferSize = 0;
    if(ctx->state == CLOSING) {
        if (ctx->destroyed) {
            nm_dtls_cli_do_free(ctx);
        }
        return;
    }
    nm_dtls_event_do_one(data);
}

int nm_dtls_mbedtls_send(void* data, const unsigned char* buffer, size_t bufferSize)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    struct np_platform* pl = ctx->pl;
    if (ctx->sslSendBufferSize == 0) {
        ctx->sending = true;
        memcpy(ctx->pl->buf.start(ctx->sslSendBuffer), buffer, bufferSize);
        ctx->sslSendBufferSize = bufferSize;
        np_error_code ec = ctx->sender(pl->buf.start(ctx->sslSendBuffer), bufferSize, &nm_dtls_udp_send_callback, ctx, ctx->callbackData);
        if (ec != NABTO_EC_OK) {
            ctx->sending = false;
            ctx->sslSendBufferSize = 0;
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        return bufferSize;
    } else {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
}

int nm_dtls_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize)
{
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (ctx->recvBufferSize == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        size_t maxCp = bufferSize > ctx->recvBufferSize ? ctx->recvBufferSize : bufferSize;
        memcpy(buffer, ctx->recvBuffer, maxCp);
        ctx->recvBufferSize = 0;
        return maxCp;
    }
}

void nm_dtls_timed_event_do_one(const np_error_code ec, void* data) {
    np_dtls_cli_context* ctx = (np_dtls_cli_context*) data;
    if (ctx->state == CLOSING) {
        return;
    }
    nm_dtls_event_do_one(data);
}
