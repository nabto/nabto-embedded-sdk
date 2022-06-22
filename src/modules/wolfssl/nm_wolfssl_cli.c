#include "nm_wolfssl_cli.h"
#include "nm_wolfssl_util.h"
#include "nm_wolfssl_timer.h"
#include "nm_wolfssl_common.h"

#include <platform/np_logging.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_allocator.h>
#include <platform/np_error_code.h>

#include <core/nc_version.h>
#include <core/nc_udp_dispatch.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <string.h>

#include <stdio.h>

#include <nn/llist.h>

#define LOG NABTO_LOG_MODULE_DTLS_CLI
#define DEBUG_LEVEL 0

const char* allowedCipherSuitesList = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM";

struct np_dtls_cli_context {
    struct np_platform* pl;
    enum sslState state;

    // Ciphertext datagram recvBuffer temporary variable.
    uint8_t* recvBuffer;
    size_t recvBufferSize;

    // Allocated when sending a packet with ciphertext through the UDP layer.
    struct np_communication_buffer* sslSendBuffer;

    struct nm_wolfssl_timer timer;

    uint32_t recvCount;
    uint32_t sentCount;

    struct nn_llist sendList;
    struct np_event* startSendEvent;

    bool receiving;
    bool destroyed;

    np_dtls_cli_sender sender;
    np_dtls_cli_data_handler dataHandler;
    np_dtls_cli_event_handler eventHandler;
    void* callbackData;

    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;

};

static const char* alpnList = NABTO_PROTOCOL_VERSION;

static np_error_code nm_wolfssl_cli_create(struct np_platform* pl, struct np_dtls_cli_context** client,
                                        np_dtls_cli_sender packetSender, np_dtls_cli_data_handler dataHandler,
                                        np_dtls_cli_event_handler eventHandler, void* data);
static void nm_wolfssl_cli_destroy(struct np_dtls_cli_context* connection);

static np_error_code nm_wolfssl_cli_set_sni(struct np_dtls_cli_context* ctx, const char* sniName);
static np_error_code nm_wolfssl_cli_set_keys(struct np_dtls_cli_context* ctx,
                                          const unsigned char* certificate, size_t certificateSize,
                                          const unsigned char* privateKeyL, size_t privateKeySize);

static np_error_code nm_wolfssl_cli_set_root_certs(struct np_dtls_cli_context* ctx, const char* rootCerts);
static np_error_code nm_wolfssl_cli_disable_certificate_validation(struct np_dtls_cli_context* ctx);

static np_error_code async_send_data(struct np_dtls_cli_context* ctx,
                                     struct np_dtls_cli_send_context* sendCtx);

static np_error_code dtls_cli_close(struct np_dtls_cli_context* ctx);

static np_error_code get_fingerprint(struct np_dtls_cli_context* ctx, uint8_t* fp);

static np_error_code set_handshake_timeout(struct np_dtls_cli_context* ctx, uint32_t minTimeout, uint32_t maxTimeout);

static void nm_dtls_timed_event_do_one(void* data);
static np_error_code dtls_cli_init_connection(struct np_dtls_cli_context* ctx);
static np_error_code nm_wolfssl_cli_reset(struct np_dtls_cli_context* ctx);
static np_error_code nm_dtls_connect(struct np_dtls_cli_context* ctx);

// Function called by wolfssl when data should be sent to the network
int nm_dtls_wolfssl_send(WOLFSSL* ssl, char* buffer, int bufferSize, void* userData);
// Function called by wolfssl when it wants data from the network
int nm_dtls_wolfssl_recv(WOLFSSL* ssl, char* buffer, int bufferSize, void* userData);
// Function used to handle events during the connection phase
void nm_dtls_event_do_one(void* data);

void nm_wolfssl_cli_remove_send_data(struct np_dtls_cli_send_context* elm);

// Handle packet from udp
static np_error_code handle_packet(struct np_dtls_cli_context* ctx,
                                   uint8_t* buffer, uint16_t bufferSize);

void nm_wolfssl_cli_start_send_deferred(void* data);

void nm_dtls_do_close(void* data, np_error_code ec);

// setup function for the wolfssl context
np_error_code nm_dtls_setup_dtls_ctx(struct np_dtls_cli_context* ctx);

void nm_wolfssl_cli_do_free(struct np_dtls_cli_context* ctx);

// Get the packet counters for given dtls_cli_context
np_error_code nm_dtls_get_packet_count(struct np_dtls_cli_context* ctx, uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = ctx->recvCount;
    *sentCount = ctx->sentCount;
    return NABTO_EC_OK;
}

// Get the result of the application layer protocol negotiation
// TODO: remove this function here, in platform, in mbedtls
const char*  nm_dtls_get_alpn_protocol(struct np_dtls_cli_context* ctx) {
    return NULL;
}

static void logging_callback(const int logLevel, const char *const logMessage)
{
    uint32_t severity;
    switch (logLevel) {
        case 0:
            severity = NABTO_LOG_SEVERITY_ERROR;
            break;
        case 1:
            severity = NABTO_LOG_SEVERITY_INFO;
            break;
        default:
            severity = NABTO_LOG_SEVERITY_TRACE;
            break;
    }
    NABTO_LOG_RAW(severity, LOG, 0, "", logMessage)
}

/*
 * Initialize the np_platform to use this particular dtls cli module
 */
np_error_code nm_wolfssl_cli_init(struct np_platform* pl)
{
    pl->dtlsC.create = &nm_wolfssl_cli_create;
    pl->dtlsC.destroy = &nm_wolfssl_cli_destroy;
    pl->dtlsC.set_sni = &nm_wolfssl_cli_set_sni;
    pl->dtlsC.set_keys = &nm_wolfssl_cli_set_keys;
    pl->dtlsC.set_root_certs = &nm_wolfssl_cli_set_root_certs;
    pl->dtlsC.disable_certificate_validation = &nm_wolfssl_cli_disable_certificate_validation;
    pl->dtlsC.connect = &nm_dtls_connect;
    pl->dtlsC.reset = &nm_wolfssl_cli_reset;
    pl->dtlsC.async_send_data = &async_send_data;
    pl->dtlsC.close = &dtls_cli_close;
    pl->dtlsC.get_fingerprint = &get_fingerprint;
    pl->dtlsC.set_handshake_timeout = &set_handshake_timeout;
    pl->dtlsC.get_alpn_protocol = &nm_dtls_get_alpn_protocol;
    pl->dtlsC.get_packet_count = &nm_dtls_get_packet_count;
    pl->dtlsC.handle_packet = &handle_packet;

    return NABTO_EC_OK;
}

np_error_code nm_wolfssl_cli_create(struct np_platform* pl, struct np_dtls_cli_context** client,
                                 np_dtls_cli_sender packetSender, np_dtls_cli_data_handler dataHandler,
                                 np_dtls_cli_event_handler eventHandler, void* data)
{
    *client = NULL;
    struct np_dtls_cli_context* ctx = np_calloc(1, sizeof(struct np_dtls_cli_context));
    if (ctx == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->pl = pl;

    WOLFSSL_METHOD *method = wolfDTLSv1_2_client_method();
    ctx->ctx = wolfSSL_CTX_new(method);

// TODO: maybe not always have logging on
    wolfSSL_SetLoggingCb(logging_callback);
    wolfSSL_Debugging_ON();


    // wolfssl_ssl_init( &ctx->ssl );
    // wolfssl_ssl_config_init( &ctx->conf );
    // wolfssl_ctr_drbg_init( &ctx->ctr_drbg );
    // wolfssl_entropy_init( &ctx->entropy );
    // WOLFSSL_X509_init( &ctx->publicKey );
    // wolfssl_pk_init( &ctx->privateKey );
    // WOLFSSL_X509_init(&ctx->rootCerts);

    ctx->sender = packetSender;
    ctx->dataHandler = dataHandler;
    ctx->eventHandler = eventHandler;
    ctx->callbackData = data;

    nn_llist_init(&ctx->sendList);
    ctx->destroyed = false;

    np_error_code ec = dtls_cli_init_connection(ctx);
    if (ec != NABTO_EC_OK) {
        nm_wolfssl_cli_do_free(ctx);
        return ec;
    }


    ctx->ssl = wolfSSL_new(ctx->ctx);
    if (ctx->ssl == NULL) {
        NABTO_LOG_ERROR(LOG,  "Failed  to create wolfSSL object");
        nm_wolfssl_cli_do_free(ctx);
        return NABTO_EC_UNKNOWN;
    }

    // wolfSSL_SSLSetIORecv(ctx->ssl, nm_dtls_wolfssl_recv);
    // wolfSSL_SSLSetIOSend(ctx->ssl, nm_dtls_wolfssl_send);
    wolfSSL_SetIOReadCtx(ctx->ssl, ctx);
    wolfSSL_SetIOWriteCtx(ctx->ssl, ctx);

    if (wolfSSL_UseALPN(ctx->ssl, (char *)(alpnList), strlen(alpnList), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
    {
        NABTO_LOG_ERROR(LOG, "cannot set alpn list");
        return NABTO_EC_FAILED;
    }


    ec = np_event_queue_create_event(&pl->eq, &nm_wolfssl_cli_start_send_deferred, ctx, &ctx->startSendEvent);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    *client = ctx;
    return NABTO_EC_OK;
}

np_error_code dtls_cli_init_connection(struct np_dtls_cli_context* ctx)
{
    np_error_code ec;
    ec = nm_wolfssl_timer_init(&ctx->timer, ctx->pl, &nm_dtls_timed_event_do_one, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    //int ret;
    //const char *pers = "dtls_client";

    // if( ( ret = wolfssl_ctr_drbg_seed( &ctx->ctr_drbg, wolfssl_entropy_func, &ctx->entropy,
    //                            (const unsigned char *) pers,
    //                            strlen( pers ) ) ) != 0 ) {
    //     NABTO_LOG_INFO(LOG,  " failed  ! wolfssl_ctr_drbg_seed returned %d", ret );
    //     return NABTO_EC_UNKNOWN;
    // }

    // if( ( ret = wolfssl_ssl_config_defaults( &ctx->conf,
    //                wolfssl_SSL_IS_CLIENT,
    //                wolfssl_SSL_TRANSPORT_DATAGRAM,
    //                wolfssl_SSL_PRESET_DEFAULT ) ) != 0 )
    // {
    //     NABTO_LOG_INFO(LOG,  " failed  ! wolfssl_ssl_config_defaults returned %d", ret );
    //     return NABTO_EC_UNKNOWN;
    // }

    if (wolfSSL_CTX_set_cipher_list(ctx->ctx, allowedCipherSuitesList) != WOLFSSL_SUCCESS)
    {
        NABTO_LOG_ERROR(LOG, "server can't set custom cipher list");
        return NABTO_EC_FAILED;
    }

    wolfSSL_CTX_set_verify(ctx->ctx, (WOLFSSL_VERIFY_PEER), NULL);

// #if defined(wolfssl_DEBUG_C)
//     wolfssl_ssl_conf_dbg( &ctx->conf, my_debug, NULL);
// #endif

    wolfSSL_CTX_SetIORecv(ctx->ctx, nm_dtls_wolfssl_recv);
    wolfSSL_CTX_SetIOSend(ctx->ctx, nm_dtls_wolfssl_send);


    // TODO handle timeouts
    // wolfssl_ssl_set_timer_cb( &ctx->ssl,
    //                           &ctx->timer,
    //                           &nm_wolfssl_timer_set_delay,
    //                           &nm_wolfssl_timer_get_delay );
    return NABTO_EC_OK;
}

np_error_code nm_wolfssl_cli_reset(struct np_dtls_cli_context* ctx)
{
    //wolfssl_ssl_session_reset( &ctx->ssl );
    // remove the first element until the list is empty

    while(!nn_llist_empty(&ctx->sendList)) {
        struct nn_llist_iterator it = nn_llist_begin(&ctx->sendList);
        struct np_dtls_cli_send_context* first = nn_llist_get_item(&it);
        nn_llist_erase(&it);
        first->cb(NABTO_EC_CONNECTION_CLOSING, first->data);
    }
    ctx->recvBufferSize = 0;

    nm_wolfssl_timer_cancel(&ctx->timer);
    return NABTO_EC_OK;
}

void nm_wolfssl_cli_do_free(struct np_dtls_cli_context* ctx)
{
    // remove the first element until the list is empty
    while(!nn_llist_empty(&ctx->sendList)) {
        struct nn_llist_iterator it = nn_llist_begin(&ctx->sendList);
        struct np_dtls_cli_send_context* first = nn_llist_get_item(&it);
        nn_llist_erase(&it);
        first->cb(NABTO_EC_CONNECTION_CLOSING, first->data);
    }

    nm_wolfssl_timer_cancel(&ctx->timer);
    np_event_queue_destroy_event(&ctx->pl->eq, ctx->startSendEvent);
    nm_wolfssl_timer_deinit(&ctx->timer);

    //WOLFSSL_X509_free(&ctx->rootCerts);
    //wolfssl_pk_free(&ctx->privateKey);
    //WOLFSSL_X509_free(&ctx->publicKey );
    //wolfssl_entropy_free( &ctx->entropy );
    //wolfssl_ctr_drbg_free( &ctx->ctr_drbg );
    wolfSSL_free(ctx->ssl);
    wolfSSL_CTX_free(ctx->ctx);

    np_free(ctx);
}

void nm_wolfssl_cli_destroy(struct np_dtls_cli_context* ctx)
{
    ctx->state = CLOSING;
    ctx->destroyed = true;

    if (ctx->sslSendBuffer == NULL && !ctx->receiving) {
        nm_wolfssl_cli_do_free(ctx);
    }
}

np_error_code nm_wolfssl_cli_set_sni(struct np_dtls_cli_context* ctx, const char* sniName)
{
    if(wolfSSL_UseSNI(ctx->ssl, WOLFSSL_SNI_HOST_NAME, sniName, strlen(sniName) ) != WOLFSSL_SUCCESS )
    {
        NABTO_LOG_INFO(LOG,  "Failed to set SNI Hostname in the DTLS client");
        return NABTO_EC_UNKNOWN;
    }
    return NABTO_EC_OK;
}

np_error_code nm_wolfssl_cli_set_keys(struct np_dtls_cli_context* ctx,
                                   const unsigned char* certificate, size_t certificateSize,
                                   const unsigned char* privateKeyL, size_t privateKeySize)
{
    if (wolfSSL_use_PrivateKey_buffer(ctx->ssl, privateKeyL, privateKeySize, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        NABTO_LOG_ERROR(LOG, "wolfSSL_CTX_use_PrivateKey_buffer");
        return NABTO_EC_UNKNOWN;
    }

    int r = wolfSSL_use_certificate_buffer(ctx->ssl, certificate, certificateSize, WOLFSSL_FILETYPE_PEM);
    if (r != WOLFSSL_SUCCESS) {
        NABTO_LOG_ERROR(LOG, "wolfSSL_CTX_use_certificate_buffer, %d", r);
        NABTO_LOG_ERROR(LOG, "%s", privateKeyL);
        return NABTO_EC_UNKNOWN;
    }

    return NABTO_EC_OK;
}

np_error_code nm_wolfssl_cli_set_root_certs(struct np_dtls_cli_context* ctx, const char* rootCerts)
{

    if (wolfSSL_CTX_load_verify_buffer(ctx->ctx, (const unsigned char*)rootCerts, strlen(rootCerts), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
    {
        NABTO_LOG_ERROR(LOG, "cannot load ca certificate");
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;
}

np_error_code nm_wolfssl_cli_disable_certificate_validation(struct np_dtls_cli_context* ctx)
{
    wolfSSL_CTX_set_verify(ctx->ctx, (SSL_VERIFY_NONE), NULL);
    return NABTO_EC_OK;
}

/**
 * get peers fingerprint for given DTLS client context
 */
np_error_code get_fingerprint(struct np_dtls_cli_context* ctx, uint8_t* fp)
{
    // Get client fingerprint
    WOLFSSL_X509 *crt = wolfSSL_get_peer_certificate(ctx->ssl);
    if (!crt) {
        return NABTO_EC_UNKNOWN;
    }
    return nm_wolfssl_util_fp_from_crt(crt, fp);
}

np_error_code set_handshake_timeout(struct np_dtls_cli_context* ctx, uint32_t minTimeout, uint32_t maxTimeout)
{
    if (wolfSSL_dtls_set_timeout_init(ctx->ssl, (int)minTimeout) != WOLFSSL_SUCCESS) {
        NABTO_LOG_ERROR(LOG, "Cannot set min timeout for DTLS client connection");
        return NABTO_EC_FAILED;
    };
    if (wolfSSL_dtls_set_timeout_max(ctx->ssl, (int)maxTimeout) != WOLFSSL_SUCCESS) {
        NABTO_LOG_ERROR(LOG, "Cannot set max timeout for DTLS client connection");
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;
}

/*
 * asyncroniously start a dtls connection
 */
np_error_code nm_dtls_connect(struct np_dtls_cli_context* ctx)
{
    ctx->state = CONNECTING;

    nm_dtls_event_do_one(ctx);
    return NABTO_EC_OK;
}

/*
 * Handle events for the connection phase
 */
void nm_dtls_event_do_one(void* data)
{
    struct np_dtls_cli_context* ctx = data;
    int ret;
    if(ctx->state == CONNECTING) {
        ret = wolfSSL_connect(ctx->ssl);
        if (ret != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ctx->ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ ||
                err == WOLFSSL_ERROR_WANT_WRITE){
                // Wait for IO to happen
                // TODO remove log
                NABTO_LOG_ERROR(LOG, "WANT_READ/WRITE");
            } else {
                enum np_dtls_cli_event event = NP_DTLS_CLI_EVENT_CLOSED;
        // TODO handle access denied
        // else if (ret == wolfssl_ERR_SSL_FATAL_ALERT_MESSAGE &&
        //            ctx->ssl.in_msg[1] == wolfssl_SSL_ALERT_MSG_ACCESS_DENIED)
        // {
        //     ctx->state = CLOSING;
        //     nm_wolfssl_timer_cancel(&ctx->timer);
        //     ctx->eventHandler(NP_DTLS_CLI_EVENT_ACCESS_DENIED,
        //     ctx->callbackData); return;
        // }
                // TODO detect certificate validation errors
                // if (ret == wolfssl_ERR_X509_CERT_VERIFY_FAILED) {
                //     char info[128];
                //     uint32_t validationStatus = wolfssl_ssl_get_verify_result(&ctx->ssl);
                //     WOLFSSL_X509_verify_info(info, 128, "", validationStatus);
                //     NABTO_LOG_ERROR(LOG, "Certificate verification failed %s", info);
                //     event = NP_DTLS_CLI_EVENT_CERTIFICATE_VERIFICATION_FAILED;
                // } else {
                char buf[80];
                wolfSSL_ERR_error_string(err, buf);
                NABTO_LOG_INFO(
                    LOG, "wolfssl_connect returned %d, which is %d, %s", ret , err, buf);
                //}
                ctx->state = CLOSING;
                nm_wolfssl_timer_cancel(&ctx->timer);
                ctx->eventHandler(event, ctx->callbackData);
                return;
            }
        } else {
            char* protocol_name;
            word16 protocol_nameSz = 0;
            if (wolfSSL_ALPN_GetProtocol(ctx->ssl, &protocol_name, &protocol_nameSz) != SSL_SUCCESS) {
                NABTO_LOG_ERROR(LOG, "Application Layer Protocol Negotiation failed for DTLS client connection");
                ctx->state = CLOSING;
                nm_dtls_do_close(ctx, NABTO_EC_ALPN_FAILED);
                return;
            }
            NABTO_LOG_TRACE(LOG, "State changed to DATA");
            ctx->state = DATA;
            ctx->eventHandler(NP_DTLS_CLI_EVENT_HANDSHAKE_COMPLETE, ctx->callbackData);

        }
    } else if(ctx->state == DATA) {
        uint8_t recvBuffer[1500];
        ret = wolfSSL_read( ctx->ssl, recvBuffer, (int)sizeof(recvBuffer) );
        if (ret == 0) {
            // EOF
            ctx->state = CLOSING;
            NABTO_LOG_TRACE(LOG, "Received EOF, state = CLOSING");
        } else if (ret > 0) {
            ctx->recvCount++;

            ctx->dataHandler(recvBuffer, (uint16_t)ret, ctx->callbackData);
            return;
        }else if (ret == WOLFSSL_ERROR_WANT_READ ||
                  ret == WOLFSSL_ERROR_WANT_WRITE)
        {
            // OK
        }
        // TODO handle access denied
        // } else if (ret == wolfssl_ERR_SSL_FATAL_ALERT_MESSAGE &&
        //            ctx->ssl.in_msg[1] == wolfssl_SSL_ALERT_MSG_ACCESS_DENIED)
        // {
        //     nm_wolfssl_timer_cancel(&ctx->timer);
        //     ctx->eventHandler(NP_DTLS_CLI_EVENT_ACCESS_DENIED, ctx->callbackData);
        //     return;
        // } else
        else {
#if defined(wolfssl_ERROR_C)
            char buf[128];
            wolfssl_strerror(ret, buf, 128);
            NABTO_LOG_TRACE(LOG, "Received ERROR -0x%04x : %s ", -ret, buf);
#endif
            ctx->state = CLOSING;
            nm_dtls_do_close(ctx, NABTO_EC_UNKNOWN);
        }
        return;
    }
}

void nm_wolfssl_cli_start_send(struct np_dtls_cli_context* ctx)
{
    np_event_queue_post_maybe_double(&ctx->pl->eq, ctx->startSendEvent);
}

void nm_wolfssl_cli_start_send_deferred(void* data)
{
    struct np_dtls_cli_context* ctx = data;
    if (ctx->state == CLOSING) {
        return;
    }
    if (ctx->sslSendBuffer != NULL) {
        return;
    }

    if (nn_llist_empty(&ctx->sendList)) {
        // empty send queue
        return;
    }

    struct nn_llist_iterator it = nn_llist_begin(&ctx->sendList);
    struct np_dtls_cli_send_context* next = nn_llist_get_item(&it);
    nn_llist_erase(&it);

    int ret = wolfSSL_write( ctx->ssl, (unsigned char *) next->buffer, next->bufferSize );
    if (next->cb == NULL) {
        ctx->sentCount++;
    }
        // TODO handle bad input data
    // } else if (ret == wolfssl_ERR_SSL_BAD_INPUT_DATA) {
    //     // packet too large
    //     NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i (Packet too large)", ret);
    //     next->cb(NABTO_EC_MALFORMED_PACKET, next->data);
    else if (ret < 0) {
        // unknown error
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i", ret);
        next->cb(NABTO_EC_UNKNOWN, next->data);
    } else {
        ctx->sentCount++;
        next->cb(NABTO_EC_OK, next->data);
    }

    // can we send more packets?
    nm_wolfssl_cli_start_send(ctx);
}


np_error_code async_send_data(struct np_dtls_cli_context* ctx,
                              struct np_dtls_cli_send_context* sendCtx)
{
    if (ctx->state == CLOSING) {
        return NABTO_EC_CONNECTION_CLOSING;
    }
    if (ctx->state != DATA) {
        return NABTO_EC_INVALID_STATE;
    }
    nn_llist_append(&ctx->sendList, &sendCtx->sendListNode, sendCtx);
    nm_wolfssl_cli_start_send(ctx);
    return NABTO_EC_OK;
}

void nm_dtls_do_close(void* data, np_error_code ec){
    (void)ec;
    struct np_dtls_cli_context* ctx = data;
    NABTO_LOG_TRACE(LOG, "Closing DTLS Client Connection");
    nm_wolfssl_timer_cancel(&ctx->timer);
    ctx->eventHandler(NP_DTLS_CLI_EVENT_CLOSED, ctx->callbackData);
}

np_error_code dtls_cli_close(struct np_dtls_cli_context* ctx)
{
    if (!ctx ) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    if ( ctx->state != CLOSING) {
        NABTO_LOG_TRACE(LOG, "Closing DTLS cli from state: %u", ctx->state);
        ctx->state = CLOSING;
        wolfSSL_shutdown(ctx->ssl);
        if (ctx->sslSendBuffer == NULL) {
            nm_dtls_do_close(ctx, /*unused*/ NABTO_EC_OK);
        }
    } else {
        NABTO_LOG_TRACE(LOG, "Tried Closing DTLS cli but was already closed");
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
    if (ctx->destroyed && ctx->sslSendBuffer == NULL) {
        nm_wolfssl_cli_do_free(ctx);
    }
    return NABTO_EC_OK;
}

void nm_dtls_udp_send_callback(const np_error_code ec, void* data)
{
    (void)ec;
    struct np_dtls_cli_context* ctx = data;
    if (data == NULL) {
        return;
    }

    ctx->pl->buf.free(ctx->sslSendBuffer);
    ctx->sslSendBuffer = NULL;

    if (ctx->state == CLOSING) {
        NABTO_LOG_TRACE(LOG, "udp send cb after close");
    }
    if(ctx->state == CLOSING) {
        nm_dtls_do_close(ctx, /* ec unused */NABTO_EC_OK);
        if (ctx->destroyed) {
            nm_wolfssl_cli_do_free(ctx);
        }
        return;
    }
    nm_dtls_event_do_one(data);
}

int nm_dtls_wolfssl_send(WOLFSSL* ssl, char* buffer,
                         int bufferSize, void* data)
{
    struct np_dtls_cli_context* ctx = data;
    struct np_platform* pl = ctx->pl;
    if (ctx->state == CLOSING) {
        NABTO_LOG_TRACE(LOG, "wolfssl want send after close");
    }
    if (ctx->sslSendBuffer == NULL) {
        ctx->sslSendBuffer = pl->buf.allocate();
        if (ctx->sslSendBuffer == NULL) {
            NABTO_LOG_ERROR(LOG,
                            "Cannot allocate a buffer for sending a packet "
                            "from the dtls client. Dropping the packet");
            // dropping the packet as there is no way to trigger a
            // retransmission of the packet once the system has available memory
            // again.
            return (int)bufferSize;
        }
        memcpy(ctx->pl->buf.start(ctx->sslSendBuffer), buffer, bufferSize);
        np_error_code ec =
            ctx->sender(pl->buf.start(ctx->sslSendBuffer), (uint16_t)bufferSize,
                        &nm_dtls_udp_send_callback, ctx, ctx->callbackData);
        if (ec != NABTO_EC_OK) {
            NABTO_LOG_ERROR(LOG,"DTLS sender failed with error: %d", ec);
            pl->buf.free(ctx->sslSendBuffer);
            ctx->sslSendBuffer = NULL;
            if (ctx->state == CLOSING) {
                nm_dtls_do_close(ctx, /* ec unused */ NABTO_EC_OK);
                if (ctx->destroyed) {
                    nm_wolfssl_cli_do_free(ctx);
                }
            }
            // dropping the packet as there is no way to trigger a
            // retransmission of the data.
            return (int)bufferSize;
        }
        return (int)bufferSize;
    } else {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
}

int nm_dtls_wolfssl_recv(WOLFSSL* ssl, char* buffer, int bufferSize, void* data)
{
    struct np_dtls_cli_context* ctx = data;
    if (ctx->recvBufferSize == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    } else {
        size_t maxCp = bufferSize > ctx->recvBufferSize ? ctx->recvBufferSize : bufferSize;
        memcpy(buffer, ctx->recvBuffer, maxCp);
        ctx->recvBufferSize = 0;
        return (int)maxCp;
    }
}

void nm_dtls_timed_event_do_one(void* data) {
    struct np_dtls_cli_context* ctx = data;
    if (ctx->state == CLOSING) {
        return;
    }
    nm_dtls_event_do_one(data);
}
