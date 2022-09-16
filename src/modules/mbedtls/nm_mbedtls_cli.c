#include "nm_mbedtls_cli.h"
#include "nm_mbedtls_util.h"
#include "nm_mbedtls_timer.h"
#include "nm_mbedtls_common.h"

#include <platform/np_logging.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_allocator.h>

#include <core/nc_version.h>
#include <core/nc_udp_dispatch.h>

#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/timing.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/pem.h>

#include <string.h>

#include <stdio.h>

#include <nn/llist.h>

/******** definitions and constants *******/

#define LOG NABTO_LOG_MODULE_DTLS_CLI

const int allowedCipherSuitesList[] = { MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM, 0 };

struct nm_mbedtls_cli_context {
    struct np_platform* pl;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config clientsConf;
    mbedtls_ssl_config attachConf;
    mbedtls_x509_crt rootCerts;
    mbedtls_x509_crt publicKey;
    mbedtls_pk_context privateKey;

    int timeoutMin;
    int timeoutMax;
};

struct np_dtls_cli_connection {
    struct np_platform* pl;
    enum sslState state;

    // Ciphertext datagram recvBuffer temporary variable.
    uint8_t* recvBuffer;
    size_t recvBufferSize;
    uint8_t recvChannelId;

    // Allocated when sending a packet with ciphertext through the UDP layer.
    struct np_communication_buffer* sslSendBuffer;

    struct nm_mbedtls_timer timer;

    uint32_t recvCount;
    uint32_t sentCount;

    struct nn_llist sendList;
    struct np_event* startSendEvent;

    struct np_completion_event senderEvent;
    uint8_t sendChannelId;

    bool receiving;
    bool destroyed;

    np_dtls_sender sender;
    np_dtls_data_handler dataHandler;
    np_dtls_event_handler eventHandler;
    void* callbackData;

    mbedtls_ssl_context ssl;

};

const char* nm_mbedtls_cli_alpnList[] = {NABTO_PROTOCOL_VERSION , NULL};

/******** Module function definitions *******/
static np_error_code create_attach_connection(
    struct np_platform* pl, struct np_dtls_cli_connection** conn,
    const char* sni, bool disable_cert_validation,
    np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
    np_dtls_event_handler eventHandler, void* data);
static np_error_code create_client_connection(
    struct np_platform* pl, struct np_dtls_cli_connection** conn,
    np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
    np_dtls_event_handler eventHandler, void* data);


static void destroy_connection(struct np_dtls_cli_connection* conn);

static np_error_code set_keys(struct np_platform* pl,
                              const unsigned char* certificate,
                              size_t certificateSize,
                              const unsigned char* privateKeyL,
                              size_t privateKeySize);
static np_error_code set_handshake_timeout(struct np_platform* pl,
                                           uint32_t minTimeout,
                                           uint32_t maxTimeout);

static np_error_code set_root_certs(struct np_platform* pl, const char* rootCerts);

static np_error_code dtls_connect(struct np_dtls_cli_connection* conn);
static np_error_code async_send_data(struct np_dtls_cli_connection* conn,
                                     struct np_dtls_send_context* sendCtx);

static np_error_code handle_packet(struct np_dtls_cli_connection* conn,
                                   uint8_t channelId, uint8_t* buffer,
                                   uint16_t bufferSize);
static np_error_code async_close(struct np_dtls_cli_connection* conn);

static np_error_code get_fingerprint(struct np_dtls_cli_connection* conn,
                                     uint8_t* fp);
static const char* get_alpn_protocol(struct np_dtls_cli_connection* conn);
static np_error_code get_packet_count(struct np_dtls_cli_connection* conn,
                                      uint32_t* recvCount, uint32_t* sentCount);



/******** Internal function definitions *******/
static np_error_code initialize_context(struct np_platform* pl);
static np_error_code init_mbedtls_config(struct nm_mbedtls_cli_context *ctx, mbedtls_ssl_config *conf);
static np_error_code create_connection(struct np_platform *pl, struct np_dtls_cli_connection **connection,
                                       np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
                                       np_dtls_event_handler eventHandler, void *data);
static void do_free_connection(struct np_dtls_cli_connection* conn);
static void event_do_one(void *data);
static void nm_dtls_do_close(void* data, np_error_code ec);
static void start_send(struct np_dtls_cli_connection *conn);
static void start_send_deferred(void *data);
static void dtls_udp_send_callback(const np_error_code ec, void *data);
static uint64_t uint64_from_bigendian(uint8_t *bytes);
static int nm_dtls_mbedtls_send(void *data, const unsigned char *buffer, size_t bufferSize);
static int nm_dtls_mbedtls_recv(void *data, unsigned char *buffer, size_t bufferSize);
static void nm_dtls_timed_event_do_one(void *data);

/*
 * Initialize the np_platform to use this particular dtls cli module
 */
np_error_code nm_mbedtls_cli_init(struct np_platform* pl)
{
    pl->dtlsC.create_attach_connection = &create_attach_connection;
    pl->dtlsC.create_client_connection = &create_client_connection;
    pl->dtlsC.destroy_connection = &destroy_connection;
    pl->dtlsC.set_keys = &set_keys;
    pl->dtlsC.set_handshake_timeout = &set_handshake_timeout;
    pl->dtlsC.set_root_certs = &set_root_certs;
    pl->dtlsC.connect = &dtls_connect;
    pl->dtlsC.async_send_data = &async_send_data;
    pl->dtlsC.handle_packet = &handle_packet;
    pl->dtlsC.async_close = &async_close;
    pl->dtlsC.get_fingerprint = &get_fingerprint;
    pl->dtlsC.get_alpn_protocol = &get_alpn_protocol;
    pl->dtlsC.get_packet_count = &get_packet_count;

    return initialize_context(pl);
}

void nm_mbedtls_cli_deinit(struct np_platform* pl)
{
    struct nm_mbedtls_cli_context* ctx =
        (struct nm_mbedtls_cli_context*)pl->dtlsCData;
    mbedtls_x509_crt_free(&ctx->rootCerts);
    mbedtls_pk_free(&ctx->privateKey);
    mbedtls_x509_crt_free(&ctx->publicKey );
    mbedtls_entropy_free( &ctx->entropy );
    mbedtls_ctr_drbg_free( &ctx->ctr_drbg );
    mbedtls_ssl_config_free( &ctx->clientsConf );
    mbedtls_ssl_config_free( &ctx->attachConf );

    np_free(ctx);
}

np_error_code init_mbedtls_config(struct nm_mbedtls_cli_context* ctx, mbedtls_ssl_config* conf)
{
    int ret;
    if ((ret = mbedtls_ssl_config_defaults(conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_config_defaults returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }

    mbedtls_ssl_conf_ciphersuites(conf,
                                  allowedCipherSuitesList);

    mbedtls_ssl_conf_alpn_protocols(conf, nm_mbedtls_cli_alpnList );
    mbedtls_ssl_conf_rng( conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg );

    nm_mbedtls_util_check_logging(conf);
    mbedtls_ssl_conf_ca_chain(conf, &ctx->rootCerts, NULL);
    return NABTO_EC_OK;
}

np_error_code initialize_context(struct np_platform* pl)
{
    struct nm_mbedtls_cli_context* ctx =
        np_calloc(1, sizeof(struct nm_mbedtls_cli_context));
    if (ctx == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    pl->dtlsCData = ctx;
    ctx->pl = pl;
    mbedtls_ssl_config_init( &ctx->clientsConf );
    mbedtls_ssl_config_init( &ctx->attachConf );
    mbedtls_ctr_drbg_init( &ctx->ctr_drbg );
    mbedtls_entropy_init( &ctx->entropy );
    mbedtls_x509_crt_init( &ctx->publicKey );
    mbedtls_pk_init( &ctx->privateKey );
    mbedtls_x509_crt_init(&ctx->rootCerts);

    int ret;
    const char *pers = "dtls_client";

    if( ( ret = mbedtls_ctr_drbg_seed( &ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 ) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ctr_drbg_seed returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }

    np_error_code ec = NABTO_EC_OK;
    if ((ec = init_mbedtls_config(ctx, &ctx->clientsConf)) != NABTO_EC_OK)
    {
        return ec;
    }
    mbedtls_ssl_conf_authmode( &ctx->clientsConf, MBEDTLS_SSL_VERIFY_OPTIONAL );

    if ((ec = init_mbedtls_config(ctx, &ctx->attachConf)) != NABTO_EC_OK)
    {
        return ec;
    }
    mbedtls_ssl_conf_authmode( &ctx->attachConf, MBEDTLS_SSL_VERIFY_REQUIRED );

    return NABTO_EC_OK;

}

np_error_code create_connection(struct np_platform* pl, struct np_dtls_cli_connection** connection,
    np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
    np_dtls_event_handler eventHandler, void* data)
{
    struct nm_mbedtls_cli_context* ctx = (struct nm_mbedtls_cli_context*)pl->dtlsCData;
    if (ctx == NULL) {
        return NABTO_EC_INVALID_STATE;
    }

    *connection = NULL;
    struct np_dtls_cli_connection* conn = np_calloc(1, sizeof(struct np_dtls_cli_connection));
    if (conn == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    conn->pl = pl;
    mbedtls_ssl_init( &conn->ssl );
    conn->sender = packetSender;
    conn->dataHandler = dataHandler;
    conn->eventHandler = eventHandler;
    conn->callbackData = data;
    conn->recvChannelId = NP_DTLS_DEFAULT_CHANNEL_ID;
    conn->sendChannelId = NP_DTLS_DEFAULT_CHANNEL_ID;

    nn_llist_init(&conn->sendList);
    conn->destroyed = false;

    np_error_code ec = nm_mbedtls_timer_init(&conn->timer, conn->pl, &nm_dtls_timed_event_do_one, conn);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(&pl->eq, &conn->senderEvent,
                                  &dtls_udp_send_callback, conn);

    mbedtls_ssl_set_bio( &conn->ssl, conn,
                         nm_dtls_mbedtls_send, nm_dtls_mbedtls_recv, NULL );

    mbedtls_ssl_set_timer_cb( &conn->ssl,
                              &conn->timer,
                              &nm_mbedtls_timer_set_delay,
                              &nm_mbedtls_timer_get_delay );

    ec = np_event_queue_create_event(&pl->eq, &start_send_deferred, conn, &conn->startSendEvent);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    *connection = conn;

    return NABTO_EC_OK;
}

static np_error_code create_client_connection(
    struct np_platform* pl, struct np_dtls_cli_connection** connection,
    np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
    np_dtls_event_handler eventHandler, void* data)
{
    np_error_code ec = create_connection(
        pl, connection, packetSender, dataHandler, eventHandler, data);
    if (ec != NABTO_EC_OK) {
        return ec;
    }    int ret;

    struct nm_mbedtls_cli_context* ctx = (struct nm_mbedtls_cli_context*)pl->dtlsCData;

    if( ( ret = mbedtls_ssl_setup( &(*connection)->ssl, &ctx->clientsConf ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_setup returned %d", ret );
        do_free_connection(*connection);
        return NABTO_EC_UNKNOWN;
    }

    return NABTO_EC_OK;
}


static np_error_code create_attach_connection(
    struct np_platform* pl, struct np_dtls_cli_connection** connection,
    const char* sni, bool disable_cert_validation,
    np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
    np_dtls_event_handler eventHandler, void* data)
{
    np_error_code ec = create_connection(
        pl, connection, packetSender, dataHandler, eventHandler, data);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    struct nm_mbedtls_cli_context* ctx = (struct nm_mbedtls_cli_context*)pl->dtlsCData;

    if (disable_cert_validation) {
        mbedtls_ssl_conf_authmode( &ctx->attachConf, MBEDTLS_SSL_VERIFY_NONE );

    }

    int ret;
    if( ( ret = mbedtls_ssl_setup( &(*connection)->ssl, &ctx->attachConf ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_setup returned %d", ret );
        do_free_connection(*connection);
        return NABTO_EC_UNKNOWN;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &(*connection)->ssl, sni ) ) != 0 )
    {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_set_hostname returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }
    return NABTO_EC_OK;
}

np_error_code get_packet_count(struct np_dtls_cli_connection* conn, uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = conn->recvCount;
    *sentCount = conn->sentCount;
    return NABTO_EC_OK;
}

// Get the result of the application layer protocol negotiation
const char*  get_alpn_protocol(struct np_dtls_cli_connection* conn)
{
    return mbedtls_ssl_get_alpn_protocol(&conn->ssl);
}


void destroy_connection(struct np_dtls_cli_connection* conn)
{
    conn->state = CLOSING;
    conn->destroyed = true;
    if (conn->sslSendBuffer == NULL && !conn->receiving) {
        do_free_connection(conn);
    }
}

void do_free_connection(struct np_dtls_cli_connection* conn)
{
    // remove the first element until the list is empty
    while(!nn_llist_empty(&conn->sendList)) {
        struct nn_llist_iterator it = nn_llist_begin(&conn->sendList);
        struct np_dtls_send_context* first = nn_llist_get_item(&it);
        nn_llist_erase(&it);
        np_completion_event_resolve(&first->ev, NABTO_EC_CONNECTION_CLOSING);
    }

    nm_mbedtls_timer_cancel(&conn->timer);
    np_event_queue_destroy_event(&conn->pl->eq, conn->startSendEvent);
    nm_mbedtls_timer_deinit(&conn->timer);
    np_completion_event_deinit(&conn->senderEvent);

    mbedtls_ssl_free( &conn->ssl );

    np_free(conn);
}

np_error_code set_keys(struct np_platform *pl,
                       const unsigned char *publicKeyL, size_t publicKeySize,
                       const unsigned char *privateKeyL, size_t privateKeySize)
{
    struct nm_mbedtls_cli_context* ctx = (struct nm_mbedtls_cli_context*)pl->dtlsCData;
    if (ctx == NULL) {
        return NABTO_EC_INVALID_STATE;
    }
    int ret;
    mbedtls_x509_crt_init( &ctx->publicKey );
    mbedtls_pk_init( &ctx->privateKey );
    ret = mbedtls_x509_crt_parse( &ctx->publicKey, publicKeyL, publicKeySize+1);
    if( ret != 0 ) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_x509_crt_parse returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }
    const unsigned char* p = privateKeyL;
    size_t pLen = privateKeySize + 1;
#if MBEDTLS_VERSION_MAJOR >= 3
    ret =  mbedtls_pk_parse_key( &ctx->privateKey, p, pLen, NULL, 0, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
#else
    ret =  mbedtls_pk_parse_key( &ctx->privateKey, p, pLen, NULL, 0);
#endif
    if( ret != 0 ) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_pk_parse_key returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }

    ret = mbedtls_ssl_conf_own_cert(&ctx->clientsConf, &ctx->publicKey, &ctx->privateKey);
    if (ret != 0) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_conf_own_cert returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }

    ret = mbedtls_ssl_conf_own_cert(&ctx->attachConf, &ctx->publicKey, &ctx->privateKey);
    if (ret != 0) {
        NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_conf_own_cert returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }

    return NABTO_EC_OK;
}

np_error_code set_root_certs(struct np_platform* pl, const char* rootCerts)
{
    struct nm_mbedtls_cli_context* ctx = (struct nm_mbedtls_cli_context*)pl->dtlsCData;
    if (ctx == NULL) {
        return NABTO_EC_INVALID_STATE;
    }
    int ret;
    ret = mbedtls_x509_crt_parse (&ctx->rootCerts, (const unsigned char *)rootCerts, strlen(rootCerts)+1);
    if (ret == MBEDTLS_ERR_PEM_ALLOC_FAILED) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    if (ret != 0) {
        NABTO_LOG_ERROR(LOG,  "Failed to load root certs mbedtls_x509_crt_parse returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }
    return NABTO_EC_OK;
}

/**
 * get peers fingerprint for given DTLS client context
 */
np_error_code get_fingerprint(struct np_dtls_cli_connection* conn, uint8_t* fp)
{
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&conn->ssl);
    if (!crt) {
        return NABTO_EC_UNKNOWN;
    }
    return nm_mbedtls_util_fp_from_crt(crt, fp);
}

np_error_code set_handshake_timeout(struct np_platform* pl, uint32_t minTimeout, uint32_t maxTimeout)
{
    struct nm_mbedtls_cli_context* ctx = (struct nm_mbedtls_cli_context*)pl->dtlsCData;
    if (ctx == NULL) {
        return NABTO_EC_INVALID_STATE;
    }
    mbedtls_ssl_conf_handshake_timeout(&ctx->clientsConf, minTimeout, maxTimeout);
    mbedtls_ssl_conf_handshake_timeout(&ctx->attachConf, minTimeout, maxTimeout);
    return NABTO_EC_OK;
}

/*
 * asyncroniously start a dtls connection
 */
np_error_code dtls_connect(struct np_dtls_cli_connection* conn)
{
    conn->state = CONNECTING;

    event_do_one(conn);
    return NABTO_EC_OK;
}

/*
 * Handle events for the connection phase
 */
void event_do_one(void* data)
{
    struct np_dtls_cli_connection* conn = data;
    int ret;
    if(conn->state == CONNECTING) {
        ret = mbedtls_ssl_handshake( &conn->ssl );
        if( ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
            //Keep State CONNECTING
        } else if (ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE &&
                   conn->ssl.MBEDTLS_PRIVATE(in_msg)[1] == MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED)
        {
            conn->state = CLOSING;
            nm_mbedtls_timer_cancel(&conn->timer);
            conn->eventHandler(NP_DTLS_EVENT_ACCESS_DENIED, conn->callbackData);
            return;
        } else {
            if( ret != 0 )
            {
                enum np_dtls_event event = NP_DTLS_EVENT_CLOSED;
                if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                    char info[128];
                    uint32_t validationStatus = mbedtls_ssl_get_verify_result(&conn->ssl);
                    mbedtls_x509_crt_verify_info(info, 128, "", validationStatus);
                    NABTO_LOG_ERROR(LOG, "Certificate verification failed %s", info);
                    event = NP_DTLS_EVENT_CERTIFICATE_VERIFICATION_FAILED;
                } else {
                    NABTO_LOG_INFO(LOG,  " failed  ! mbedtls_ssl_handshake returned %i", ret );
                }
                conn->state = CLOSING;
                nm_mbedtls_timer_cancel(&conn->timer);
                conn->eventHandler(event, conn->callbackData);
                return;
            } else if (mbedtls_ssl_get_alpn_protocol(&conn->ssl) == NULL) {
                NABTO_LOG_ERROR(LOG, "Application Layer Protocol Negotiation failed for DTLS client connection");
                conn->state = CLOSING;
                nm_mbedtls_timer_cancel(&conn->timer);
                conn->eventHandler(NP_DTLS_EVENT_CLOSED, conn->callbackData);
                return;
            }

            NABTO_LOG_TRACE(LOG, "State changed to DATA");
            conn->state = DATA;
            conn->eventHandler(NP_DTLS_EVENT_HANDSHAKE_COMPLETE, conn->callbackData);
        }
        return;
    } else if(conn->state == DATA) {
        uint8_t recvBuffer[1500];
        ret = mbedtls_ssl_read( &conn->ssl, recvBuffer, sizeof(recvBuffer) );
        if (ret == 0) {
            // EOF
            conn->state = CLOSING;
            NABTO_LOG_TRACE(LOG, "Received EOF, state = CLOSING");
        } else if (ret > 0) {
            conn->recvCount++;
            // TODO: sequence numbers
            uint64_t seq = uint64_from_bigendian(conn->ssl.MBEDTLS_PRIVATE(in_ctr));
            conn->dataHandler(conn->recvChannelId, seq, recvBuffer, (uint16_t)ret, conn->callbackData);
            return;
        }else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                  ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // OK
        } else if (ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE &&
                   conn->ssl.MBEDTLS_PRIVATE(in_msg)[1] == MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED)
        {
            nm_mbedtls_timer_cancel(&conn->timer);
            conn->eventHandler(NP_DTLS_EVENT_ACCESS_DENIED, conn->callbackData);
            return;
        } else {
#if defined(MBEDTLS_ERROR_C)
            char buf[128];
            mbedtls_strerror(ret, buf, 128);
            NABTO_LOG_TRACE(LOG, "Received ERROR -0x%04x : %s ", -ret, buf);
#endif
            conn->state = CLOSING;
            nm_dtls_do_close(conn, NABTO_EC_UNKNOWN);
        }
        return;
    }
}

void nm_dtls_do_close(void* data, np_error_code ec){
    (void)ec;
    struct np_dtls_cli_connection* conn = data;
    NABTO_LOG_TRACE(LOG, "Closing DTLS Client Connection");
    nm_mbedtls_timer_cancel(&conn->timer);
    conn->eventHandler(NP_DTLS_EVENT_CLOSED, conn->callbackData);
}

void start_send(struct np_dtls_cli_connection* conn)
{
    np_event_queue_post_maybe_double(&conn->pl->eq, conn->startSendEvent);
}

void start_send_deferred(void* data)
{
    struct np_dtls_cli_connection* conn = data;
    if (conn->state == CLOSING) {
        return;
    }
    if (conn->sslSendBuffer != NULL) {
        return;
    }

    if (nn_llist_empty(&conn->sendList)) {
        // empty send queue
        return;
    }

    struct nn_llist_iterator it = nn_llist_begin(&conn->sendList);
    struct np_dtls_send_context* next = nn_llist_get_item(&it);
    nn_llist_erase(&it);

    conn->sendChannelId = next->channelId;

    int ret = mbedtls_ssl_write( &conn->ssl, (unsigned char *) next->buffer, next->bufferSize );
    conn->sendChannelId = NP_DTLS_DEFAULT_CHANNEL_ID;

    if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
        // packet too large
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i (Packet too large)", ret);
        np_completion_event_resolve(&next->ev, NABTO_EC_MALFORMED_PACKET);
    } else if (ret < 0) {
        // unknown error
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i", ret);
        np_completion_event_resolve(&next->ev, NABTO_EC_UNKNOWN);
    } else {
        conn->sentCount++;
        np_completion_event_resolve(&next->ev, NABTO_EC_OK);
    }

    // can we send more packets?
    start_send(conn);
}

np_error_code async_send_data(struct np_dtls_cli_connection* conn,
                              struct np_dtls_send_context* sendCtx)
{
    if (conn->state == CLOSING) {
        return NABTO_EC_CONNECTION_CLOSING;
    }
    if (conn->state != DATA) {
        return NABTO_EC_INVALID_STATE;
    }
    nn_llist_append(&conn->sendList, &sendCtx->sendListNode, sendCtx);
    start_send(conn);
    return NABTO_EC_OK;
}

np_error_code async_close(struct np_dtls_cli_connection* conn)
{
    if (!conn ) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    if ( conn->state != CLOSING) {
        NABTO_LOG_TRACE(LOG, "Closing DTLS cli from state: %u", conn->state);
        conn->state = CLOSING;
        mbedtls_ssl_close_notify(&conn->ssl);
        if (conn->sslSendBuffer == NULL) {
            nm_dtls_do_close(conn, /*unused*/ NABTO_EC_OK);
        }
    } else {
        NABTO_LOG_TRACE(LOG, "Tried Closing DTLS cli but was already closed");
    }
    return NABTO_EC_OK;
}

np_error_code handle_packet(struct np_dtls_cli_connection* conn, uint8_t ch,
                            uint8_t* buffer, uint16_t bufferSize)
{
    conn->recvBuffer = buffer;
    conn->recvBufferSize = bufferSize;
    conn->receiving = true;
    conn->recvChannelId = ch;
    event_do_one(conn);
    conn->recvChannelId = NP_DTLS_CLI_DEFAULT_CHANNEL_ID;
    conn->recvBuffer = NULL;
    conn->recvBufferSize = 0;
    conn->receiving = false;
    if (conn->destroyed && conn->sslSendBuffer == NULL) {
        do_free_connection(conn);
    }
    return NABTO_EC_OK;
}

void dtls_udp_send_callback(const np_error_code ec, void* data)
{
    (void)ec;
    struct np_dtls_cli_connection* conn = data;
    if (data == NULL) {
        return;
    }

    if (conn->state == CLOSING) {
        NABTO_LOG_TRACE(LOG, "udp send cb after close");
    }
    conn->pl->buf.free(conn->sslSendBuffer);
    if(conn->state == CLOSING) {
        nm_dtls_do_close(conn, /* ec unused */NABTO_EC_OK);
        conn->sslSendBuffer = NULL;
        if (conn->destroyed) {
            do_free_connection(conn);
        }
        return;
    }
    conn->sslSendBuffer = NULL;
    if (conn->state == DATA) {
        start_send(conn);
    }
    event_do_one(data);
}

uint64_t uint64_from_bigendian( uint8_t* bytes )
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

int nm_dtls_mbedtls_send(void* data, const unsigned char* buffer,
                         size_t bufferSize)
{
    struct np_dtls_cli_connection* conn = data;
    struct np_platform* pl = conn->pl;
    if (conn->state == CLOSING) {
        NABTO_LOG_TRACE(LOG, "mbedtls want send after close");
    }
    if (conn->sslSendBuffer == NULL) {
        conn->sslSendBuffer = pl->buf.allocate();
        if (conn->sslSendBuffer == NULL) {
            NABTO_LOG_ERROR(LOG,
                            "Cannot allocate a buffer for sending a packet "
                            "from the dtls client. Dropping the packet");
            // dropping the packet as there is no way to trigger a
            // retransmission of the packet once the system has available memory
            // again.
            return (int)bufferSize;
        }
        memcpy(conn->pl->buf.start(conn->sslSendBuffer), buffer, bufferSize);
        np_error_code ec =
            conn->sender(conn->sendChannelId, pl->buf.start(conn->sslSendBuffer), (uint16_t)bufferSize,
                        &conn->senderEvent, conn->callbackData);
        if (ec != NABTO_EC_OK) {
            pl->buf.free(conn->sslSendBuffer);
            conn->sslSendBuffer = NULL;
            if (conn->state == CLOSING) {
                nm_dtls_do_close(conn, /* ec unused */ NABTO_EC_OK);
                if (conn->destroyed) {
                    do_free_connection(conn);
                }
            }
            // dropping the packet as there is no way to trigger a
            // retransmission of the data.
            return (int)bufferSize;
        }
        return (int)bufferSize;
    } else {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
}

int nm_dtls_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize)
{
    struct np_dtls_cli_connection* conn = data;
    if (conn->recvBufferSize == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        size_t maxCp = bufferSize > conn->recvBufferSize ? conn->recvBufferSize : bufferSize;
        memcpy(buffer, conn->recvBuffer, maxCp);
        conn->recvBufferSize = 0;
        return (int)maxCp;
    }
}

void nm_dtls_timed_event_do_one(void* data) {
    struct np_dtls_cli_connection* conn = data;
    if (conn->state == CLOSING) {
        return;
    }
    event_do_one(data);
}
