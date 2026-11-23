#include "nm_openssl_srv.h"
#include "nm_openssl_common.h"
#include "nm_openssl_util.h"

#include <core/nc_version.h>
#include <platform/np_allocator.h>
#include <platform/np_completion_event.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_logging.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <string.h>

#if !defined(NABTO_DEVICE_DTLS_CLIENT_ONLY)

#define LOG NABTO_LOG_MODULE_DTLS_SRV

// Handshake retransmission timeouts in milliseconds.
static const uint32_t MIN_TIMEOUT = 1000;
static const uint32_t MAX_TIMEOUT = 16000;

static const char* allowedCipherSuitesList = "ECDHE-ECDSA-AES128-CCM";

// The only ALPN protocol the server accepts.
static const char* alpnProtocol = NABTO_PROTOCOL_VERSION;

struct np_dtls_srv_connection {
    struct np_platform* pl;
    struct np_dtls_srv* server;
    enum sslState state;
    SSL* ssl;
    uint8_t currentChannelId;
    uint8_t* recvBuffer;
    size_t recvBufferSize;

    // The sequence number in the last received dtls record.
    uint64_t lastRecvSequenceNumber;

    // The current handshake retransmission timeout in microseconds.
    unsigned int timeoutUs;

    struct np_communication_buffer* sslSendBuffer;

    struct np_event* timerEvent;

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
    SSL_CTX* ctx;
    BIO_METHOD* bioMethod;
    X509* certificate;
    uint16_t mtu;
};

static np_error_code nm_openssl_srv_create(struct np_platform* pl,
                                           struct np_dtls_srv** server);

static void nm_openssl_srv_destroy(struct np_dtls_srv* server);

static np_error_code nm_openssl_srv_set_keys(struct np_dtls_srv* server,
                                             const unsigned char* certificate,
                                             size_t certificateSize,
                                             const unsigned char* privateKeyL,
                                             size_t privateKeySize);

static np_error_code nm_openssl_srv_create_connection(
    struct np_dtls_srv* server, struct np_dtls_srv_connection** dtls,
    np_dtls_sender sender, np_dtls_data_handler dataHandler,
    np_dtls_event_handler eventHandler, void* data);
static void nm_openssl_srv_destroy_connection(
    struct np_dtls_srv_connection* connection);

static void nm_openssl_srv_do_free_connection(struct np_dtls_srv_connection* conn);

static np_error_code nm_openssl_srv_async_send_data(
    struct np_platform* pl, struct np_dtls_srv_connection* ctx,
    struct np_dtls_send_context* sendCtx);

static np_error_code nm_openssl_srv_async_close(
    struct np_platform* pl, struct np_dtls_srv_connection* ctx,
    struct np_completion_event* completionEvent);

static np_error_code nm_openssl_srv_get_fingerprint(
    struct np_platform* pl, struct np_dtls_srv_connection* ctx, uint8_t* fp);
static np_error_code nm_openssl_srv_get_server_fingerprint(
    struct np_dtls_srv* server, uint8_t* fp);
static const char* nm_openssl_srv_get_alpn_protocol(struct np_dtls_srv_connection* ctx);
static np_error_code nm_openssl_srv_get_packet_count(
    struct np_dtls_srv_connection* ctx, uint32_t* recvCount,
    uint32_t* sentCount);
static np_error_code nm_openssl_srv_handle_packet(struct np_platform* pl,
                                                  struct np_dtls_srv_connection* ctx,
                                                  uint8_t channelId, uint8_t* buffer,
                                                  uint16_t bufferSize);

static void set_timeout(struct np_dtls_srv_connection* ctx);
static void handle_timeout(void* data);
static unsigned int timer_callback(SSL* ssl, unsigned int timerUs);

static void connection_send_callback(const np_error_code ec, void* data);
static void do_one(struct np_dtls_srv_connection* ctx);
static void start_send(struct np_dtls_srv_connection* ctx);
static void start_send_deferred(void* data);
static void event_callback(struct np_dtls_srv_connection* ctx,
                           enum np_dtls_event event);
static void is_closed(struct np_dtls_srv_connection* ctx);

// Functions called by OpenSSL when data should be sent to or received from
// the network
static int bio_write(BIO* bio, const char* buffer, int bufferSize);
static int bio_read(BIO* bio, char* buffer, int bufferSize);
static void msg_callback(int writeP, int version, int contentType,
                         const void* buf, size_t len, SSL* ssl, void* arg);

static int verify_callback(int preverifyOk, X509_STORE_CTX* storeCtx)
{
    // Client certificates are self signed, the client is identified by the
    // fingerprint of its public key.
    (void)preverifyOk;
    (void)storeCtx;
    return 1;
}

static int alpn_select_callback(SSL* ssl, const unsigned char** out,
                                unsigned char* outlen, const unsigned char* in,
                                unsigned int inlen, void* arg)
{
    (void)ssl;
    (void)arg;
    size_t len = strlen(alpnProtocol);

    // Find the protocol in the client list, the selected protocol must point
    // into the client list.
    unsigned int i = 0;
    while (i < inlen) {
        unsigned int l = in[i];
        if (i + 1 + l > inlen) {
            break;
        }
        if (l == len && memcmp(in + i + 1, alpnProtocol, len) == 0) {
            *out = in + i + 1;
            *outlen = (unsigned char)l;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + l;
    }
    NABTO_LOG_ERROR(LOG, "Application Layer Protocol Negotiation failed for DTLS server connection");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

np_error_code nm_openssl_srv_init(struct np_platform* pl)
{
    pl->dtlsS.create = &nm_openssl_srv_create;
    pl->dtlsS.destroy = &nm_openssl_srv_destroy;
    pl->dtlsS.set_keys = &nm_openssl_srv_set_keys;
    pl->dtlsS.get_server_fingerprint = &nm_openssl_srv_get_server_fingerprint;
    pl->dtlsS.create_connection = &nm_openssl_srv_create_connection;
    pl->dtlsS.destroy_connection = &nm_openssl_srv_destroy_connection;
    pl->dtlsS.async_send_data = &nm_openssl_srv_async_send_data;
    pl->dtlsS.async_close = &nm_openssl_srv_async_close;
    pl->dtlsS.get_fingerprint = &nm_openssl_srv_get_fingerprint;
    pl->dtlsS.get_alpn_protocol = &nm_openssl_srv_get_alpn_protocol;
    pl->dtlsS.get_packet_count = &nm_openssl_srv_get_packet_count;
    pl->dtlsS.handle_packet = &nm_openssl_srv_handle_packet;
    return NABTO_EC_OK;
}

// Get the packet counters for given dtls_srv_connection
np_error_code nm_openssl_srv_get_packet_count(
    struct np_dtls_srv_connection* ctx, uint32_t* recvCount,
    uint32_t* sentCount)
{
    *recvCount = ctx->recvCount;
    *sentCount = ctx->sentCount;
    return NABTO_EC_OK;
}

// Get the result of the application layer protocol negotiation
const char* nm_openssl_srv_get_alpn_protocol(struct np_dtls_srv_connection* ctx)
{
    const unsigned char* data = NULL;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ctx->ssl, &data, &len);
    if (data == NULL || len == 0) {
        return NULL;
    }
    // The only protocol which can be selected.
    return alpnProtocol;
}

/**
 * get peers fingerprint for given DTLS server connection
 */
np_error_code nm_openssl_srv_get_fingerprint(struct np_platform* pl,
                                             struct np_dtls_srv_connection* ctx,
                                             uint8_t* fp)
{
    (void)pl;
    X509* crt = SSL_get0_peer_certificate(ctx->ssl);
    if (crt == NULL) {
        return NABTO_EC_UNKNOWN;
    }
    return nm_openssl_util_fp_from_crt(crt, fp);
}

np_error_code nm_openssl_srv_get_server_fingerprint(struct np_dtls_srv* server,
                                                    uint8_t* fp)
{
    if (server->certificate == NULL) {
        return NABTO_EC_INVALID_STATE;
    }
    return nm_openssl_util_fp_from_crt(server->certificate, fp);
}

np_error_code nm_openssl_srv_create(struct np_platform* pl,
                                    struct np_dtls_srv** server)
{
    struct np_dtls_srv* srv = np_calloc(1, sizeof(struct np_dtls_srv));
    if (srv == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    srv->pl = pl;
    np_error_code ec = nm_openssl_util_get_mtu(pl, &srv->mtu);
    if (ec != NABTO_EC_OK) {
        np_free(srv);
        return ec;
    }

    srv->ctx = SSL_CTX_new(DTLS_server_method());
    srv->bioMethod = nm_openssl_util_create_bio_method("nabto dtls server", &bio_write, &bio_read);
    if (srv->ctx == NULL || srv->bioMethod == NULL) {
        nm_openssl_util_log_errors(LOG);
        nm_openssl_srv_destroy(srv);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    if (SSL_CTX_set_min_proto_version(srv->ctx, DTLS1_2_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(srv->ctx, DTLS1_2_VERSION) != 1 ||
        SSL_CTX_set_cipher_list(srv->ctx, allowedCipherSuitesList) != 1) {
        NABTO_LOG_ERROR(LOG, "server can't set custom cipher list");
        nm_openssl_util_log_errors(LOG);
        nm_openssl_srv_destroy(srv);
        return NABTO_EC_FAILED;
    }

    // Request a client certificate, but do not validate it.
    SSL_CTX_set_verify(srv->ctx, SSL_VERIFY_PEER, &verify_callback);
    SSL_CTX_set_alpn_select_cb(srv->ctx, &alpn_select_callback, NULL);
    // Connections are not resumed.
    SSL_CTX_set_session_cache_mode(srv->ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(srv->ctx, SSL_OP_NO_TICKET);

    *server = srv;
    return NABTO_EC_OK;
}

void nm_openssl_srv_destroy(struct np_dtls_srv* server)
{
    if (server == NULL) {
        return;
    }
    SSL_CTX_free(server->ctx);
    BIO_meth_free(server->bioMethod);
    X509_free(server->certificate);
    np_free(server);
}

np_error_code nm_openssl_srv_set_keys(struct np_dtls_srv* server,
                                      const unsigned char* certificate,
                                      size_t certificateSize,
                                      const unsigned char* privateKeyL,
                                      size_t privateKeySize)
{
    X509* crt = nm_openssl_util_load_certificate(certificate, certificateSize);
    if (crt == NULL) {
        NABTO_LOG_ERROR(LOG, "Cannot parse the certificate");
        nm_openssl_util_log_errors(LOG);
        return NABTO_EC_UNKNOWN;
    }
    EVP_PKEY* key = nm_openssl_util_load_private_key(privateKeyL, privateKeySize);
    if (key == NULL) {
        NABTO_LOG_ERROR(LOG, "Cannot parse the private key");
        nm_openssl_util_log_errors(LOG);
        X509_free(crt);
        return NABTO_EC_UNKNOWN;
    }

    np_error_code ec = NABTO_EC_OK;
    if (SSL_CTX_use_certificate(server->ctx, crt) != 1 ||
        SSL_CTX_use_PrivateKey(server->ctx, key) != 1) {
        NABTO_LOG_ERROR(LOG, "Cannot use the certificate and private key");
        nm_openssl_util_log_errors(LOG);
        ec = NABTO_EC_UNKNOWN;
    }
    EVP_PKEY_free(key);
    if (ec != NABTO_EC_OK) {
        X509_free(crt);
        return ec;
    }
    X509_free(server->certificate);
    server->certificate = crt;
    return NABTO_EC_OK;
}

np_error_code nm_openssl_srv_create_connection(
    struct np_dtls_srv* server, struct np_dtls_srv_connection** dtls,
    np_dtls_sender sender, np_dtls_data_handler dataHandler,
    np_dtls_event_handler eventHandler, void* data)
{
    struct np_dtls_srv_connection* ctx = np_calloc(1, sizeof(struct np_dtls_srv_connection));
    if (ctx == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->pl = server->pl;
    ctx->server = server;
    ctx->sender = sender;
    ctx->dataHandler = dataHandler;
    ctx->eventHandler = eventHandler;
    ctx->senderData = data;
    ctx->channelId = NP_DTLS_DEFAULT_CHANNEL_ID;
    ctx->state = CONNECTING;

    nn_llist_init(&ctx->sendList);

    struct np_platform* pl = ctx->pl;

    np_error_code ec = np_event_queue_create_event(&pl->eq, &start_send_deferred, ctx, &ctx->startSendEvent);
    if (ec == NABTO_EC_OK) {
        ec = np_event_queue_create_event(&pl->eq, &handle_timeout, ctx, &ctx->timerEvent);
    }
    if (ec == NABTO_EC_OK) {
        ec = np_completion_event_init(&pl->eq, &ctx->senderEvent, &connection_send_callback, ctx);
    }
    if (ec != NABTO_EC_OK) {
        nm_openssl_srv_do_free_connection(ctx);
        return ec;
    }

    ctx->ssl = SSL_new(server->ctx);
    BIO* bio = BIO_new(server->bioMethod);
    if (ctx->ssl == NULL || bio == NULL) {
        NABTO_LOG_ERROR(LOG, "Cannot create the ssl object");
        nm_openssl_util_log_errors(LOG);
        BIO_free(bio);
        nm_openssl_srv_do_free_connection(ctx);
        return NABTO_EC_OUT_OF_MEMORY;
    }
    BIO_set_data(bio, ctx);
    // The ssl object takes the reference to the bio.
    SSL_set_bio(ctx->ssl, bio, bio);
    SSL_set_app_data(ctx->ssl, ctx);
    SSL_set_msg_callback(ctx->ssl, &msg_callback);
    SSL_set_msg_callback_arg(ctx->ssl, ctx);
    DTLS_set_timer_cb(ctx->ssl, &timer_callback);
    SSL_set_accept_state(ctx->ssl);

    ec = nm_openssl_util_configure_ssl(ctx->ssl, server->mtu);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Cannot configure the ssl object");
        nm_openssl_util_log_errors(LOG);
        nm_openssl_srv_do_free_connection(ctx);
        return ec;
    }

    NABTO_LOG_TRACE(LOG, "New DTLS srv connection was allocated.");

    *dtls = ctx;
    return NABTO_EC_OK;
}

void nm_openssl_srv_do_free_connection(struct np_dtls_srv_connection* conn)
{
    // remove the first element until the list is empty
    if (!nn_llist_empty(&conn->sendList)) {
        NABTO_LOG_ERROR(LOG, "invalid state the sendlist must be empty when calling destroy.");
    }
    while (!nn_llist_empty(&conn->sendList)) {
        struct nn_llist_iterator it = nn_llist_begin(&conn->sendList);
        struct np_dtls_send_context* first = nn_llist_get_item(&it);
        nn_llist_erase(&it);
        np_completion_event_resolve(&first->ev, NABTO_EC_CONNECTION_CLOSING);
    }

    struct np_event_queue* eq = &conn->pl->eq;
    np_event_queue_destroy_event(eq, conn->timerEvent);
    np_event_queue_destroy_event(eq, conn->startSendEvent);
    np_completion_event_deinit(&conn->senderEvent);
    SSL_free(conn->ssl);
    np_free(conn);
}

static void nm_openssl_srv_destroy_connection(struct np_dtls_srv_connection* conn)
{
    if (conn == NULL) {
        return;
    }
    conn->destroyed = true;
    if (conn->sslSendBuffer == NULL && !conn->receiving) {
        nm_openssl_srv_do_free_connection(conn);
    }
}

np_error_code nm_openssl_srv_handle_packet(struct np_platform* pl,
                                           struct np_dtls_srv_connection* ctx,
                                           uint8_t channelId, uint8_t* buffer,
                                           uint16_t bufferSize)
{
    (void)pl;
    ctx->currentChannelId = channelId;
    ctx->recvBuffer = buffer;
    ctx->recvBufferSize = bufferSize;
    ctx->channelId = channelId;
    ctx->receiving = true;
    do_one(ctx);
    ctx->channelId = NP_DTLS_DEFAULT_CHANNEL_ID;
    ctx->recvBuffer = NULL;
    ctx->recvBufferSize = 0;
    ctx->receiving = false;
    if (ctx->destroyed && ctx->sslSendBuffer == NULL) {
        nm_openssl_srv_do_free_connection(ctx);
    }
    return NABTO_EC_OK;
}

void do_one(struct np_dtls_srv_connection* ctx)
{
    if (ctx->state == CONNECTING) {
        ERR_clear_error();
        int ret = SSL_do_handshake(ctx->ssl);
        if (ret == 1) {
            NABTO_LOG_TRACE(LOG, "State changed to DATA");
            np_event_queue_cancel_event(&ctx->pl->eq, ctx->timerEvent);
            ctx->state = DATA;
            event_callback(ctx, NP_DTLS_EVENT_HANDSHAKE_COMPLETE);
            return;
        }
        int err = SSL_get_error(ctx->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // keep state as CONNECTING
            set_timeout(ctx);
        } else {
            NABTO_LOG_ERROR(LOG, "SSL_do_handshake failed with %d", err);
            nm_openssl_util_log_errors(LOG);
            np_event_queue_cancel_event(&ctx->pl->eq, ctx->timerEvent);
            event_callback(ctx, NP_DTLS_EVENT_CLOSED);
        }
    } else if (ctx->state == DATA) {
        ERR_clear_error();
        uint8_t* recvBuffer = NULL;
        int err = SSL_ERROR_NONE;
        int ret = nm_openssl_recv_data(ctx->ssl, &recvBuffer, &err);
        if (ret > 0) {
            // The sequence number is the epoch and sequence number of the
            // record, 8 bytes in total.
            uint64_t seq = ctx->lastRecvSequenceNumber;
            ctx->recvCount++;
            ctx->dataHandler(ctx->currentChannelId, seq, recvBuffer, (uint16_t)ret, ctx->senderData);
            np_free(recvBuffer);
        } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // OK
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            // close notify, expected to happen on a connection.
            NABTO_LOG_TRACE(LOG, "Received close notify");
            event_callback(ctx, NP_DTLS_EVENT_CLOSED);
        } else {
            NABTO_LOG_ERROR(LOG, "Received ERROR: %i", err);
            nm_openssl_util_log_errors(LOG);
            event_callback(ctx, NP_DTLS_EVENT_CLOSED);
        }
    }
}

unsigned int timer_callback(SSL* ssl, unsigned int timerUs)
{
    struct np_dtls_srv_connection* ctx = SSL_get_app_data(ssl);
    // The retransmission timeout is doubled from MIN_TIMEOUT up to
    // MAX_TIMEOUT, handle_timeout fails the handshake when the timeout at
    // MAX_TIMEOUT expires.
    unsigned int next = 0;
    if (timerUs == 0) {
        next = MIN_TIMEOUT * 1000;
    } else {
        next = timerUs * 2;
        if (next > MAX_TIMEOUT * 1000) {
            next = MAX_TIMEOUT * 1000;
        }
    }
    ctx->timeoutUs = next;
    return next;
}

void set_timeout(struct np_dtls_srv_connection* ctx)
{
    struct timeval tv;
    np_event_queue_cancel_event(&ctx->pl->eq, ctx->timerEvent);
    if (DTLSv1_get_timeout(ctx->ssl, &tv) == 1) {
        uint64_t ms = (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
        np_event_queue_post_timed_event(&ctx->pl->eq, ctx->timerEvent, (uint32_t)ms);
    }
}

void handle_timeout(void* data)
{
    struct np_dtls_srv_connection* ctx = data;
    if (ctx->state != CONNECTING) {
        return;
    }
    struct timeval tv;
    if (DTLSv1_get_timeout(ctx->ssl, &tv) != 1) {
        // No timer is running.
        return;
    }
    if (tv.tv_sec > 0 || tv.tv_usec > 0) {
        // The OpenSSL timer has not expired yet.
        set_timeout(ctx);
        return;
    }
    if (ctx->timeoutUs >= MAX_TIMEOUT * 1000) {
        NABTO_LOG_TRACE(LOG, "DTLS handshake timed out");
        event_callback(ctx, NP_DTLS_EVENT_CLOSED);
        return;
    }
    ERR_clear_error();
    if (DTLSv1_handle_timeout(ctx->ssl) < 0) {
        // too many retries, timeout.
        nm_openssl_util_log_errors(LOG);
        event_callback(ctx, NP_DTLS_EVENT_CLOSED);
        return;
    }
    set_timeout(ctx);
}

void event_callback(struct np_dtls_srv_connection* ctx, enum np_dtls_event event)
{
    ctx->eventHandler(event, ctx->senderData);
}

void start_send(struct np_dtls_srv_connection* ctx)
{
    np_event_queue_post_maybe_double(&ctx->pl->eq, ctx->startSendEvent);
}

void start_send_deferred(void* data)
{
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*)data;
    if (ctx->sslSendBuffer != NULL) {
        return;
    }

    if (nn_llist_empty(&ctx->sendList)) {
        // empty send queue
        is_closed(ctx);
        return;
    }

    struct nn_llist_iterator it = nn_llist_begin(&ctx->sendList);
    struct np_dtls_send_context* next = nn_llist_get_item(&it);
    nn_llist_erase(&it);

    if (ctx->state != DATA) {
        np_completion_event_resolve(&next->ev, NABTO_EC_INVALID_STATE);
        return;
    }

    if (next->bufferSize > DTLS_get_data_mtu(ctx->ssl)) {
        // The record would be larger than a communication buffer.
        NABTO_LOG_ERROR(LOG, "ssl_write failed (Packet too large)");
        np_completion_event_resolve(&next->ev, NABTO_EC_MALFORMED_PACKET);
        return;
    }

    ERR_clear_error();
    ctx->channelId = next->channelId;
    int ret = SSL_write(ctx->ssl, next->buffer, (int)next->bufferSize);
    ctx->channelId = NP_DTLS_DEFAULT_CHANNEL_ID;

    if (ret <= 0) {
        int err = SSL_get_error(ctx->ssl, ret);
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i", err);
        nm_openssl_util_log_errors(LOG);
        np_completion_event_resolve(&next->ev, NABTO_EC_UNKNOWN);
    } else {
        ctx->sentCount++;
        np_completion_event_resolve(&next->ev, NABTO_EC_OK);
    }
}

np_error_code nm_openssl_srv_async_send_data(struct np_platform* pl,
                                             struct np_dtls_srv_connection* ctx,
                                             struct np_dtls_send_context* sendCtx)
{
    (void)pl;
    if (ctx->state == CLOSING) {
        return NABTO_EC_CONNECTION_CLOSING;
    }
    nn_llist_append(&ctx->sendList, &sendCtx->sendListNode, sendCtx);
    start_send(ctx);
    return NABTO_EC_OK;
}

void is_closed(struct np_dtls_srv_connection* ctx)
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

np_error_code nm_openssl_srv_async_close(struct np_platform* pl,
                                         struct np_dtls_srv_connection* ctx,
                                         struct np_completion_event* completionEvent)
{
    (void)pl;
    if (ctx->closeCompletionEvent != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    if (ctx->state == CLOSING) {
        return NABTO_EC_OK;
    }
    bool handshakeDone = ctx->state == DATA;
    ctx->closeCompletionEvent = completionEvent;
    ctx->state = CLOSING;
    np_event_queue_cancel_event(&pl->eq, ctx->timerEvent);
    if (handshakeDone) {
        // Send close notify, a failure is not an error as the connection is
        // closed anyway.
        ERR_clear_error();
        SSL_shutdown(ctx->ssl);
        ERR_clear_error();
    }
    is_closed(ctx);
    return NABTO_EC_OPERATION_STARTED;
}

// Function called by OpenSSL when a datagram should be sent to the network
int bio_write(BIO* bio, const char* buffer, int bufferSize)
{
    struct np_dtls_srv_connection* ctx = BIO_get_data(bio);
    struct np_platform* pl = ctx->pl;
    BIO_clear_retry_flags(bio);
    if (ctx->sslSendBuffer != NULL) {
        BIO_set_retry_write(bio);
        return -1;
    }
    if (bufferSize < 0) {
        return -1;
    }
    ctx->sslSendBuffer = pl->buf.allocate();
    if (ctx->sslSendBuffer == NULL) {
        NABTO_LOG_ERROR(LOG, "Could not allocate buffer for sending data from the dtls server, dropping the packet.");
        // if we return a retry there is no mechanism which ensures a
        // retransmission occurs.
        return bufferSize;
    }
    if ((size_t)bufferSize + NP_DTLS_CONNECTION_ID_HEADER_SIZE > pl->buf.size(ctx->sslSendBuffer)) {
        // Cannot happen as the mtu leaves room for the connection id
        // header in a communication buffer.
        NABTO_LOG_ERROR(LOG, "The dtls record (%d bytes) does not fit in a communication buffer, dropping the packet.", bufferSize);
        pl->buf.free(ctx->sslSendBuffer);
        ctx->sslSendBuffer = NULL;
        return bufferSize;
    }
    memcpy(pl->buf.start(ctx->sslSendBuffer), buffer, (size_t)bufferSize);

    np_error_code ec = ctx->sender(ctx->channelId, pl->buf.start(ctx->sslSendBuffer), (uint16_t)bufferSize, &ctx->senderEvent, ctx->senderData);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Could not send the packet from the dtls server, dropping the packet.");
        pl->buf.free(ctx->sslSendBuffer);
        ctx->sslSendBuffer = NULL;
        // if we return a retry there is no mechanism which ensures a
        // retransmission occurs.
        return bufferSize;
    }
    return bufferSize;
}

void connection_send_callback(const np_error_code ec, void* data)
{
    (void)ec;
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*)data;
    if (data == NULL) {
        return;
    }
    ctx->pl->buf.free(ctx->sslSendBuffer);
    ctx->sslSendBuffer = NULL;

    if (ctx->destroyed) {
        if (!ctx->receiving) {
            nm_openssl_srv_do_free_connection(ctx);
        }
        return;
    }

    // A handshake flight which did not fit in one datagram continues.
    do_one(ctx);
    start_send(ctx);
}

// Function called by OpenSSL when it wants a datagram from the network
int bio_read(BIO* bio, char* buffer, int bufferSize)
{
    struct np_dtls_srv_connection* ctx = BIO_get_data(bio);
    BIO_clear_retry_flags(bio);
    if (ctx->recvBufferSize == 0) {
        BIO_set_retry_read(bio);
        return -1;
    }
    if (bufferSize < 0) {
        return -1;
    }
    size_t maxCp = (size_t)bufferSize > ctx->recvBufferSize ? ctx->recvBufferSize : (size_t)bufferSize;
    memcpy(buffer, ctx->recvBuffer, maxCp);
    ctx->recvBufferSize = 0;
    return (int)maxCp;
}

void msg_callback(int writeP, int version, int contentType, const void* buf,
                  size_t len, SSL* ssl, void* arg)
{
    (void)version;
    (void)ssl;
    struct np_dtls_srv_connection* ctx = arg;
    if (!writeP && contentType == SSL3_RT_HEADER) {
        // Called with the header of each record which is read.
        nm_openssl_util_record_sequence_number(buf, len, &ctx->lastRecvSequenceNumber);
    }
    nm_openssl_util_log_message(LOG, writeP, contentType, buf, len);
}

#endif
