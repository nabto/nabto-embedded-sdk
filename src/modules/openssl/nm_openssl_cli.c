#include "nm_openssl_cli.h"
#include "nm_openssl_common.h"
#include "nm_openssl_util.h"

#include <platform/np_allocator.h>
#include <platform/np_error_code.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_logging.h>

#include <core/nc_version.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include <limits.h>
#include <string.h>

#include <nn/llist.h>

/******** definitions and constants *******/

#define LOG NABTO_LOG_MODULE_DTLS_CLI

static const char* allowedCipherSuitesList = "ECDHE-ECDSA-AES128-CCM";
static const char* alpnProtocol = NABTO_PROTOCOL_VERSION;

struct nm_openssl_cli_context {
    struct np_platform* pl;
    SSL_CTX* ctx;
    BIO_METHOD* bioMethod;

    // Handshake retransmission timeouts in milliseconds.
    uint32_t timeoutMin;
    uint32_t timeoutMax;

    uint16_t mtu;
};

struct np_dtls_cli_connection {
    struct np_platform* pl;
    SSL* ssl;
    enum sslState state;

    // Ciphertext datagram recvBuffer temporary variable.
    uint8_t* recvBuffer;
    size_t recvBufferSize;
    uint8_t recvChannelId;

    // The sequence number in the last received dtls record.
    uint64_t lastRecvSequenceNumber;
    // The description of the last received alert, -1 if none.
    int lastRecvAlert;
    bool verifyCertificate;

    // The current handshake retransmission timeout in microseconds.
    unsigned int timeoutUs;

    // Allocated when sending a packet with ciphertext through the UDP layer.
    struct np_communication_buffer* sslSendBuffer;

    struct np_event* timerEvent;

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
};

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

static np_error_code get_certificate_expiration(struct np_dtls_cli_connection* conn, uint64_t* expiration);

/******** Internal function definitions *******/
static np_error_code initialize_context(struct np_platform* pl);
static np_error_code create_connection(struct np_platform* pl, struct np_dtls_cli_connection** connection,
                                       np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
                                       np_dtls_event_handler eventHandler, void* data);
static void do_free_connection(struct np_dtls_cli_connection* conn);
static void event_do_one(void* data);
static void event_handle_connecting_state(struct np_dtls_cli_connection* conn);
static void nm_dtls_do_close(struct np_dtls_cli_connection* conn);
static void start_send(struct np_dtls_cli_connection* conn);
static void start_send_deferred(void* data);
static void dtls_udp_send_callback(np_error_code ec, void* data);
static void set_timeout(struct np_dtls_cli_connection* conn);
static void handle_timeout(void* data);
static unsigned int timer_callback(SSL* ssl, unsigned int timerUs);

// Functions called by OpenSSL when data should be sent to or received from
// the network
static int bio_write(BIO* bio, const char* buffer, int bufferSize);
static int bio_read(BIO* bio, char* buffer, int bufferSize);
static void msg_callback(int writeP, int version, int contentType,
                         const void* buf, size_t len, SSL* ssl, void* arg);

/*
 * Initialize the np_platform to use this particular dtls cli module
 */
np_error_code nm_openssl_cli_init(struct np_platform* pl)
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
    pl->dtlsC.get_certificate_expiration = &get_certificate_expiration;
    return initialize_context(pl);
}

void nm_openssl_cli_deinit(struct np_platform* pl)
{
    struct nm_openssl_cli_context* ctx = (struct nm_openssl_cli_context*)pl->dtlsCData;
    if (ctx == NULL) {
        return;
    }
    SSL_CTX_free(ctx->ctx);
    BIO_meth_free(ctx->bioMethod);
    np_free(ctx);
    pl->dtlsCData = NULL;
}

np_error_code initialize_context(struct np_platform* pl)
{
    struct nm_openssl_cli_context* ctx = np_calloc(1, sizeof(struct nm_openssl_cli_context));
    if (ctx == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    pl->dtlsCData = ctx;
    ctx->pl = pl;
    // The mbedtls defaults.
    ctx->timeoutMin = 1000;
    ctx->timeoutMax = 60000;
    np_error_code ec = nm_openssl_util_get_mtu(pl, &ctx->mtu);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ctx->ctx = SSL_CTX_new(DTLS_client_method());
    ctx->bioMethod = nm_openssl_util_create_bio_method("nabto dtls client", &bio_write, &bio_read);
    if (ctx->ctx == NULL || ctx->bioMethod == NULL) {
        nm_openssl_util_log_errors(LOG);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    if (SSL_CTX_set_min_proto_version(ctx->ctx, DTLS1_2_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx->ctx, DTLS1_2_VERSION) != 1 ||
        SSL_CTX_set_cipher_list(ctx->ctx, allowedCipherSuitesList) != 1) {
        NABTO_LOG_ERROR(LOG, "client can't set custom cipher list");
        nm_openssl_util_log_errors(LOG);
        return NABTO_EC_FAILED;
    }

    unsigned char protos[256];
    size_t len = strlen(alpnProtocol);
    protos[0] = (unsigned char)len;
    memcpy(protos + 1, alpnProtocol, len);
    // Returns 0 on success.
    if (SSL_CTX_set_alpn_protos(ctx->ctx, protos, (unsigned int)(len + 1)) != 0) {
        NABTO_LOG_ERROR(LOG, "Cannot configure alpn protocols");
        return NABTO_EC_FAILED;
    }

    // Attach connections verify the server certificate, client connections
    // identify the peer by the fingerprint of its public key.
    SSL_CTX_set_verify(ctx->ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_session_cache_mode(ctx->ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx->ctx, SSL_OP_NO_TICKET);

    // The trusted roots are only the ones given in set_root_certs.
    X509_STORE* store = X509_STORE_new();
    if (store == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    SSL_CTX_set_cert_store(ctx->ctx, store);
    return NABTO_EC_OK;
}

np_error_code create_connection(struct np_platform* pl, struct np_dtls_cli_connection** connection,
                                np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
                                np_dtls_event_handler eventHandler, void* data)
{
    struct nm_openssl_cli_context* ctx = (struct nm_openssl_cli_context*)pl->dtlsCData;
    if (ctx == NULL || ctx->ctx == NULL) {
        return NABTO_EC_INVALID_STATE;
    }

    *connection = NULL;
    struct np_dtls_cli_connection* conn = np_calloc(1, sizeof(struct np_dtls_cli_connection));
    if (conn == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    conn->pl = pl;
    conn->sender = packetSender;
    conn->dataHandler = dataHandler;
    conn->eventHandler = eventHandler;
    conn->callbackData = data;
    conn->recvChannelId = NP_DTLS_DEFAULT_CHANNEL_ID;
    conn->sendChannelId = NP_DTLS_DEFAULT_CHANNEL_ID;
    conn->lastRecvAlert = -1;

    nn_llist_init(&conn->sendList);

    np_error_code ec = np_event_queue_create_event(&pl->eq, &handle_timeout, conn, &conn->timerEvent);
    if (ec == NABTO_EC_OK) {
        ec = np_event_queue_create_event(&pl->eq, &start_send_deferred, conn, &conn->startSendEvent);
    }
    if (ec == NABTO_EC_OK) {
        ec = np_completion_event_init(&pl->eq, &conn->senderEvent, &dtls_udp_send_callback, conn);
    }
    if (ec != NABTO_EC_OK) {
        do_free_connection(conn);
        return ec;
    }

    conn->ssl = SSL_new(ctx->ctx);
    BIO* bio = BIO_new(ctx->bioMethod);
    if (conn->ssl == NULL || bio == NULL) {
        NABTO_LOG_ERROR(LOG, "Cannot create the ssl object");
        nm_openssl_util_log_errors(LOG);
        BIO_free(bio);
        do_free_connection(conn);
        return NABTO_EC_OUT_OF_MEMORY;
    }
    BIO_set_data(bio, conn);
    // The ssl object takes the reference to the bio.
    SSL_set_bio(conn->ssl, bio, bio);
    SSL_set_app_data(conn->ssl, conn);
    SSL_set_msg_callback(conn->ssl, &msg_callback);
    SSL_set_msg_callback_arg(conn->ssl, conn);
    DTLS_set_timer_cb(conn->ssl, &timer_callback);
    SSL_set_connect_state(conn->ssl);

    ec = nm_openssl_util_configure_ssl(conn->ssl, ctx->mtu);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Cannot configure the ssl object");
        nm_openssl_util_log_errors(LOG);
        do_free_connection(conn);
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
    return create_connection(pl, connection, packetSender, dataHandler, eventHandler, data);
}

static np_error_code create_attach_connection(
    struct np_platform* pl, struct np_dtls_cli_connection** connection,
    const char* sni, bool disable_cert_validation,
    np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
    np_dtls_event_handler eventHandler, void* data)
{
    np_error_code ec = create_connection(pl, connection, packetSender, dataHandler, eventHandler, data);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    struct np_dtls_cli_connection* conn = *connection;

    if (SSL_set_tlsext_host_name(conn->ssl, sni) != 1) {
        NABTO_LOG_ERROR(LOG, "Failed to set SNI Hostname in the DTLS client");
        nm_openssl_util_log_errors(LOG);
        do_free_connection(conn);
        *connection = NULL;
        return NABTO_EC_UNKNOWN;
    }

    if (!disable_cert_validation) {
        // The certificate must be valid for the hostname.
        if (SSL_set1_host(conn->ssl, sni) != 1) {
            NABTO_LOG_ERROR(LOG, "Failed to set the hostname to verify in the DTLS client");
            nm_openssl_util_log_errors(LOG);
            do_free_connection(conn);
            *connection = NULL;
            return NABTO_EC_UNKNOWN;
        }
        SSL_set_verify(conn->ssl, SSL_VERIFY_PEER, NULL);
        conn->verifyCertificate = true;
    }
    return NABTO_EC_OK;
}

np_error_code get_packet_count(struct np_dtls_cli_connection* conn, uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = conn->recvCount;
    *sentCount = conn->sentCount;
    return NABTO_EC_OK;
}

np_error_code get_certificate_expiration(struct np_dtls_cli_connection* conn, uint64_t* expiration)
{
    if (conn->state != DATA) {
        return NABTO_EC_INVALID_STATE;
    }
    X509* crt = SSL_get0_peer_certificate(conn->ssl);
    if (crt == NULL) {
        NABTO_LOG_ERROR(LOG, "Connection has no certificate");
        return NABTO_EC_UNKNOWN;
    }
    return nm_openssl_util_get_expiration(crt, expiration);
}

// Get the result of the application layer protocol negotiation
const char* get_alpn_protocol(struct np_dtls_cli_connection* conn)
{
    const unsigned char* data = NULL;
    unsigned int len = 0;
    SSL_get0_alpn_selected(conn->ssl, &data, &len);
    if (data == NULL || len == 0) {
        return NULL;
    }
    // The server can only select a protocol the client offered.
    return alpnProtocol;
}

void destroy_connection(struct np_dtls_cli_connection* conn)
{
    if (conn == NULL) {
        return;
    }
    conn->state = CLOSING;
    conn->destroyed = true;
    if (conn->sslSendBuffer == NULL && !conn->receiving) {
        do_free_connection(conn);
    }
}

void do_free_connection(struct np_dtls_cli_connection* conn)
{
    if (conn == NULL) {
        return;
    }
    // remove the first element until the list is empty
    while (!nn_llist_empty(&conn->sendList)) {
        struct nn_llist_iterator it = nn_llist_begin(&conn->sendList);
        struct np_dtls_send_context* first = nn_llist_get_item(&it);
        nn_llist_erase(&it);
        np_completion_event_resolve(&first->ev, NABTO_EC_CONNECTION_CLOSING);
    }

    np_event_queue_destroy_event(&conn->pl->eq, conn->timerEvent);
    np_event_queue_destroy_event(&conn->pl->eq, conn->startSendEvent);
    np_completion_event_deinit(&conn->senderEvent);

    SSL_free(conn->ssl);
    np_free(conn);
}

np_error_code set_keys(struct np_platform* pl,
                       const unsigned char* certificate, size_t certificateSize,
                       const unsigned char* privateKeyL, size_t privateKeySize)
{
    struct nm_openssl_cli_context* ctx = (struct nm_openssl_cli_context*)pl->dtlsCData;
    if (ctx == NULL || ctx->ctx == NULL) {
        return NABTO_EC_INVALID_STATE;
    }
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
    if (SSL_CTX_use_certificate(ctx->ctx, crt) != 1 ||
        SSL_CTX_use_PrivateKey(ctx->ctx, key) != 1) {
        NABTO_LOG_ERROR(LOG, "Cannot use the certificate and private key");
        nm_openssl_util_log_errors(LOG);
        ec = NABTO_EC_UNKNOWN;
    }
    X509_free(crt);
    EVP_PKEY_free(key);
    return ec;
}

static np_error_code load_root_certs(X509_STORE* store, const char* rootCerts)
{
    size_t len = strlen(rootCerts);
    if (len > INT_MAX) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    BIO* bio = BIO_new_mem_buf(rootCerts, (int)len);
    if (bio == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    STACK_OF(X509_INFO)* infos = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (infos == NULL) {
        return NABTO_EC_UNKNOWN;
    }
    np_error_code ec = NABTO_EC_OK;
    int count = 0;
    for (int i = 0; i < sk_X509_INFO_num(infos); i++) {
        X509_INFO* info = sk_X509_INFO_value(infos, i);
        if (info->x509 == NULL) {
            continue;
        }
        if (X509_STORE_add_cert(store, info->x509) != 1) {
            ec = NABTO_EC_UNKNOWN;
            break;
        }
        count++;
    }
    sk_X509_INFO_pop_free(infos, X509_INFO_free);
    if (ec == NABTO_EC_OK && count == 0 && len > 0) {
        // The string is not empty but contains no certificates.
        ec = NABTO_EC_UNKNOWN;
    }
    return ec;
}

np_error_code set_root_certs(struct np_platform* pl, const char* rootCerts)
{
    struct nm_openssl_cli_context* ctx = (struct nm_openssl_cli_context*)pl->dtlsCData;
    if (ctx == NULL || ctx->ctx == NULL) {
        return NABTO_EC_INVALID_STATE;
    }
    // The certs replace the trusted roots, including the default ones.
    X509_STORE* store = X509_STORE_new();
    if (store == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    np_error_code ec = load_root_certs(store, rootCerts);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to load root certs");
        nm_openssl_util_log_errors(LOG);
        // The certs loaded before the failure must not be trusted.
        X509_STORE_free(store);
        store = X509_STORE_new();
        if (store == NULL) {
            return NABTO_EC_OUT_OF_MEMORY;
        }
    }
    // The ctx takes ownership of the store and frees the old one. The store
    // is looked up in the ctx when a certificate is verified, so the roots also
    // apply to handshakes which are in progress, as with mbedtls.
    SSL_CTX_set_cert_store(ctx->ctx, store);
    return ec;
}

/**
 * get peers fingerprint for given DTLS client context
 */
np_error_code get_fingerprint(struct np_dtls_cli_connection* conn, uint8_t* fp)
{
    X509* crt = SSL_get0_peer_certificate(conn->ssl);
    if (crt == NULL) {
        return NABTO_EC_UNKNOWN;
    }
    return nm_openssl_util_fp_from_crt(crt, fp);
}

np_error_code set_handshake_timeout(struct np_platform* pl, uint32_t minTimeout, uint32_t maxTimeout)
{
    struct nm_openssl_cli_context* ctx = (struct nm_openssl_cli_context*)pl->dtlsCData;
    if (ctx == NULL) {
        return NABTO_EC_INVALID_STATE;
    }
    ctx->timeoutMin = minTimeout;
    ctx->timeoutMax = maxTimeout;
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
    if (conn->state == CONNECTING) {
        event_handle_connecting_state(conn);
    } else if (conn->state == DATA) {
        ERR_clear_error();
        uint8_t* recvBuffer = NULL;
        int err = SSL_ERROR_NONE;
        int ret = nm_openssl_recv_data(conn->ssl, &recvBuffer, &err);
        if (ret > 0) {
            conn->recvCount++;
            uint64_t seq = conn->lastRecvSequenceNumber;
            conn->dataHandler(conn->recvChannelId, seq, recvBuffer, (uint16_t)ret, conn->callbackData);
            np_free(recvBuffer);
        } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // OK
        } else if (conn->lastRecvAlert == SSL_AD_ACCESS_DENIED) {
            NABTO_LOG_ERROR(LOG, "Server returned access denied");
            conn->state = CLOSING;
            np_event_queue_cancel_event(&conn->pl->eq, conn->timerEvent);
            conn->eventHandler(NP_DTLS_EVENT_ACCESS_DENIED, conn->callbackData);
        } else {
            if (err == SSL_ERROR_ZERO_RETURN) {
                NABTO_LOG_TRACE(LOG, "Received close notify, state = CLOSING");
            } else {
                NABTO_LOG_TRACE(LOG, "Received ERROR %d", err);
                nm_openssl_util_log_errors(LOG);
            }
            conn->state = CLOSING;
            nm_dtls_do_close(conn);
        }
    }
}

static enum np_dtls_event handshake_failure_event(struct np_dtls_cli_connection* conn)
{
    if (conn->lastRecvAlert == SSL_AD_ACCESS_DENIED) {
        NABTO_LOG_ERROR(LOG, "Server returned access denied");
        return NP_DTLS_EVENT_ACCESS_DENIED;
    }
    long verifyResult = SSL_get_verify_result(conn->ssl);
    if (conn->verifyCertificate && verifyResult != X509_V_OK) {
        NABTO_LOG_ERROR(LOG, "Certificate verification failed: (%ld) %s", verifyResult, X509_verify_cert_error_string(verifyResult));
        if (verifyResult == X509_V_ERR_CERT_NOT_YET_VALID ||
            verifyResult == X509_V_ERR_CERT_HAS_EXPIRED) {
            NABTO_LOG_ERROR(
                LOG,
                "Time may not be configured on this system. "
                "Certificates which are expired or starting in the "
                "future are often caused by mis-configured timezone or"
                " system time.");
        }
        return NP_DTLS_EVENT_CERTIFICATE_VERIFICATION_FAILED;
    }
    if (conn->lastRecvAlert >= 0) {
        NABTO_LOG_ERROR(LOG, "Server returned fatal alert code: %d", conn->lastRecvAlert);
    }
    return NP_DTLS_EVENT_CLOSED;
}

void event_handle_connecting_state(struct np_dtls_cli_connection* conn)
{
    ERR_clear_error();
    int ret = SSL_do_handshake(conn->ssl);
    if (ret != 1) {
        int err = SSL_get_error(conn->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // Keep State CONNECTING
            set_timeout(conn);
            return;
        }
        NABTO_LOG_INFO(LOG, "SSL_do_handshake failed with %d", err);
        nm_openssl_util_log_errors(LOG);
        enum np_dtls_event event = handshake_failure_event(conn);
        conn->state = CLOSING;
        np_event_queue_cancel_event(&conn->pl->eq, conn->timerEvent);
        conn->eventHandler(event, conn->callbackData);
        return;
    }

    np_event_queue_cancel_event(&conn->pl->eq, conn->timerEvent);
    if (get_alpn_protocol(conn) == NULL) {
        NABTO_LOG_ERROR(LOG, "Application Layer Protocol Negotiation failed for DTLS client connection");
        conn->state = CLOSING;
        conn->eventHandler(NP_DTLS_EVENT_CLOSED, conn->callbackData);
        return;
    }

    NABTO_LOG_TRACE(LOG, "State changed to DATA");
    conn->state = DATA;
    conn->eventHandler(NP_DTLS_EVENT_HANDSHAKE_COMPLETE, conn->callbackData);
}

unsigned int timer_callback(SSL* ssl, unsigned int timerUs)
{
    struct np_dtls_cli_connection* conn = SSL_get_app_data(ssl);
    struct nm_openssl_cli_context* ctx = (struct nm_openssl_cli_context*)conn->pl->dtlsCData;
    // The retransmission timeout is doubled from timeoutMin up to timeoutMax,
    // handle_timeout fails the handshake when the timeout at timeoutMax
    // expires. This is how mbedtls uses the handshake timeouts.
    uint64_t minUs = (uint64_t)ctx->timeoutMin * 1000;
    uint64_t maxUs = (uint64_t)ctx->timeoutMax * 1000;
    uint64_t next = 0;
    if (timerUs == 0) {
        next = minUs;
    } else {
        next = (uint64_t)timerUs * 2;
    }
    if (next > maxUs) {
        next = maxUs;
    }
    if (next > UINT_MAX) {
        next = UINT_MAX;
    }
    conn->timeoutUs = (unsigned int)next;
    return conn->timeoutUs;
}

void set_timeout(struct np_dtls_cli_connection* conn)
{
    struct timeval tv;
    np_event_queue_cancel_event(&conn->pl->eq, conn->timerEvent);
    if (DTLSv1_get_timeout(conn->ssl, &tv) == 1) {
        uint64_t ms = (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
        np_event_queue_post_timed_event(&conn->pl->eq, conn->timerEvent, (uint32_t)ms);
    }
}

void handle_timeout(void* data)
{
    struct np_dtls_cli_connection* conn = data;
    struct nm_openssl_cli_context* ctx = (struct nm_openssl_cli_context*)conn->pl->dtlsCData;
    if (conn->state != CONNECTING) {
        return;
    }
    struct timeval tv;
    if (DTLSv1_get_timeout(conn->ssl, &tv) != 1) {
        // No timer is running.
        return;
    }
    if (tv.tv_sec > 0 || tv.tv_usec > 0) {
        // The OpenSSL timer has not expired yet.
        set_timeout(conn);
        return;
    }
    if ((uint64_t)conn->timeoutUs >= (uint64_t)ctx->timeoutMax * 1000) {
        NABTO_LOG_TRACE(LOG, "DTLS handshake timed out");
        conn->state = CLOSING;
        conn->eventHandler(NP_DTLS_EVENT_CLOSED, conn->callbackData);
        return;
    }
    ERR_clear_error();
    if (DTLSv1_handle_timeout(conn->ssl) < 0) {
        NABTO_LOG_ERROR(LOG, "DTLS handshake retransmission failed");
        nm_openssl_util_log_errors(LOG);
        conn->state = CLOSING;
        conn->eventHandler(NP_DTLS_EVENT_CLOSED, conn->callbackData);
        return;
    }
    set_timeout(conn);
}

void nm_dtls_do_close(struct np_dtls_cli_connection* conn)
{
    NABTO_LOG_TRACE(LOG, "Closing DTLS Client Connection");
    np_event_queue_cancel_event(&conn->pl->eq, conn->timerEvent);
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

    if (next->bufferSize > DTLS_get_data_mtu(conn->ssl)) {
        // The record would be larger than a communication buffer.
        NABTO_LOG_ERROR(LOG, "ssl_write failed (Packet too large)");
        np_completion_event_resolve(&next->ev, NABTO_EC_MALFORMED_PACKET);
    } else {
        ERR_clear_error();
        conn->sendChannelId = next->channelId;
        int ret = SSL_write(conn->ssl, next->buffer, (int)next->bufferSize);
        conn->sendChannelId = NP_DTLS_DEFAULT_CHANNEL_ID;

        if (ret <= 0) {
            int err = SSL_get_error(conn->ssl, ret);
            NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i", err);
            nm_openssl_util_log_errors(LOG);
            np_completion_event_resolve(&next->ev, NABTO_EC_UNKNOWN);
        } else {
            conn->sentCount++;
            np_completion_event_resolve(&next->ev, NABTO_EC_OK);
        }
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
    if (!conn) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    if (conn->state != CLOSING) {
        NABTO_LOG_TRACE(LOG, "Closing DTLS cli from state: %u", conn->state);
        bool handshakeDone = conn->state == DATA;
        conn->state = CLOSING;
        if (handshakeDone) {
            // Send close notify, a failure is not an error as the connection
            // is closed anyway.
            ERR_clear_error();
            SSL_shutdown(conn->ssl);
            ERR_clear_error();
        }
        if (conn->sslSendBuffer == NULL) {
            nm_dtls_do_close(conn);
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
    conn->recvChannelId = NP_DTLS_DEFAULT_CHANNEL_ID;
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

    conn->pl->buf.free(conn->sslSendBuffer);
    conn->sslSendBuffer = NULL;
    if (conn->state == CLOSING) {
        NABTO_LOG_TRACE(LOG, "udp send cb after close");
        if (conn->destroyed) {
            if (!conn->receiving) {
                do_free_connection(conn);
            }
            return;
        }
        nm_dtls_do_close(conn);
        return;
    }
    if (conn->state == DATA) {
        start_send(conn);
    }
    // A handshake flight which did not fit in one datagram continues.
    event_do_one(conn);
}

// Function called by OpenSSL when a datagram should be sent to the network
int bio_write(BIO* bio, const char* buffer, int bufferSize)
{
    struct np_dtls_cli_connection* conn = BIO_get_data(bio);
    struct np_platform* pl = conn->pl;
    BIO_clear_retry_flags(bio);
    if (conn->sslSendBuffer != NULL) {
        BIO_set_retry_write(bio);
        return -1;
    }
    if (bufferSize < 0) {
        return -1;
    }
    conn->sslSendBuffer = pl->buf.allocate();
    if (conn->sslSendBuffer == NULL) {
        NABTO_LOG_ERROR(LOG,
                        "Cannot allocate a buffer for sending a packet "
                        "from the dtls client. Dropping the packet");
        // dropping the packet as there is no way to trigger a
        // retransmission of the packet once the system has available memory
        // again.
        return bufferSize;
    }
    if ((size_t)bufferSize + NP_DTLS_CONNECTION_ID_HEADER_SIZE > pl->buf.size(conn->sslSendBuffer)) {
        // Cannot happen as the mtu leaves room for the connection id
        // header in a communication buffer.
        NABTO_LOG_ERROR(LOG,
                        "The dtls record (%d bytes) does not fit in a "
                        "communication buffer. Dropping the packet",
                        bufferSize);
        pl->buf.free(conn->sslSendBuffer);
        conn->sslSendBuffer = NULL;
        return bufferSize;
    }
    memcpy(pl->buf.start(conn->sslSendBuffer), buffer, (size_t)bufferSize);
    np_error_code ec = conn->sender(conn->sendChannelId, pl->buf.start(conn->sslSendBuffer), (uint16_t)bufferSize,
                                    &conn->senderEvent, conn->callbackData);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_INFO(LOG, "DTLS sender failed with error: %d", ec);
        pl->buf.free(conn->sslSendBuffer);
        conn->sslSendBuffer = NULL;
        // dropping the packet as there is no way to trigger a
        // retransmission of the data.
        return bufferSize;
    }
    return bufferSize;
}

// Function called by OpenSSL when it wants a datagram from the network
int bio_read(BIO* bio, char* buffer, int bufferSize)
{
    struct np_dtls_cli_connection* conn = BIO_get_data(bio);
    BIO_clear_retry_flags(bio);
    if (conn->recvBufferSize == 0) {
        BIO_set_retry_read(bio);
        return -1;
    }
    if (bufferSize < 0) {
        return -1;
    }
    size_t maxCp = (size_t)bufferSize > conn->recvBufferSize ? conn->recvBufferSize : (size_t)bufferSize;
    memcpy(buffer, conn->recvBuffer, maxCp);
    conn->recvBufferSize = 0;
    return (int)maxCp;
}

void msg_callback(int writeP, int version, int contentType, const void* buf,
                  size_t len, SSL* ssl, void* arg)
{
    (void)version;
    (void)ssl;
    struct np_dtls_cli_connection* conn = arg;
    if (!writeP) {
        if (contentType == SSL3_RT_HEADER) {
            // Called with the header of each record which is read.
            nm_openssl_util_record_sequence_number(buf, len, &conn->lastRecvSequenceNumber);
        } else if (contentType == SSL3_RT_ALERT && len >= 2) {
            conn->lastRecvAlert = ((const uint8_t*)buf)[1];
        }
    }
    nm_openssl_util_log_message(LOG, writeP, contentType, buf, len);
}
