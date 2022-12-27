#include "nm_wolfssl_cli.h"
#include "nm_wolfssl_util.h"
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
#include <wolfssl/error-ssl.h>

#include <string.h>

#include <stdio.h>

#include <nn/llist.h>
#include <nn/string.h>

#define LOG NABTO_LOG_MODULE_DTLS_CLI

static const char* allowedCipherSuitesList = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM";
static const char* alpnList = NABTO_PROTOCOL_VERSION;


struct nm_wolfssl_cli_context {
    struct np_platform* pl;

    WOLFSSL_CTX* ctx;

    int timeoutMin;
    int timeoutMax;
};

struct np_dtls_cli_connection {
    struct np_platform* pl;
    WOLFSSL* ssl;
    enum sslState state;
    // Ciphertext datagram recvBuffer temporary variable.
    uint8_t* recvBuffer;
    size_t recvBufferSize;

    // Allocated when sending a packet with ciphertext through the UDP layer.
    struct np_communication_buffer* sslSendBuffer;

    struct np_event* timerEvent;

    uint32_t recvCount;
    uint32_t sentCount;

    struct nn_llist sendList;
    struct np_event* startSendEvent;

    struct np_completion_event senderEvent;

    bool receiving;
    bool destroyed;

    np_dtls_sender sender;
    np_dtls_data_handler dataHandler;
    np_dtls_event_handler eventHandler;
    void* callbackData;
    uint8_t sendChannelId;
    uint8_t recvChannelId;
    uint64_t lastRecvSequenceNumber;
};

// Module function definitions
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

static np_error_code nm_wolfssl_connect(struct np_dtls_cli_connection* conn);
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


// Internal function definitions
static np_error_code initialize_context(struct np_platform* pl);
static void do_destroy_connection(struct np_dtls_cli_connection* conn);

// Old internal functions
static void set_timeout(struct np_dtls_cli_connection* conn);
static void handle_timeout(void* data);

// Function called by wolfssl when data should be sent to the network
static int nm_dtls_wolfssl_send(WOLFSSL* ssl, char* buffer, int bufferSize, void* userData);
// Function called by wolfssl when it wants data from the network
static int nm_dtls_wolfssl_recv(WOLFSSL* ssl, char* buffer, int bufferSize, void* userData);
// Function used to handle events during the connection phase
static void event_do_one(void* data);

static void start_send_deferred(void* data);

static void nm_wolfssl_do_close(void* data, np_error_code ec);

static void nm_dtls_udp_send_callback(const np_error_code ec, void* data);

static np_error_code get_certificate_expiration(struct np_dtls_cli_connection* conn, uint64_t* expiration);


// Get the packet counters for given dtls_cli_context
np_error_code get_packet_count(struct np_dtls_cli_connection* ctx, uint32_t* recvCount, uint32_t* sentCount)
{
    *recvCount = ctx->recvCount;
    *sentCount = ctx->sentCount;
    return NABTO_EC_OK;
}

// Get the result of the application layer protocol negotiation
// TODO: remove this function here, in platform, in mbedtls
const char* get_alpn_protocol(struct np_dtls_cli_connection* ctx) {
    return NULL;
}


/*
 * Initialize the np_platform to use this particular dtls cli module
 */
np_error_code nm_wolfssl_cli_init(struct np_platform* pl)
{
    pl->dtlsC.create_attach_connection = &create_attach_connection;
    pl->dtlsC.create_client_connection = &create_client_connection;
    pl->dtlsC.destroy_connection = &destroy_connection;
    pl->dtlsC.set_keys = &set_keys;
    pl->dtlsC.set_handshake_timeout = &set_handshake_timeout;
    pl->dtlsC.set_root_certs = &set_root_certs;
    pl->dtlsC.connect = &nm_wolfssl_connect;
    pl->dtlsC.async_send_data = &async_send_data;
    pl->dtlsC.handle_packet = &handle_packet;
    pl->dtlsC.async_close = &async_close;
    pl->dtlsC.get_fingerprint = &get_fingerprint;
    pl->dtlsC.get_alpn_protocol = &get_alpn_protocol;
    pl->dtlsC.get_packet_count = &get_packet_count;
    pl->dtlsC.get_certificate_expiration = &get_certificate_expiration;

    return initialize_context(pl);
}

void nm_wolfssl_cli_deinit(struct np_platform* pl)
{
    struct nm_wolfssl_cli_context* ctx =
        (struct nm_wolfssl_cli_context*)pl->dtlsCData;

    wolfSSL_CTX_free(ctx->ctx);
    np_free(ctx);
    pl->dtlsCData = NULL;
}


np_error_code initialize_context(struct np_platform* pl)
{
    struct nm_wolfssl_cli_context* ctx =
        np_calloc(1, sizeof(struct nm_wolfssl_cli_context));
    if (ctx == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    pl->dtlsCData = ctx;
    ctx->pl = pl;
    WOLFSSL_METHOD *method = wolfDTLSv1_2_client_method();
    ctx->ctx = wolfSSL_CTX_new(method);

    nm_wolfssl_util_check_logging();
    ctx->timeoutMin = 1;
    ctx->timeoutMax = 16;

    if (wolfSSL_CTX_set_cipher_list(ctx->ctx, allowedCipherSuitesList) != WOLFSSL_SUCCESS)
    {
        NABTO_LOG_ERROR(LOG, "server can't set custom cipher list");
        nm_wolfssl_cli_deinit(pl);
        return NABTO_EC_FAILED;
    }

    wolfSSL_CTX_SetIORecv(ctx->ctx, nm_dtls_wolfssl_recv);
    wolfSSL_CTX_SetIOSend(ctx->ctx, nm_dtls_wolfssl_send);

    return NABTO_EC_OK;
}


static np_error_code create_client_connection(
    struct np_platform* pl, struct np_dtls_cli_connection** connection,
    np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
    np_dtls_event_handler eventHandler, void* data)
{
    struct nm_wolfssl_cli_context* ctx = (struct nm_wolfssl_cli_context*)pl->dtlsCData;
    if (ctx == NULL) {
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
    conn->sendChannelId = NP_DTLS_CLI_DEFAULT_CHANNEL_ID;
    conn->recvChannelId = NP_DTLS_CLI_DEFAULT_CHANNEL_ID;

    nn_llist_init(&conn->sendList);
    conn->destroyed = false;

    np_error_code ec = np_event_queue_create_event(&pl->eq, handle_timeout, conn, &conn->timerEvent);
    if (ec != NABTO_EC_OK) {
        do_destroy_connection(conn);
        return ec;
    }
    ec = np_event_queue_create_event(&pl->eq, &start_send_deferred, conn, &conn->startSendEvent);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(&pl->eq, &conn->senderEvent,
                                  &nm_dtls_udp_send_callback, conn);

    conn->ssl = wolfSSL_new(ctx->ctx);
    if (conn->ssl == NULL) {
        NABTO_LOG_ERROR(LOG,  "Failed  to create wolfSSL object");
        do_destroy_connection(conn);
        return NABTO_EC_UNKNOWN;
    }

    wolfSSL_SetIOReadCtx(conn->ssl, conn);
    wolfSSL_SetIOWriteCtx(conn->ssl, conn);
    wolfSSL_dtls_set_using_nonblock(conn->ssl, 1);
    if (wolfSSL_UseALPN(conn->ssl, (char *)(alpnList), strlen(alpnList), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
    {
        NABTO_LOG_ERROR(LOG, "cannot set alpn list");
        do_destroy_connection(conn);
        return NABTO_EC_FAILED;
    }

    if (wolfSSL_dtls_set_timeout_init(conn->ssl, ctx->timeoutMin) !=
            WOLFSSL_SUCCESS ||
        wolfSSL_dtls_set_timeout_max(conn->ssl, ctx->timeoutMax) !=
            WOLFSSL_SUCCESS) {
        NABTO_LOG_ERROR(LOG, "Cannot set timeout for DTLS client connection");
        do_destroy_connection(conn);
        return NABTO_EC_FAILED;
    };

    wolfSSL_set_verify(conn->ssl, (WOLFSSL_VERIFY_NONE), NULL);

    *connection = conn;
    return NABTO_EC_OK;
}

static np_error_code create_attach_connection(
    struct np_platform* pl, struct np_dtls_cli_connection** connection,
    const char* sni, bool disable_cert_validation,
    np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
    np_dtls_event_handler eventHandler, void* data)
{
    np_error_code ec = create_client_connection(
        pl, connection, packetSender, dataHandler, eventHandler, data);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    if(wolfSSL_UseSNI((*connection)->ssl, WOLFSSL_SNI_HOST_NAME, sni, strlen(sni) ) != WOLFSSL_SUCCESS )
    {
        NABTO_LOG_INFO(LOG,  "Failed to set SNI Hostname in the DTLS client");
        do_destroy_connection(*connection);
        return NABTO_EC_UNKNOWN;
    }

    if (wolfSSL_check_domain_name((*connection)->ssl, sni) != WOLFSSL_SUCCESS ) {
        NABTO_LOG_INFO(LOG,  "Failed to set check domain name in the DTLS client");
        do_destroy_connection(*connection);
        return NABTO_EC_UNKNOWN;
    }

    if (!disable_cert_validation) {
        wolfSSL_set_verify((*connection)->ssl, (WOLFSSL_VERIFY_PEER), NULL);
    }
    return NABTO_EC_OK;
}

void do_destroy_connection(struct np_dtls_cli_connection* conn)
{
    conn->state = CLOSING;
    conn->destroyed = true;
    // remove the first element until the list is empty
    while(!nn_llist_empty(&conn->sendList)) {
        struct nn_llist_iterator it = nn_llist_begin(&conn->sendList);
        struct np_dtls_send_context* first = nn_llist_get_item(&it);
        nn_llist_erase(&it);
        np_completion_event_resolve(&first->ev, NABTO_EC_CONNECTION_CLOSING);
    }

    np_event_queue_destroy_event(&conn->pl->eq, conn->timerEvent);
    np_event_queue_destroy_event(&conn->pl->eq, conn->startSendEvent);
    np_completion_event_deinit(&conn->senderEvent);

    wolfSSL_free(conn->ssl);
    np_free(conn);
}

void destroy_connection(struct np_dtls_cli_connection* conn)
{
    conn->state = CLOSING;
    conn->destroyed = true;

    if (conn->sslSendBuffer == NULL && !conn->receiving) {
        do_destroy_connection(conn);
    }
}

np_error_code set_keys(struct np_platform* pl,
                                   const unsigned char* certificate, size_t certificateSize,
                                   const unsigned char* privateKeyL, size_t privateKeySize)
{
    struct nm_wolfssl_cli_context* ctx =
        (struct nm_wolfssl_cli_context*)pl->dtlsCData;
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx->ctx, privateKeyL, privateKeySize, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        NABTO_LOG_ERROR(LOG, "wolfSSL_CTX_use_PrivateKey_buffer");
        return NABTO_EC_UNKNOWN;
    }

    if (wolfSSL_CTX_use_certificate_buffer(ctx->ctx, certificate, certificateSize, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        NABTO_LOG_ERROR(LOG, "wolfSSL_CTX_use_certificate_buffer");
        return NABTO_EC_UNKNOWN;
    }

    return NABTO_EC_OK;
}

np_error_code set_root_certs(struct np_platform* pl, const char* rootCerts)
{
    struct nm_wolfssl_cli_context* ctx =
        (struct nm_wolfssl_cli_context*)pl->dtlsCData;

    if (wolfSSL_CTX_load_verify_buffer(ctx->ctx, (const unsigned char*)rootCerts, strlen(rootCerts), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
    {
        NABTO_LOG_ERROR(LOG, "cannot load ca certificate");
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;
}

/**
 * get peers fingerprint for given DTLS client context
 */
np_error_code get_fingerprint(struct np_dtls_cli_connection* conn, uint8_t* fp)
{
    // Get client fingerprint
    WOLFSSL_X509 *crt = wolfSSL_get_peer_certificate(conn->ssl);
    if (!crt) {
        return NABTO_EC_UNKNOWN;
    }
    return nm_wolfssl_util_fp_from_crt(crt, fp);
}

np_error_code set_handshake_timeout(struct np_platform* pl, uint32_t minTimeout, uint32_t maxTimeout)
{
    struct nm_wolfssl_cli_context* ctx =
        (struct nm_wolfssl_cli_context*)pl->dtlsCData;

    ctx->timeoutMin = minTimeout < 1000 ? 1 : minTimeout / 1000;
    ctx->timeoutMax = maxTimeout < 1000 ? 1 : maxTimeout / 1000;
    ctx->timeoutMax = ctx->timeoutMin >= ctx->timeoutMax ? ctx->timeoutMin + 1
                                                         : ctx->timeoutMax;
    return NABTO_EC_OK;
}

/*
 * asyncroniously start a dtls connection
 */
np_error_code nm_wolfssl_connect(struct np_dtls_cli_connection* conn)
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
        ret = wolfSSL_connect(conn->ssl);
        if (ret != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(conn->ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ) {
                NABTO_LOG_TRACE(LOG, "Want Read");
                set_timeout(conn);
            } else if (err == WOLFSSL_ERROR_WANT_WRITE || err == 0){
// TODO: remove err == 0 when https://github.com/wolfSSL/wolfssl/issues/5325 is resolved
                NABTO_LOG_TRACE(LOG, "Want Write");
                // Wait for IO to happen
            } else {
                enum np_dtls_event event = NP_DTLS_EVENT_CLOSED;
                char buf[80];
                wolfSSL_ERR_error_string(err, buf);
                if (err > MIN_CODE_E) { // All wolfCrypt errors range ]MIN_CODE_E...0[
                    // This matches all wolfCrypt errors which may include errors other than verification errors.
                    NABTO_LOG_ERROR(LOG, "Certificate verification failed: (%d) %s", err, buf);
                    event = NP_DTLS_EVENT_CERTIFICATE_VERIFICATION_FAILED;
                } else if( err == FATAL_ERROR ) {
                    WOLFSSL_ALERT_HISTORY h;
                    wolfSSL_get_alert_history(conn->ssl, &h);
                    if (h.last_rx.code == access_denied) {
                        event = NP_DTLS_EVENT_ACCESS_DENIED;
                        NABTO_LOG_ERROR(LOG, "Server returned access denied: (%d) %s" , err, buf);
                    } else {
                        NABTO_LOG_ERROR(
                            LOG, "Server returned fatal alert code: %d",
                            h.last_rx.code);
                    }
                }
                NABTO_LOG_INFO( LOG, "wolfssl_connect returned %d, which is %d, %s", ret , err, buf);
                conn->state = CLOSING;
                np_event_queue_cancel_event(&conn->pl->eq, conn->timerEvent);
                conn->eventHandler(event, conn->callbackData);
                return;
            }
        } else if (ret == WOLFSSL_SUCCESS) {
            NABTO_LOG_TRACE(LOG, "State changed to DATA");
            conn->state = DATA;
            np_event_queue_cancel_event(&conn->pl->eq, conn->timerEvent);
            conn->eventHandler(NP_DTLS_EVENT_HANDSHAKE_COMPLETE, conn->callbackData);
        } else {
            NABTO_LOG_ERROR(LOG, "unknown case %d", ret );
        }
    } else if(conn->state == DATA) {
        uint8_t recvBuffer[1500];
        ret = wolfSSL_read( conn->ssl, recvBuffer, (int)sizeof(recvBuffer) );

        if (ret == 0) {
            // EOF
            conn->state = CLOSING;
            NABTO_LOG_TRACE(LOG, "Received EOF, state = CLOSING");
            nm_wolfssl_do_close(conn, NABTO_EC_FAILED);
        } else if (ret > 0) {
            uint64_t seq = conn->lastRecvSequenceNumber;
            conn->recvCount++;
            conn->dataHandler(conn->recvChannelId, seq, recvBuffer, (uint16_t)ret, conn->callbackData);
            return;
        } else if (ret == WOLFSSL_FATAL_ERROR) {
            int err = wolfSSL_get_error(conn->ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
            {
                // ok
            } else {
                char buf[80];
                wolfSSL_ERR_error_string(err, buf);
                if (err == FATAL_ERROR) {
                    WOLFSSL_ALERT_HISTORY h;
                    wolfSSL_get_alert_history(conn->ssl, &h);
                    if (h.last_rx.code == access_denied) {
                        NABTO_LOG_ERROR(LOG, "Server returned access denied: (%d) %s" , err, buf);
                        np_event_queue_cancel_event(&conn->pl->eq, conn->timerEvent);
                        conn->state = CLOSING;
                        conn->eventHandler(NP_DTLS_EVENT_ACCESS_DENIED, conn->callbackData);
                        return;
                    }
                }
                NABTO_LOG_TRACE(LOG, "Received unhandled wolfssl ERROR (%d) %s ", err, buf);
                conn->state = CLOSING;
                nm_wolfssl_do_close(conn, NABTO_EC_UNKNOWN);
            }
        }
        return;
    }
}

void set_timeout(struct np_dtls_cli_connection* conn)
{
    int timeout = wolfSSL_dtls_get_current_timeout(conn->ssl);
    np_event_queue_cancel_event(&conn->pl->eq, conn->timerEvent);
    if (timeout >= 0) {
        np_event_queue_post_timed_event(&conn->pl->eq, conn->timerEvent, (uint32_t)(timeout*1000));
    }
}

void handle_timeout(void* data)
{
    struct np_dtls_cli_connection* conn = data;
    int ec = wolfSSL_dtls_got_timeout(conn->ssl);
    if (ec == WOLFSSL_SUCCESS) {
        NABTO_LOG_TRACE(LOG, "Got timeout returned success");
        set_timeout(conn);
    } else if (ec == WOLFSSL_FATAL_ERROR) {
        int err = wolfSSL_get_error(conn->ssl, ec);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            NABTO_LOG_TRACE(LOG, "Got timeout returned want read/write");
            set_timeout(conn);
        } else {
            char buf[80];
            wolfSSL_ERR_error_string(err, buf);
            NABTO_LOG_ERROR(LOG, "Got timeout returned error: %s", buf);
            // too many retries, timeout.
            conn->eventHandler(NP_DTLS_EVENT_CLOSED, conn->callbackData);
        }
    } else {
        // NOT_COMPILED_IN etc
        NABTO_LOG_ERROR(LOG, "Unhandled wolfSSL_dtls_got_timeout error code.");
    }

}


void nm_wolfssl_cli_start_send(struct np_dtls_cli_connection* conn)
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

    int ret = wolfSSL_write( conn->ssl, (unsigned char *) next->buffer, next->bufferSize );
    conn->sendChannelId = NP_DTLS_CLI_DEFAULT_CHANNEL_ID;

    if (ret < 0) {
        // unknown error
        NABTO_LOG_ERROR(LOG, "ssl_write failed with: %i", ret);
        np_completion_event_resolve(&next->ev, NABTO_EC_UNKNOWN);
    } else {
        conn->sentCount++;
        np_completion_event_resolve(&next->ev, NABTO_EC_OK);
    }

    // can we send more packets?
    nm_wolfssl_cli_start_send(conn);
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
    nm_wolfssl_cli_start_send(conn);
    return NABTO_EC_OK;
}

void nm_wolfssl_do_close(void* data, np_error_code ec){
    (void)ec;
    struct np_dtls_cli_connection* conn = data;
    NABTO_LOG_TRACE(LOG, "Closing DTLS Client Connection");
    np_event_queue_cancel_event(&conn->pl->eq, conn->timerEvent);
    conn->eventHandler(NP_DTLS_EVENT_CLOSED, conn->callbackData);
}

np_error_code async_close(struct np_dtls_cli_connection* conn)
{
    if (!conn) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    if (conn->state != CLOSING) {
        NABTO_LOG_TRACE(LOG, "Closing DTLS cli from state: %u", conn->state);
        conn->state = CLOSING;
        wolfSSL_shutdown(conn->ssl);
        if (conn->sslSendBuffer == NULL) {
            nm_wolfssl_do_close(conn, /*unused*/ NABTO_EC_OK);
        }
    } else {
        NABTO_LOG_TRACE(LOG, "Tried Closing DTLS cli but was already closed");
        return NABTO_EC_INVALID_STATE;
    }
    return NABTO_EC_OK;
}

np_error_code handle_packet(struct np_dtls_cli_connection* conn, uint8_t channelId,
                            uint8_t* buffer, uint16_t bufferSize)
{
    conn->recvBuffer = buffer;
    conn->recvBufferSize = bufferSize;
    conn->receiving = true;
    conn->recvChannelId = channelId;
    event_do_one(conn);
    conn->recvChannelId = NP_DTLS_CLI_DEFAULT_CHANNEL_ID;
    conn->recvBuffer = NULL;
    if (conn->recvBufferSize != 0) {
        NABTO_LOG_TRACE(LOG, "Discarding received data");
    }
    conn->recvBufferSize = 0;
    conn->receiving = false;
    if (conn->destroyed && conn->sslSendBuffer == NULL) {
        do_destroy_connection(conn);
    }
    return NABTO_EC_OK;
}

void nm_dtls_udp_send_callback(const np_error_code ec, void* data)
{
    (void)ec;
    struct np_dtls_cli_connection* conn = data;
    if (data == NULL) {
        return;
    }

    conn->pl->buf.free(conn->sslSendBuffer);

    if (conn->state == CLOSING) {
        NABTO_LOG_TRACE(LOG, "udp send cb after close");
    }
    if(conn->state == CLOSING) {
        nm_wolfssl_do_close(conn, /* ec unused */NABTO_EC_OK);
        if (conn->destroyed) {
            do_destroy_connection(conn);
        }
        return;
    }
    conn->sslSendBuffer = NULL;
    if (conn->state == DATA) {
        nm_wolfssl_cli_start_send(conn);
    }
    event_do_one(data);
}

int nm_dtls_wolfssl_send(WOLFSSL* ssl, char* buffer,
                         int bufferSize, void* data)
{
    struct np_dtls_cli_connection* conn = data;
    struct np_platform* pl = conn->pl;
    if (conn->state == CLOSING) {
        NABTO_LOG_TRACE(LOG, "wolfssl want send after close");
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
        memcpy(pl->buf.start(conn->sslSendBuffer), buffer, bufferSize);
        np_error_code ec =
            conn->sender(conn->sendChannelId, pl->buf.start(conn->sslSendBuffer), (uint16_t)bufferSize,
                        &conn->senderEvent, conn->callbackData);
        if (ec != NABTO_EC_OK) {
            NABTO_LOG_INFO(LOG,"DTLS sender failed with error: %d", ec);
            pl->buf.free(conn->sslSendBuffer);
            conn->sslSendBuffer = NULL;
            if (conn->state == CLOSING) {
                nm_wolfssl_do_close(conn, /* ec unused */ NABTO_EC_OK);
                if (conn->destroyed) {
                    do_destroy_connection(conn);
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

static uint64_t uint64_from_bigendian(uint8_t* bytes)
{
    return (((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48) |
            ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32) |
            ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16) |
            ((uint64_t)bytes[6] << 8) | ((uint64_t)bytes[7]));
}

int nm_dtls_wolfssl_recv(WOLFSSL* ssl, char* buffer, int bufferSize, void* data)
{
    struct np_dtls_cli_connection* conn = data;
    if (conn->recvBufferSize == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    } else {
        if (conn->recvBufferSize >= 12) {
            conn->lastRecvSequenceNumber =
                uint64_from_bigendian(conn->recvBuffer + 4);
        }
        size_t maxCp = bufferSize > conn->recvBufferSize ? conn->recvBufferSize : bufferSize;
        memcpy(buffer, conn->recvBuffer, maxCp);
        conn->recvBufferSize = 0;
        return (int)maxCp;
    }
}


static np_error_code get_certificate_expiration(struct np_dtls_cli_connection* conn, uint64_t* expiration)
{
    return NABTO_EC_NOT_IMPLEMENTED;
}
