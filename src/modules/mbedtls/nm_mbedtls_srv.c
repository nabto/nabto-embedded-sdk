#include "nm_mbedtls_srv.h"
#include "nm_mbedtls_common.h"
#include "nm_mbedtls_timer.h"
#include "nm_mbedtls_util.h"
#include <nabto/nabto_device_config.h>

#include <core/nc_version.h>
#include <platform/np_allocator.h>
#include <platform/np_completion_event.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_logging.h>

#if !defined(DEVICE_MBEDTLS_2)
#include <mbedtls/build_info.h>
#endif
#include <mbedtls/ssl_cookie.h>



#if !defined(NABTO_DEVICE_DTLS_CLIENT_ONLY)


#define LOG NABTO_LOG_MODULE_DTLS_SRV

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_COOKIE_C)
#define NM_MBEDTLS_SRV_COOKIES
#endif

#define NM_MBEDTLS_SRV_MAX_CLIENT_ID_SIZE 64

static const int allowedCipherSuitesList[] = { MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM, 0 };

const char* nm_mbedtls_srv_alpnList[] = {NABTO_PROTOCOL_VERSION , NULL};

struct np_dtls_srv_connection {
    struct np_platform* pl;
    struct np_dtls_srv* server;
    uint8_t clientId[NM_MBEDTLS_SRV_MAX_CLIENT_ID_SIZE];
    size_t clientIdSize;
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
#if defined(NM_MBEDTLS_SRV_COOKIES)
    mbedtls_ssl_cookie_ctx cookieCtx;
#endif
    uint16_t mtu;
};

static np_error_code nm_mbedtls_srv_create(struct np_platform* pl, struct np_dtls_srv** server);
static void nm_mbedtls_srv_destroy(struct np_dtls_srv* server);


static np_error_code nm_mbedtls_srv_init_config(struct np_dtls_srv* server,
                                             const unsigned char* publicKeyL, size_t publicKeySize,
                                             const unsigned char* privateKeyL, size_t privateKeySize);

static np_error_code nm_mbedtls_srv_set_keys(struct np_dtls_srv* server,
                                          const unsigned char* publicKeyL, size_t publicKeySize,
                                          const unsigned char* privateKeyL, size_t privateKeySize);

#if defined(NM_MBEDTLS_SRV_COOKIES)
static np_error_code nm_mbedtls_srv_verify_client_hello(struct np_dtls_srv* server,
                                                        const uint8_t* clientId, size_t clientIdSize,
                                                        const uint8_t* packet, size_t packetSize,
                                                        uint8_t* response, size_t* responseSize);
#endif

static np_error_code nm_mbedtls_srv_create_connection(struct np_dtls_srv* server,
                                                   const uint8_t* clientId, size_t clientIdSize,
                                                   struct np_dtls_srv_connection** dtls,
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
void nm_mbedtls_srv_connection_send_callback(np_error_code ec, void* data);
void nm_mbedtls_srv_do_one(void* data);
void nm_mbedtls_srv_start_send(struct np_dtls_srv_connection* ctx);
void nm_mbedtls_srv_start_send_deferred(void* data);
static void nm_mbedtls_srv_do_free_connection(struct np_dtls_srv_connection *conn);
static int nm_mbedtls_srv_reset_ssl(struct np_dtls_srv_connection* ctx);

// Function called by mbedtls when data should be sent to the network
int nm_mbedtls_srv_mbedtls_send(void* data, const unsigned char* buffer, size_t bufferSize);
// Function called by mbedtls when it wants data from the network
int nm_mbedtls_srv_mbedtls_recv(void* data, unsigned char* buffer, size_t bufferSize);

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
#if defined(NM_MBEDTLS_SRV_COOKIES)
    pl->dtlsS.verify_client_hello = &nm_mbedtls_srv_verify_client_hello;
#else
    NABTO_LOG_WARN(LOG, "mbedtls is built without MBEDTLS_SSL_DTLS_HELLO_VERIFY or MBEDTLS_SSL_COOKIE_C, the DTLS server cannot verify client addresses.");
    pl->dtlsS.verify_client_hello = NULL;
#endif
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
    np_error_code ec = nm_mbedtls_util_get_mtu(pl, &(*server)->mtu);
    if (ec != NABTO_EC_OK) {
        np_free(*server);
        *server = NULL;
        return ec;
    }
    mbedtls_ssl_config_init( &(*server)->conf );
    mbedtls_entropy_init( &(*server)->entropy );
    mbedtls_ctr_drbg_init( &(*server)->ctr_drbg );
    mbedtls_x509_crt_init( &(*server)->publicKey );
    mbedtls_pk_init( &(*server)->privateKey );
#if defined(NM_MBEDTLS_SRV_COOKIES)
    mbedtls_ssl_cookie_init( &(*server)->cookieCtx );
#endif
    return NABTO_EC_OK;
}

void nm_mbedtls_srv_destroy(struct np_dtls_srv* server)
{
    mbedtls_ssl_config_free( &server->conf );
    mbedtls_entropy_free( &server->entropy );
    mbedtls_ctr_drbg_free( &server->ctr_drbg );
    mbedtls_x509_crt_free( &server->publicKey );
    mbedtls_pk_free( &server->privateKey );
#if defined(NM_MBEDTLS_SRV_COOKIES)
    mbedtls_ssl_cookie_free( &server->cookieCtx );
#endif

    np_free(server);
}

np_error_code nm_mbedtls_srv_set_keys(struct np_dtls_srv* server,
                                   const unsigned char* publicKeyL, size_t publicKeySize,
                                   const unsigned char* privateKeyL, size_t privateKeySize)
{
    return nm_mbedtls_srv_init_config(server, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
}

np_error_code nm_mbedtls_srv_create_connection(struct np_dtls_srv* server,
                                            const uint8_t* clientId, size_t clientIdSize,
                                            struct np_dtls_srv_connection** dtls,
                                            np_dtls_sender sender,
                                            np_dtls_data_handler dataHandler,
                                            np_dtls_event_handler eventHandler, void* data)
{
    if (clientIdSize == 0 || clientIdSize > NM_MBEDTLS_SRV_MAX_CLIENT_ID_SIZE) {
        return NABTO_EC_INVALID_ARGUMENT;
    }
    struct np_dtls_srv_connection* ctx = (struct np_dtls_srv_connection*)np_calloc(1, sizeof(struct np_dtls_srv_connection));
    if(!ctx) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->pl = server->pl;
    ctx->server = server;
    memcpy(ctx->clientId, clientId, clientIdSize);
    ctx->clientIdSize = clientIdSize;
    ctx->sender = sender;
    ctx->dataHandler = dataHandler;
    ctx->eventHandler = eventHandler;
    ctx->senderData = data;
    ctx->channelId = NP_DTLS_DEFAULT_CHANNEL_ID;

    ctx->destroyed = false;
    ctx->receiving = false;

    nn_llist_init(&ctx->sendList);

    struct np_platform* pl = ctx->pl;

    np_error_code ec = np_event_queue_create_event(&pl->eq, &nm_mbedtls_srv_start_send_deferred, ctx, &ctx->startSendEvent);
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
    int ret = mbedtls_ssl_setup( &ctx->ssl, &server->conf );
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_setup returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }



    mbedtls_ssl_set_timer_cb(&ctx->ssl, &ctx->timer, &nm_mbedtls_timer_set_delay,
                              &nm_mbedtls_timer_get_delay );

    ret = nm_mbedtls_srv_reset_ssl(ctx);
    if (ret != 0) {
        return NABTO_EC_UNKNOWN;
    }

    mbedtls_ssl_set_bio( &ctx->ssl, ctx,
                         &nm_mbedtls_srv_mbedtls_send, &nm_mbedtls_srv_mbedtls_recv, NULL );

    mbedtls_ssl_set_mtu(&ctx->ssl, server->mtu);

    *dtls = ctx;
    return NABTO_EC_OK;
}

/**
 * Prepare the ssl context for a new handshake. The handshake parameters and the
 * client transport id are cleared by a session reset, so they are set again.
 */
int nm_mbedtls_srv_reset_ssl(struct np_dtls_srv_connection* ctx)
{
    int ret = mbedtls_ssl_session_reset( &ctx->ssl );
    if ( ret != 0) {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_session_reset returned %d", ret );
        return ret;
    }

#if defined(NM_MBEDTLS_SRV_COOKIES)
    ret = mbedtls_ssl_set_client_transport_id(&ctx->ssl, ctx->clientId, ctx->clientIdSize);
    if (ret != 0) {
        NABTO_LOG_ERROR(LOG, "mbedtls_ssl_set_client_transport_id() returned -0x%x", -ret);
        return ret;
    }
#endif

    mbedtls_ssl_set_hs_authmode( &ctx->ssl, MBEDTLS_SSL_VERIFY_OPTIONAL );

    ret = mbedtls_ssl_set_hs_own_cert(&ctx->ssl, &ctx->server->publicKey, &ctx->server->privateKey);
    if (ret != 0) {
        NABTO_LOG_ERROR(LOG, "failed ! mbedtls_ssl_set_hs_own_cert returned %d", ret);
        return ret;
    }
    return 0;
}

#if defined(NM_MBEDTLS_SRV_COOKIES)

#define DTLS_RECORD_HEADER_SIZE 13
#define DTLS_HANDSHAKE_HEADER_SIZE 12
#define DTLS_CONTENT_TYPE_HANDSHAKE 22
#define DTLS_HANDSHAKE_CLIENT_HELLO 1
#define DTLS_HANDSHAKE_HELLO_VERIFY_REQUEST 3

static uint32_t uint24_from_bigendian(const uint8_t* bytes)
{
    return ((uint32_t)bytes[0] << 16) | ((uint32_t)bytes[1] << 8) | (uint32_t)bytes[2];
}

static void uint24_to_bigendian(uint8_t* bytes, size_t value)
{
    bytes[0] = (uint8_t)(value >> 16);
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)value;
}

/**
 * Stateless version of the cookie exchange mbedtls does in
 * ssl_parse_client_hello, so no ssl context has to be allocated for a peer
 * before it has proven that it owns its source address.
 */
np_error_code nm_mbedtls_srv_verify_client_hello(struct np_dtls_srv* server,
                                                 const uint8_t* clientId, size_t clientIdSize,
                                                 const uint8_t* packet, size_t packetSize,
                                                 uint8_t* response, size_t* responseSize)
{
    if (packetSize < DTLS_RECORD_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE) {
        return NABTO_EC_MALFORMED_PACKET;
    }
    const uint8_t* record = packet;
    size_t recordLength = ((size_t)record[11] << 8) | record[12];
    if (record[0] != DTLS_CONTENT_TYPE_HANDSHAKE ||
        record[3] != 0 || record[4] != 0 || // epoch
        recordLength > packetSize - DTLS_RECORD_HEADER_SIZE ||
        recordLength < DTLS_HANDSHAKE_HEADER_SIZE)
    {
        return NABTO_EC_MALFORMED_PACKET;
    }

    const uint8_t* handshake = record + DTLS_RECORD_HEADER_SIZE;
    size_t messageLength = uint24_from_bigendian(handshake + 1);
    // Only unfragmented ClientHellos are accepted, a fragmented one is answered
    // by mbedtls with an error anyway.
    if (handshake[0] != DTLS_HANDSHAKE_CLIENT_HELLO ||
        uint24_from_bigendian(handshake + 6) != 0 ||
        uint24_from_bigendian(handshake + 9) != messageLength ||
        messageLength > recordLength - DTLS_HANDSHAKE_HEADER_SIZE)
    {
        return NABTO_EC_MALFORMED_PACKET;
    }

    // client_version(2) random(32) session_id<0..32> cookie<0..2^8-1>
    const uint8_t* body = handshake + DTLS_HANDSHAKE_HEADER_SIZE;
    size_t offset = 2 + 32;
    if (offset + 1 > messageLength) {
        return NABTO_EC_MALFORMED_PACKET;
    }
    size_t sessionIdLength = body[offset];
    if (sessionIdLength > 32) {
        return NABTO_EC_MALFORMED_PACKET;
    }
    offset += 1 + sessionIdLength;
    if (offset + 1 > messageLength) {
        return NABTO_EC_MALFORMED_PACKET;
    }
    size_t cookieLength = body[offset];
    offset += 1;
    if (offset + cookieLength > messageLength) {
        return NABTO_EC_MALFORMED_PACKET;
    }
    const uint8_t* cookie = body + offset;

    if (cookieLength > 0 &&
        mbedtls_ssl_cookie_check(&server->cookieCtx, cookie, cookieLength, clientId, clientIdSize) == 0)
    {
        return NABTO_EC_OK;
    }

    // Answer with a HelloVerifyRequest using the record and message sequence
    // numbers of the ClientHello, as mbedtls does.
    uint8_t* end = response + NP_DTLS_SRV_MAX_HELLO_VERIFY_SIZE;
    uint8_t* hvrHandshake = response + DTLS_RECORD_HEADER_SIZE;
    uint8_t* p = hvrHandshake + DTLS_HANDSHAKE_HEADER_SIZE;
    // server_version, the version negotiated later is DTLS 1.2.
    *p++ = 0xfe;
    *p++ = 0xfd;
    uint8_t* cookieLengthByte = p++;
    int ret = mbedtls_ssl_cookie_write(&server->cookieCtx, &p, end, clientId, clientIdSize);
    if (ret != 0) {
        NABTO_LOG_ERROR(LOG, "mbedtls_ssl_cookie_write returned -0x%04x", -ret);
        return NABTO_EC_UNKNOWN;
    }
    *cookieLengthByte = (uint8_t)(p - (cookieLengthByte + 1));
    size_t hvrMessageLength = (size_t)(p - hvrHandshake) - DTLS_HANDSHAKE_HEADER_SIZE;
    size_t hvrRecordLength = (size_t)(p - hvrHandshake);

    hvrHandshake[0] = DTLS_HANDSHAKE_HELLO_VERIFY_REQUEST;
    uint24_to_bigendian(hvrHandshake + 1, hvrMessageLength);
    hvrHandshake[4] = handshake[4]; // message_seq
    hvrHandshake[5] = handshake[5];
    uint24_to_bigendian(hvrHandshake + 6, 0); // fragment_offset
    uint24_to_bigendian(hvrHandshake + 9, hvrMessageLength); // fragment_length

    response[0] = DTLS_CONTENT_TYPE_HANDSHAKE;
    response[1] = 0xfe; // DTLS 1.2
    response[2] = 0xfd;
    memcpy(response + 3, record + 3, 8); // epoch and sequence number
    response[11] = (uint8_t)(hvrRecordLength >> 8);
    response[12] = (uint8_t)hvrRecordLength;

    *responseSize = (size_t)(p - response);
    return NABTO_EC_OPERATION_STARTED;
}

#endif

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
    if (conn == NULL) {
        return;
    }
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

static uint64_t uint64_from_bigendian( const uint8_t* bytes )
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
        int ret = 0;
        ret = mbedtls_ssl_handshake( &ctx->ssl );
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            // keep state as CONNECTING
        } else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            nm_mbedtls_timer_cancel(&ctx->timer);
            event_callback(ctx, NP_DTLS_EVENT_CLOSED);
#if defined(NM_MBEDTLS_SRV_COOKIES)
        } else if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
            // A HelloVerifyRequest has been sent, wait for the ClientHello
            // with the cookie on a fresh session.
            nm_mbedtls_timer_cancel(&ctx->timer);
            if (nm_mbedtls_srv_reset_ssl(ctx) != 0) {
                event_callback(ctx, NP_DTLS_EVENT_CLOSED);
                return;
            }
#endif
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
        int ret = 0;
        uint8_t* recvBuffer = NULL;
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
    int ret = mbedtls_ssl_config_defaults( &server->conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_DATAGRAM,
        MBEDTLS_SSL_PRESET_DEFAULT );

    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_config_defaults returned %i", ret);
        return NABTO_EC_UNKNOWN;
    }

    mbedtls_ssl_conf_ciphersuites(&server->conf,
                                  allowedCipherSuitesList);

    mbedtls_ssl_conf_alpn_protocols(&server->conf, nm_mbedtls_srv_alpnList );

    ret = mbedtls_ctr_drbg_seed( &server->ctr_drbg, mbedtls_entropy_func, &server->entropy,
        (const unsigned char *) pers,
        strlen( pers ) );
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ctr_drbg_seed returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }
    mbedtls_ssl_conf_rng( &server->conf, mbedtls_ctr_drbg_random, &server->ctr_drbg );

#if defined(NM_MBEDTLS_SRV_COOKIES)
    ret = mbedtls_ssl_cookie_setup( &server->cookieCtx, mbedtls_ctr_drbg_random, &server->ctr_drbg );
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG, " failed ! mbedtls_ssl_cookie_setup returned %d", ret );
        return NABTO_EC_UNKNOWN;
    }
#endif

    nm_mbedtls_util_check_logging(&server->conf);

    ret = mbedtls_x509_crt_parse( &server->publicKey, publicKeyL, publicKeySize+1);
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

    ret = mbedtls_ssl_conf_own_cert( &server->conf, &server->publicKey, &server->privateKey );
    if( ret != 0 )
    {
        NABTO_LOG_ERROR(LOG,"mbedtls_ssl_conf_own_cert returned %d", ret);
        return NABTO_EC_UNKNOWN;
    }
#if defined(NM_MBEDTLS_SRV_COOKIES)
    // A peer has to prove that it owns its source address before it gets the
    // much larger ServerHello flight, otherwise the device can be used to
    // reflect and amplify traffic towards a spoofed address.
    mbedtls_ssl_conf_dtls_cookies(&server->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &server->cookieCtx);
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
        if (bufferSize + NP_DTLS_CONNECTION_ID_HEADER_SIZE > pl->buf.size(ctx->sslSendBuffer)) {
            // Cannot happen as the mtu leaves room for the connection id
            // header in a communication buffer.
            NABTO_LOG_ERROR(LOG, "The dtls record (%u bytes) does not fit in a communication buffer, dropping the packet.", (unsigned)bufferSize);
            pl->buf.free(ctx->sslSendBuffer);
            ctx->sslSendBuffer = NULL;
            return (int)bufferSize;
        }
        memcpy(pl->buf.start(ctx->sslSendBuffer), buffer, bufferSize);

        np_error_code ec = ctx->sender(ctx->channelId, pl->buf.start(ctx->sslSendBuffer), (uint16_t)bufferSize, &ctx->senderEvent, ctx->senderData);
        if (ec != NABTO_EC_OK) {
            NABTO_LOG_ERROR(LOG, "Could not send the packet from the dtls server, dropping the packet.");
            pl->buf.free(ctx->sslSendBuffer);
            ctx->sslSendBuffer = NULL;
            // if we return WANT_WRITE there is no mechanism which ensures a retransmission occurs.
            return (int)bufferSize;
        }
        return (int)bufferSize;
    }
    return MBEDTLS_ERR_SSL_WANT_WRITE;
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
    }
    size_t maxCp = bufferSize > ctx->recvBufferSize ? ctx->recvBufferSize : bufferSize;
    memcpy(buffer, ctx->recvBuffer, maxCp);
    ctx->recvBufferSize = 0;
    return (int)maxCp;
}

void nm_mbedtls_srv_timed_event_do_one(void* data) {
    nm_mbedtls_srv_do_one(data);
}

#endif
