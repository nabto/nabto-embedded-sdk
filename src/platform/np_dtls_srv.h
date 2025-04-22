#ifndef NP_DTLS_SRV_H
#define NP_DTLS_SRV_H

#include <platform/np_dtls.h>
#include <platform/np_error_code.h>

/**
 * DTLS Server interface
 *
 * Warning: this interface is not final.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define NP_DTLS_SRV_DEFAULT_CHANNEL_ID  NP_DTLS_DEFAULT_CHANNEL_ID

enum np_dtls_srv_event {
    NP_DTLS_SRV_EVENT_CLOSED,
    NP_DTLS_SRV_EVENT_HANDSHAKE_COMPLETE
};

typedef void (*np_dtls_srv_send_callback)(const np_error_code ec, void* data);

struct np_dtls_srv_send_context {
    uint8_t* buffer;
    uint16_t bufferSize;
    uint8_t channelId;
    np_dtls_send_to_callback cb;
    void* data;
    struct nn_llist_node sendListNode;
};

#include <core/nc_protocol_defines.h>

struct np_platform;

struct np_dtls_srv_connection;

struct np_dtls_srv;

struct np_dtls_srv_module {

    np_error_code (*create)(struct np_platform* pl, struct np_dtls_srv** server);
    np_error_code (*set_keys)(struct np_dtls_srv* server,
                              const unsigned char* certificate, size_t certificateSize,
                              const unsigned char* privateKeyL, size_t privateKeySize);
    void (*destroy)(struct np_dtls_srv* server);

    np_error_code (*get_server_fingerprint)(struct np_dtls_srv* srv, uint8_t* fp);


    np_error_code (*create_connection)(struct np_dtls_srv* server, struct np_dtls_srv_connection** dtls,
                                       np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
                                       np_dtls_event_handler eventHandler, void* data);

    /**
     * Destroy a connection, a connection can be destroyed when no more
     * unresolved async send callbacks exists. Such a state can be obtained by
     * calling async_close.
     */
    void (*destroy_connection)(struct np_dtls_srv_connection* connection);

    /**
     * Send data.
     */
    np_error_code (*async_send_data)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                     struct np_dtls_send_context* sendCtx);

    np_error_code (*handle_packet)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                   uint8_t channelId, uint8_t* buffer, uint16_t bufferSize);

    /**
     * Async Close a dtls connection. The callback is called when the connection
     * has been closed and no more data is sent. No more data can be sent after
     * close has been called. The function is async such that the dtls
     * connection has time to send the last dtls close notify packet.
     * Outstanding async send operations will be resolved before close returns.
     * Destroy connection can be invoked from the close callback.
     */
    np_error_code (*async_close)(struct np_platform* pl, struct np_dtls_srv_connection* ctx,
                                 struct np_completion_event* completionEvent);

    np_error_code (*get_fingerprint)(struct np_platform* pl, struct np_dtls_srv_connection* ctx, uint8_t* fp);

    const char* (*get_alpn_protocol)(struct np_dtls_srv_connection* ctx);

    np_error_code (*get_packet_count)(struct np_dtls_srv_connection* ctx, uint32_t* recvCount, uint32_t* sentCount);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NP_DTLS_SRV_H
