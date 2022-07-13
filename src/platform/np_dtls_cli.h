#ifndef NP_DTLS_CLI_H
#define NP_DTLS_CLI_H

#include <platform/np_error_code.h>

#include <nn/llist.h>

/**
 * DTLS Client interface
 *
 * Warning: this interface is not final.
 */



#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;

enum np_dtls_cli_event {
    NP_DTLS_CLI_EVENT_CLOSED, // The connection is closed
    NP_DTLS_CLI_EVENT_HANDSHAKE_COMPLETE,
    NP_DTLS_CLI_EVENT_ACCESS_DENIED, // The connection got an access denied alert. The connection is closed.
    NP_DTLS_CLI_EVENT_CERTIFICATE_VERIFICATION_FAILED // The certificate could not be validated. The connection is closed.
};

typedef np_error_code (*np_dtls_cli_sender)(uint8_t channelId, uint8_t* buffer,
                                            uint16_t bufferSize,
                                            struct np_completion_event* cb,
                                            void* senderData);
typedef void (*np_dtls_cli_event_handler)(enum np_dtls_cli_event event,
                                          void* data);
typedef void (*np_dtls_cli_data_handler)(uint8_t channelId, uint8_t* buffer,
                                         uint16_t bufferSize, void* data);

struct np_dtls_cli_connection;

struct np_dtls_cli_send_context {
    // Data to send
    uint8_t* buffer;
    uint16_t bufferSize;
    // channel ID unused by DTLS, but passed to data_handler/sender as needed by nc_client_connection
    uint8_t channelId;
    // callback when sent
    struct np_completion_event* ev;
    // node for message queue
    struct nn_llist_node sendListNode;
};

struct np_dtls_cli_module {

    /**
     * @brief Create an attach connection. Attach connections use ALPN, SNI, root certs, and cert validation
     * @param pl           [in]  The platform to create connection in
     * @param conn         [out] The resulting connection object
     * @param packetSender [in]  Function called when the DTLS module wants to send a packet
     * @param dataHandler  [in]  Function called when decrypted data is available
     * @param eventHandler [in]  Function called when the connection changes state
     * @param data         [in]  data pointer passed to the 3 provided functions
     */
    np_error_code (*create_attach_connection)(
        struct np_platform* pl, struct np_dtls_cli_connection** conn,
        np_dtls_cli_sender packetSender, np_dtls_cli_data_handler dataHandler,
        np_dtls_cli_event_handler eventHandler, void* data);

    /**
     * @brief Create an client connection. Client connections use ALPN, ChannelID
     */
    np_error_code (*create_client_connection)(
        struct np_platform* pl, struct np_dtls_cli_connection** conn,
        np_dtls_cli_sender packetSender, np_dtls_cli_data_handler dataHandler,
        np_dtls_cli_event_handler eventHandler, void* data);

    void (*destroy_connection)(struct_dtls_cli_connection* conn);

    /**
     * @brief Set the certificate and private key used for all connections.
     * The certificate is a pem encoded certificate matching the pem encoded private key.
     */
    np_error_code (*set_keys)(struct np_platform* pl,
                              const unsigned char* certificate, size_t certificateSize,
                              const unsigned char* privateKeyL, size_t privateKeySize);

    // The retransmission in the dtls handshake uses exponential backoff,
    // If minTimeout is 1000ms and maxTimeout is 5000ms the dtls implementation will
    // retry at something like 1s, 2s, 4s,
    np_error_code (*set_handshake_timeout)(struct np_platform* pl, uint32_t minTimeout, uint32_t maxTimeout);

    /**
     * @brief Set SNI, root certs, or disable cert validation only applies to attach connections.
     */
    np_error_code (*set_sni)(struct np_platform* pl, const char* sni);
    np_error_code (*set_root_certs)(struct np_platform* pl, const char* rootCerts);
    np_error_code (*disable_certificate_validation)(struct np_platform* pl);



    np_error_code (*connect)(struct np_dtls_cli_connection* conn);
    np_error_code (*async_send_data)(struct np_dtls_cli_connection* conn,
                                     struct np_dtls_cli_send_context* sendCtx);

    /**
     * @brief make the DTLS module handle an incoming packet. For data-phase packets, channelId is passed to the data_handler, but is otherwise unused.
     */
    np_error_code (*handle_packet)(struct np_dtls_cli_connection* conn, uint8_t channelId,
                                   uint8_t* buffer, uint16_t bufferSize);

   /**
     * Async Close a dtls connection. The callback is called when the connection
     * has been closed and no more data is sent. No more data can be sent after
     * close has been called. The function is async such that the dtls
     * connection has time to send the last dtls close notify packet.
     * Outstanding async send operations will be resolved before close returns.
     * Destroy connection can be invoked from the close callback.
     */
    np_error_code (*async_close)(struct np_dtls_cli_connection* conn,
                                 struct np_completion_event* completionEvent);

    np_error_code (*get_fingerprint)(struct np_dtls_cli_connection* conn, uint8_t* fp);

    /**
     * @brief Get negotiated ALP. Only needed determine which protocol to use if multiple exists. The module will fail the connection if ALPN failed.
     */
    const char* (*get_alpn_protocol)(struct np_dtls_cli_connection* conn);

    /**
     * @brief get packet count to determine when to send keep alive
     */
    np_error_code (*get_packet_count)(struct np_dtls_cli_connection* conn, uint32_t* recvCount, uint32_t* sentCount);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NP_DTLS_CLI_H
