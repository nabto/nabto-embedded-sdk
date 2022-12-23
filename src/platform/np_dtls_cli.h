#ifndef NP_DTLS_CLI_H
#define NP_DTLS_CLI_H

#include <platform/np_dtls.h>
#include <platform/np_error_code.h>


/**
 * DTLS Client interface
 *
 * Warning: this interface is not final.
 */



#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;

#define NP_DTLS_CLI_DEFAULT_CHANNEL_ID NP_DTLS_DEFAULT_CHANNEL_ID

struct np_dtls_cli_connection;

struct np_dtls_cli_module {
    /**
     * @brief Create an attach connection. Attach connections use ALPN, SNI,
     * root certs, and cert validation. Attach connections do not need channel
     * IDs, however, since channel IDs are simply passed through the module
     * opaquely, they kept in attach connections to simplify the interface.
     *
     * @param pl           [in]  The platform to create connection in
     * @param conn         [out] The resulting connection object
     * @param packetSender [in]  Function called when the DTLS module wants to send a packet
     * @param dataHandler  [in]  Function called when decrypted data is available
     * @param eventHandler [in]  Function called when the connection changes state
     * @param data         [in]  data pointer passed to the 3 provided functions
     */
    np_error_code (*create_attach_connection)(
        struct np_platform* pl, struct np_dtls_cli_connection** conn,
        const char* sni, bool disable_cert_validation,
        np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
        np_dtls_event_handler eventHandler, void* data);

    /**
     * @brief Create an client connection. Client connections use ALPN, ChannelID
     */
    np_error_code (*create_client_connection)(
        struct np_platform* pl, struct np_dtls_cli_connection** conn,
        np_dtls_sender packetSender, np_dtls_data_handler dataHandler,
        np_dtls_event_handler eventHandler, void* data);

    void (*destroy_connection)(struct np_dtls_cli_connection* conn);

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
     * @brief Set root certs. Cert validation is only used by attach connections.
     */
    np_error_code (*set_root_certs)(struct np_platform* pl, const char* rootCerts);



    np_error_code (*connect)(struct np_dtls_cli_connection* conn);
    np_error_code (*async_send_data)(struct np_dtls_cli_connection* conn,
                                     struct np_dtls_send_context* sendCtx);

    /**
     * @brief make the DTLS module handle an incoming packet. For data-phase packets, channelId is passed to the data_handler, but is otherwise unused.
     */
    np_error_code (*handle_packet)(struct np_dtls_cli_connection* conn, uint8_t channelId,
                                   uint8_t* buffer, uint16_t bufferSize);

    /**
     * Async Close a dtls connection. When the connection
     * has been closed and no more data is sent the CLOSED event will be
     * emitted. No more data can be sent after close has been called. The
     * function is async such that the dtls connection has time to send the last
     * dtls close notify packet. Outstanding async send operations will be
     * resolved before close returns. Destroy connection can be invoked from the
     * event handler.
     */
    np_error_code (*async_close)(struct np_dtls_cli_connection* conn);

    np_error_code (*get_fingerprint)(struct np_dtls_cli_connection* conn, uint8_t* fp);

    /**
     * @brief Get negotiated ALP. Only needed determine which protocol to use if multiple exists. The module will fail the connection if ALPN failed.
     */
    const char* (*get_alpn_protocol)(struct np_dtls_cli_connection* conn);

    /**
     * @brief get packet count to determine when to send keep alive
     */
    np_error_code (*get_packet_count)(struct np_dtls_cli_connection* conn, uint32_t* recvCount, uint32_t* sentCount);

#if defined(NABTO_DEVICE_GET_ATTACH_CERTIFICATE_EXPIRATION)

    /**
     * @brief Get certificate expiration
     *
     * @param conn  the connection
     * @param expiration  The expiration time as a unix timestamp
     * @retval NABTO_EC_OK  If ok.
     * @retval NABTO_EC_INVALID_STATE If not connected.
     * @retval NABTO_EC_UNKNOWN  See log for datailed description of what went wrong.
    */
    np_error_code (*get_certificate_expiration)(struct np_dtls_cli_connection* conn, uint64_t* expiration);
#endif
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NP_DTLS_CLI_H
