#ifndef NC_KEEP_ALIVE_H
#define NC_KEEP_ALIVE_H

#include <platform/np_platform.h>

#include <nabto_types.h>

typedef void (*keep_alive_callback)(const np_error_code ec, void* data);

struct nc_keep_alive_context
{
    struct np_platform* pl;
    bool isCli;
    np_dtls_cli_context* cli;
    np_dtls_srv_connection* srv;
    keep_alive_callback cb;
    void* data;
    struct np_timed_event kaEv;
    np_communication_buffer* buf;
    uint16_t bufSize;
    uint16_t kaInterval;
    uint8_t kaRetryInterval;
    uint8_t kaMaxRetries;
    uint32_t lastRecvCount;
    uint32_t lastSentCount;
    uint8_t lostKeepAlives;
};

/**
 * Initializes and starts keep alive for given DTLS client connection
 * Callback is invoked if an error occurs while keeping the connection alive
 * Callback is invoked with NABTO_EC_OK if nc_keep_alive_stop is called
 */
void nc_keep_alive_init_cli(struct np_platform* pl, struct nc_keep_alive_context* ctx,
                            np_dtls_cli_context* conn, keep_alive_callback cb, void* data);

/**
 * Initializes and starts keep alive for given DTLS server connection
 * Callback is invoked if an error occurs while keeping the connection alive
 * Callback is invoked with NABTO_EC_OK if nc_keep_alive_stop is called
 */
void nc_keep_alive_init_srv(struct np_platform* pl, struct nc_keep_alive_context* ctx,
                            np_dtls_srv_connection* conn, keep_alive_callback cb, void* data);

/** 
 * Stops keep alive and invokes callback provided when the context was initialized
 */
void nc_keep_alive_stop(struct np_platform* pl,  struct nc_keep_alive_context* ctx);

/**
 * Probes a connection on specific channelId.
 * callback is invoked when a KEEP_ALIVE_RESPONSE packet is received, or when timeout.
 */
np_error_code nc_keep_alive_async_probe(struct np_platform* pl, struct nc_keep_alive_context* ctx,
                                        uint8_t channelId, keep_alive_callback cb, void* data);

/** 
 * Sets keep alive settings for a given context.
 * @param kaInterval      set the interval between successfull keep alive
 * @param kaRetryInterval set the interval between retransmissions for packet losses
 * @param kaMaxRetries    set the number of retries before connection is assumed dead
 */
np_error_code nc_keep_alive_set_settings(struct np_platform* pl, struct nc_keep_alive_context* ctx,
                                         uint16_t kaInterval, uint8_t kaRetryInterval, uint8_t kaMaxRetries);

#endif //NC_KEEP_ALIVE_H
