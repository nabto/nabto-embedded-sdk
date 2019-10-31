#ifndef NC_KEEP_ALIVE_H
#define NC_KEEP_ALIVE_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>

#include <nabto_types.h>

#ifndef NC_KEEP_ALIVE_MTU_MAX
#define NC_KEEP_ALIVE_MTU_MAX 1400
#endif

#ifndef NC_KEEP_ALIVE_MTU_START
#define NC_KEEP_ALIVE_MTU_START 1024
#endif

#ifndef NC_KEEP_ALIVE_MTU_RETRY_INTERVAL
#define NC_KEEP_ALIVE_MTU_RETRY_INTERVAL 2000 // ms
#endif

#ifndef NC_KEEP_ALIVE_MTU_MAX_TRIES
#define NC_KEEP_ALIVE_MTU_MAX_TRIES 5
#endif

#define NC_KEEP_ALIVE_DEFAULT_INTERVAL 30000
#define NC_KEEP_ALIVE_DEFAULT_RETRY_INTERVAL 2000
#define NC_KEEP_ALIVE_DEFAULT_MAX_RETRIES 15


struct nc_keep_alive_context
{
    struct np_platform* pl;
    uint32_t kaInterval;
    uint32_t kaRetryInterval;
    uint32_t kaMaxRetries;
    uint32_t lastRecvCount;
    uint32_t lastSentCount;
    uint32_t lostKeepAlives;
    uint32_t n;

    bool isSending;
    uint8_t sendBuffer[18];
    struct np_timed_event keepAliveEvent;

};

enum nc_keep_alive_action{
    DO_NOTHING,
    SEND_KA,
    KA_TIMEOUT
};

typedef void (*keep_alive_wait_callback)(const np_error_code ec, void* data);

//TODO add ability to change keep alive settings
/**
 * Init keep alive with the given parameters
 * @param pl            The platform to use
 * @param ctx           The keep alive context to use for keep alive
 * @param interval      The interval between keep alive transmissions
 * @param retryInterval The interval between retransmissions in case of packet loss
 * @param maxRetries    The maximum amount of retransmissions before a connection is considered dead
 */
void nc_keep_alive_init(struct nc_keep_alive_context* ctx, struct np_platform* pl);

void nc_keep_alive_deinit(struct nc_keep_alive_context* ctx);

void nc_keep_alive_set_settings(struct nc_keep_alive_context* ctx, uint32_t interval, uint32_t retryInterval, uint32_t maxRetries);

void nc_keep_alive_create_request(struct nc_keep_alive_context* ctx, uint8_t** buffer, size_t* length);

enum nc_keep_alive_action nc_keep_alive_should_send(struct nc_keep_alive_context* ctx, uint32_t recvCount, uint32_t sentCount);
bool nc_keep_alive_handle_request(struct nc_keep_alive_context* ctx, uint8_t* reqBuffer, size_t reqLength, uint8_t** respBuffer, size_t* respLength);


void nc_keep_alive_wait(struct nc_keep_alive_context* ctx, keep_alive_wait_callback cb, void* data);
void nc_keep_alive_packet_sent(const np_error_code ec, void* data);

#endif //NC_KEEP_ALIVE_H
