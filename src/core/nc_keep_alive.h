#ifndef NC_KEEP_ALIVE_H
#define NC_KEEP_ALIVE_H

#include <platform/np_platform.h>

typedef void (*keep_alive_callback)(const np_error_code ec, void* data);

struct keep_alive_context
{
    struct np_platform* pl;
    np_crypto_context* conn;
    keep_alive_callback cb;
    void* data;
    struct np_timed_event ev;
    np_communication_buffer* buf;
    uint16_t bufSize;
    uint16_t kaInterval;
    uint8_t kaRetryInterval;
    uint8_t kaMaxRetries;
};

void nc_keep_alive_init(struct np_platform* pl, struct keep_alive_context* ctx,
                         np_crypto_context* conn, keep_alive_callback cb, void* data);
void nc_keep_alive_stop(struct np_platform* pl,  struct keep_alive_context* ctx);
void nc_keep_alive_recv(const np_error_code ec, uint8_t channelId, uint64_t seq,
                        np_communication_buffer* buf, uint16_t bufferSize, void* data);
np_error_code nc_keep_alive_async_probe(struct np_platform* pl, struct keep_alive_context* ctx,
                                        uint8_t channelId, keep_alive_callback cb, void* data);

#endif //NC_KEEP_ALIVE_H
