#ifndef NC_KEEP_ALIVE_H
#define NC_KEEP_ALIVE_H

#include <platform/np_platform.h>

#ifndef NABTO_KEEP_ALIVE_DEVICE_INTERVAL
#define NABTO_KEEP_ALIVE_DEVICE_INTERVAL 10000 // 10sec
#endif

#ifndef NABTO_KEEP_ALIVE_SERVER_INTERVAL
#define NABTO_KEEP_ALIVE_SERVER_INTERVAL 10000 // 10sec
#endif

typedef void (*keep_alive_callback)(const np_error_code ec, void* data);

void nc_keep_alive_start(struct np_platform* pl, np_crypto_context* conn, keep_alive_callback cb, void* data);
void nc_keep_alive_recv(const np_error_code ec, np_communication_buffer* buf, uint16_t bufferSize);

#endif //NC_KEEP_ALIVE_H
