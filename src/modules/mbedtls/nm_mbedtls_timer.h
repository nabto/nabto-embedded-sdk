#ifndef _NM_MBEDTLS_TIMER_H_
#define _NM_MBEDTLS_TIMER_H_

#include <stdint.h>

#include <platform/np_platform.h>
#include <platform/np_timestamp.h>

typedef void (*nm_mbedtls_timer_callback)(const np_error_code ec, void* data);

struct nm_mbedtls_timer {
    struct np_platform* pl;
    uint32_t intermediateTp;
    uint32_t finalTp;
    struct np_timed_event* tEv;
    nm_mbedtls_timer_callback cb;
    void* cbData;
};

np_error_code nm_mbedtls_timer_init(struct nm_mbedtls_timer* timer, struct np_platform* pl, nm_mbedtls_timer_callback cb, void* userData);
void nm_mbedtls_timer_deinit(struct nm_mbedtls_timer* timer);

void nm_mbedtls_timer_cancel(struct nm_mbedtls_timer* timer);

void nm_mbedtls_timer_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds);


int nm_mbedtls_timer_get_delay(void* data);

#endif
