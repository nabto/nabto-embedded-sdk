#ifndef NM_MBEDTLS_TIMER_H_
#define NM_MBEDTLS_TIMER_H_

#include <stdint.h>

#include <platform/interfaces/np_timestamp.h>
#include <platform/np_platform.h>

typedef void (*nm_mbedtls_timer_callback)(void* data);

struct nm_mbedtls_timer {
    struct np_platform* pl;
    uint32_t intermediateTp;
    struct np_event* tEv;
    nm_mbedtls_timer_callback cb;
    void* cbData;
    bool armed;
    bool expired;
};

np_error_code nm_mbedtls_timer_init(struct nm_mbedtls_timer* timer, struct np_platform* pl, nm_mbedtls_timer_callback cb, void* userData);
void nm_mbedtls_timer_deinit(struct nm_mbedtls_timer* timer);

void nm_mbedtls_timer_cancel(struct nm_mbedtls_timer* timer);

void nm_mbedtls_timer_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds);


int nm_mbedtls_timer_get_delay(void* data);


#endif
