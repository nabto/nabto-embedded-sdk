#ifndef _NM_wolfssl_TIMER_H_
#define _NM_wolfssl_TIMER_H_

#include <stdint.h>

#include <platform/np_platform.h>
#include <platform/interfaces/np_timestamp.h>

typedef void (*nm_wolfssl_timer_callback)(void* data);

struct nm_wolfssl_timer {
    struct np_platform* pl;
    uint32_t intermediateTp;
    struct np_event* tEv;
    nm_wolfssl_timer_callback cb;
    void* cbData;
    bool armed;
    bool expired;
};

np_error_code nm_wolfssl_timer_init(struct nm_wolfssl_timer* timer, struct np_platform* pl, nm_wolfssl_timer_callback cb, void* userData);
void nm_wolfssl_timer_deinit(struct nm_wolfssl_timer* timer);

void nm_wolfssl_timer_cancel(struct nm_wolfssl_timer* timer);

void nm_wolfssl_timer_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds);


int nm_wolfssl_timer_get_delay(void* data);


#endif
