#ifndef _NM_DTLS_TIMER_H_
#define _NM_DTLS_TIMER_H_

#include <stdint.h>

#include <platform/np_platform.h>
#include <platform/np_timestamp.h>

typedef void (*nm_dtls_timer_callback)(const np_error_code ec, void* data);

struct nm_dtls_timer {
    struct np_platform* pl;
    np_timestamp intermediateTp;
    np_timestamp finalTp;
    struct np_timed_event* tEv;
    nm_dtls_timer_callback cb;
    void* cbData;
};

np_error_code nm_dtls_timer_init(struct nm_dtls_timer* timer, struct np_platform* pl, nm_dtls_timer_callback cb, void* userData);
void nm_dtls_timer_deinit(struct nm_dtls_timer* timer);

void nm_dtls_timer_cancel(struct nm_dtls_timer* timer);

void nm_dtls_timer_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds);


int nm_dtls_timer_get_delay(void* data);

#endif
