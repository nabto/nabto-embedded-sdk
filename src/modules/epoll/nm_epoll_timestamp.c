#include "nm_epoll.h"

#include <platform/interfaces/np_timestamp.h>

#include <time.h>

static uint32_t ts_now_ms(struct np_timestamp* obj);

static struct np_timestamp_functions module = {
    .now_ms               = &ts_now_ms
};

struct np_timestamp nm_epoll_ts_get_impl(struct nm_epoll* ctx)
{
    struct np_timestamp ts;
    ts.mptr = &module;
    ts.data = ctx;
    return ts;
}

uint32_t ts_now_ms(struct np_timestamp* obj)
{
    struct nm_epoll* ctx = obj->data;
    return ctx->cachedTimestamp;
}

void nm_epoll_ts_update(struct nm_epoll* ctx) 
{
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    ctx->cachedTimestamp = ((spec.tv_sec * 1000) + (spec.tv_nsec / 1000000));
}
