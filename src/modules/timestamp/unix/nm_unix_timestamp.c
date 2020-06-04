#include "nm_unix_timestamp.h"
#include <platform/np_logging.h>
#include <platform/interfaces/np_timestamp.h>

#include <time.h>

static uint32_t ts_now_ms(void* data);

static struct np_timestamp_functions vtable = {
    .now_ms               = &ts_now_ms
};

struct np_timestamp nm_unix_ts_create()
{
    struct np_timestamp ts;
    ts.vptr = &vtable;
    ts.data = NULL;
    return ts;
}

uint32_t ts_now_ms(void* data)
{
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return ((spec.tv_sec * 1000) + (spec.tv_nsec / 1000000));
}
