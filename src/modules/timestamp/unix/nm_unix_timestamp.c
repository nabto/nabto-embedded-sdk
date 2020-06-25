#include "nm_unix_timestamp.h"
#include <platform/np_logging.h>
#include <platform/interfaces/np_timestamp.h>

#include <time.h>

static uint32_t ts_now_ms(struct np_timestamp* obj);

static struct np_timestamp_functions module = {
    .now_ms               = &ts_now_ms
};

struct np_timestamp nm_unix_ts_get_impl()
{
    struct np_timestamp ts;
    ts.mptr = &module;
    ts.data = NULL;
    return ts;
}

uint32_t ts_now_ms(struct np_timestamp* obj)
{
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return ((spec.tv_sec * 1000) + (spec.tv_nsec / 1000000));
}
