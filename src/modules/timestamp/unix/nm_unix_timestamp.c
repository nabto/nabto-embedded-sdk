#include "nm_unix_timestamp.h"
#include <platform/np_logging.h>
#include <platform/np_timestamp.h>

#include <time.h>

static uint32_t ts_now_ms(struct np_timestamp_impl* impl);



void nm_unix_ts_init(struct np_platform* pl)
{
    pl->ts.now_ms               = &ts_now_ms;
    pl->tsImpl = NULL;
}

uint32_t ts_now_ms(struct np_timestamp_impl* pl)
{
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return ((spec.tv_sec * 1000) + (spec.tv_nsec / 1000000));
}
