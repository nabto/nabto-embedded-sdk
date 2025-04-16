#include "nm_unix_timestamp.h"
#include <platform/np_logging.h>
#include <platform/interfaces/np_timestamp.h>

#include <time.h>
#include <errno.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_PLATFORM

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
    (void)obj;
    struct timespec spec;
    if (clock_gettime(CLOCK_REALTIME, &spec) == -1) {
        int err = errno;
        NABTO_LOG_ERROR(LOG, "Cannot get the current time in ms '%s'", strerror(err));
        return 0;
    }
    return ((spec.tv_sec * 1000) + (spec.tv_nsec / 1000000));
}
