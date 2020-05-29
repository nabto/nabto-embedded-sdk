#include "np_timestamp.h"
#include "np_platform.h"

uint32_t np_timestamp_now_ms(struct np_platform* pl)
{
    return pl->ts.now_ms(pl->tsImpl);
}

bool np_timestamp_passed_or_now(struct np_platform* pl, uint32_t stamp)
{
    return np_timestamp_less_or_equal(stamp, np_timestamp_now_ms(pl));
}

/**
 * return true iff t1 <= t2
 */
bool np_timestamp_less_or_equal(uint32_t t1, uint32_t t2)
{
    int32_t v1 = (int32_t)t1;
    int32_t v2 = (int32_t)t2;
    return (v1 - v2) <= 0;
}

uint32_t np_timestamp_future(struct np_platform* pl, uint32_t ms)
{
    return np_timestamp_now_ms(pl) + ms;
}


int32_t np_timestamp_difference(uint32_t t1, uint32_t t2)
{
    int32_t v1 = (int32_t)t1;
    int32_t v2 = (int32_t)t2;

    return v1 - v2;
}
