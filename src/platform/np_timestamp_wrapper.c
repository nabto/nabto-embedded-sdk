#include "np_timestamp_wrapper.h"

uint32_t np_timestamp_now_ms(struct np_timestamp* obj)
{
    return obj->mptr->now_ms(obj);
}

bool np_timestamp_passed_or_now(struct np_timestamp* obj, uint32_t stamp)
{
    return np_timestamp_less_or_equal(stamp, np_timestamp_now_ms(obj));
}

/**
 * return true iff t1 <= t2
 */
bool np_timestamp_less_or_equal(uint32_t t1, uint32_t t2)
{
    return ((int32_t)(t1 - t2) <= 0);
}

uint32_t np_timestamp_future(struct np_timestamp* obj, uint32_t ms)
{
    return np_timestamp_now_ms(obj) + ms;
}


int32_t np_timestamp_difference(uint32_t t1, uint32_t t2)
{
    return (int32_t)(t1 - t2);
}
