#include <platform/np_platform.h>
#include <platform/np_unit_test.h>
#include <platform/np_tests.h>

struct test_state {
    bool called;
};

static void np_test_callback(void* data)
{
    struct test_state* state = (struct test_state*)data;
    state->called = true;
}

static void np_timed_event_test_callback(const np_error_code ec, void* data)
{
    struct test_state* state = (struct test_state*)data;
    state->called = true;
}

void np_platform_test_post_event()
{
    struct np_platform pl;

    np_platform_init(&pl);

    NABTO_TEST_CHECK(np_event_queue_is_event_queue_empty(&pl));

    struct test_state state; 
    state.called = false;

    struct np_event event;

    np_event_queue_post(&pl, &event, &np_test_callback, &state);

    NABTO_TEST_CHECK(!np_event_queue_is_event_queue_empty(&pl));

    np_event_queue_poll_one(&pl);

    NABTO_TEST_CHECK(np_event_queue_is_event_queue_empty(&pl));

    NABTO_TEST_CHECK(state.called);
}

np_timestamp time;
bool np_platform_test_ts_passed_or_now(np_timestamp* timestamp)
{
    return (time >= *timestamp);
}

void np_platform_test_ts_now(np_timestamp* ts)
{
    *ts = time;
}
bool np_platform_test_ts_less_or_equal(np_timestamp* t1, np_timestamp* t2)
{
    return (*t1 <= *t2);
}

void np_platform_test_ts_set_future_timestamp(np_timestamp* ts, uint32_t milliseconds)
{
    *ts = time + milliseconds;
}

void np_platform_test_post_timed_event()
{
    struct np_platform pl;
    np_platform_init(&pl);

    time = 0;
    pl.ts.passed_or_now = &np_platform_test_ts_passed_or_now;
    pl.ts.less_or_equal = &np_platform_test_ts_less_or_equal;
    pl.ts.now = &np_platform_test_ts_now;
    pl.ts.set_future_timestamp = &np_platform_test_ts_set_future_timestamp;

    NABTO_TEST_CHECK(!np_event_queue_has_timed_event(&pl));

    struct np_timed_event event;
    struct test_state state;
    state.called = false;

    np_event_queue_post_timed_event(&pl, &event, 50, &np_timed_event_test_callback, &state);

    NABTO_TEST_CHECK(np_event_queue_has_timed_event(&pl));

    NABTO_TEST_CHECK(!np_event_queue_has_ready_timed_event(&pl));

    time += 100;

    NABTO_TEST_CHECK(np_event_queue_has_ready_timed_event(&pl));

    np_event_queue_poll_one_timed_event(&pl);

    NABTO_TEST_CHECK(!np_event_queue_has_ready_timed_event(&pl));
    NABTO_TEST_CHECK(!np_event_queue_has_timed_event(&pl));

    NABTO_TEST_CHECK(state.called = true);
}

void np_event_queue_tests()
{
    np_platform_test_post_event();
    np_platform_test_post_timed_event();
}
