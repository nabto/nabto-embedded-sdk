#include <boost/test/unit_test.hpp>

#include <platform/np_platform.h>

namespace
{

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

uint32_t time_;
bool np_platform_test_ts_passed_or_now(uint32_t* timestamp)
{
    return (time_ >= *timestamp);
}

void np_platform_test_ts_now(uint32_t* ts)
{
    *ts = time_;
}
bool np_platform_test_ts_less_or_equal(uint32_t* t1, uint32_t* t2)
{
    return (*t1 <= *t2);
}

void np_platform_test_ts_set_future_timestamp(uint32_t* ts, uint32_t milliseconds)
{
    *ts = time_ + milliseconds;
}

}

BOOST_AUTO_TEST_SUITE(event_queue)


BOOST_AUTO_TEST_CASE(test_post_event)
{
    struct np_platform pl;

    np_event_queue_init(&pl, NULL, NULL);

    BOOST_TEST(np_event_queue_is_event_queue_empty(&pl));

    struct test_state state;
    state.called = false;

    struct np_event event;

    np_event_queue_post(&pl, &event, &np_test_callback, &state);

    BOOST_TEST(!np_event_queue_is_event_queue_empty(&pl));

    np_event_queue_poll_one(&pl);

    BOOST_TEST(np_event_queue_is_event_queue_empty(&pl));

    BOOST_TEST(state.called);
}

BOOST_AUTO_TEST_CASE(test_post_many_event)
{
    struct np_platform pl;
    int i;

    np_event_queue_init(&pl, NULL, NULL);

    BOOST_TEST(np_event_queue_is_event_queue_empty(&pl));

    struct test_state state[100];
    for (i = 0; i < 100; i++) {
        state[i].called = false;
    }

    struct np_event event[100];

    for(i = 0; i < 100; i++) {
        np_event_queue_post(&pl, &event[i], &np_test_callback, &state[i]);
    }

    for (int i = 0; i < 100; i++) {
        BOOST_TEST(!np_event_queue_is_event_queue_empty(&pl));
        np_event_queue_poll_one(&pl);
    }

    BOOST_TEST(np_event_queue_is_event_queue_empty(&pl));

    for (int i = 0; i < 100; i++) {
        BOOST_TEST(state[i].called);
    }
}

BOOST_AUTO_TEST_CASE(test_post_timed_event)
{
    struct np_platform pl;
    np_event_queue_init(&pl, NULL, NULL);

    time_ = 0;
    pl.ts.passed_or_now = &np_platform_test_ts_passed_or_now;
    pl.ts.less_or_equal = &np_platform_test_ts_less_or_equal;
    pl.ts.now = &np_platform_test_ts_now;
    pl.ts.set_future_timestamp = &np_platform_test_ts_set_future_timestamp;

    BOOST_TEST(!np_event_queue_has_timed_event(&pl));

    struct np_timed_event event;
    struct test_state state;
    state.called = false;

    np_event_queue_post_timed_event(&pl, &event, 50, &np_timed_event_test_callback, &state);

    BOOST_TEST(np_event_queue_has_timed_event(&pl));

    BOOST_TEST(!np_event_queue_has_ready_timed_event(&pl));

    time_ += 100;

    BOOST_TEST(np_event_queue_has_ready_timed_event(&pl));

    np_event_queue_poll_one_timed_event(&pl);

    BOOST_TEST(!np_event_queue_has_ready_timed_event(&pl));
    BOOST_TEST(!np_event_queue_has_timed_event(&pl));

    BOOST_TEST(state.called == true);
}

BOOST_AUTO_TEST_CASE(cancel_timed_event)
{
    struct np_platform pl;
    np_event_queue_init(&pl, NULL, NULL);

    time_ = 0;
    pl.ts.passed_or_now = &np_platform_test_ts_passed_or_now;
    pl.ts.less_or_equal = &np_platform_test_ts_less_or_equal;
    pl.ts.now = &np_platform_test_ts_now;
    pl.ts.set_future_timestamp = &np_platform_test_ts_set_future_timestamp;

    BOOST_TEST(!np_event_queue_has_timed_event(&pl));

    struct np_timed_event event;
    struct test_state state;
    state.called = false;

    np_event_queue_post_timed_event(&pl, &event, 50, &np_timed_event_test_callback, &state);

    BOOST_TEST(np_event_queue_has_timed_event(&pl));

    np_event_queue_cancel_event(&pl, &event);

    BOOST_TEST(!np_event_queue_has_timed_event(&pl));

    time_ += 100;

    np_event_queue_poll_one_timed_event(&pl);

    BOOST_TEST(state.called == false);
}

BOOST_AUTO_TEST_CASE(test_cancel_timed_event_for_non_empty_q)
{
    struct np_platform pl;
    np_event_queue_init(&pl, NULL, NULL);

    time_ = 0;
    pl.ts.passed_or_now = &np_platform_test_ts_passed_or_now;
    pl.ts.less_or_equal = &np_platform_test_ts_less_or_equal;
    pl.ts.now = &np_platform_test_ts_now;
    pl.ts.set_future_timestamp = &np_platform_test_ts_set_future_timestamp;

    BOOST_TEST(!np_event_queue_has_timed_event(&pl));

    struct np_timed_event event;
    struct np_timed_event event2;
    struct np_timed_event event3;
    struct test_state state;
    struct test_state state2;
    struct test_state state3;
    state.called = false;

    np_event_queue_post_timed_event(&pl, &event2, 50, &np_timed_event_test_callback, &state2);
    np_event_queue_post_timed_event(&pl, &event, 50, &np_timed_event_test_callback, &state);
    np_event_queue_post_timed_event(&pl, &event3, 50, &np_timed_event_test_callback, &state3);

    BOOST_TEST(np_event_queue_has_timed_event(&pl));

    np_event_queue_cancel_event(&pl, &event);

    time_ += 100;

    np_event_queue_poll_one_timed_event(&pl);
    np_event_queue_poll_one_timed_event(&pl);
    np_event_queue_poll_one_timed_event(&pl);

    BOOST_TEST(state.called == false);
}


BOOST_AUTO_TEST_CASE(test_post_timed_event_sorting)
{
    struct np_platform pl;
    np_event_queue_init(&pl, NULL, NULL);

    time_ = 0;
    pl.ts.passed_or_now = &np_platform_test_ts_passed_or_now;
    pl.ts.less_or_equal = &np_platform_test_ts_less_or_equal;
    pl.ts.now = &np_platform_test_ts_now;
    pl.ts.set_future_timestamp = &np_platform_test_ts_set_future_timestamp;

    BOOST_TEST(!np_event_queue_has_timed_event(&pl));

    struct np_timed_event event1;
    struct np_timed_event event2;
    struct test_state state1;
    struct test_state state2;
    state1.called = false;
    state2.called = false;

    np_event_queue_post_timed_event(&pl, &event1, 5000, &np_timed_event_test_callback, &state1);

    BOOST_TEST(np_event_queue_has_timed_event(&pl));

    BOOST_TEST(!np_event_queue_has_ready_timed_event(&pl));

    time_ += 100;

    BOOST_TEST(!np_event_queue_has_ready_timed_event(&pl));

    np_event_queue_post_timed_event(&pl, &event2, 50, &np_timed_event_test_callback, &state2);

    time_ += 100;

    BOOST_TEST(np_event_queue_has_ready_timed_event(&pl));

    np_event_queue_poll_one_timed_event(&pl);

    BOOST_TEST(!np_event_queue_has_ready_timed_event(&pl));
    BOOST_TEST(np_event_queue_has_timed_event(&pl));

    BOOST_TEST(state2.called == true);
    BOOST_TEST(state1.called == false);
}


BOOST_AUTO_TEST_SUITE_END()
