#include "platform_test.h"
#include "platform.h"
#include "unit_test.h"

struct test_state {
    bool called;
};

static void nabto_test_callback(void* data)
{
    struct test_state* state = (struct test_state*)data;
    state->called = true;
}

void nabto_platform_test_post_event()
{
    struct nabto_platform pl;

    nabto_platform_init(&pl);

    NABTO_TEST_CHECK(nabto_platform_is_event_queue_empty(&pl));

    struct test_state state; 
    state.called = false;

    struct nabto_platform_event event;

    nabto_platform_post(&pl, &event, &nabto_test_callback, &state);

    NABTO_TEST_CHECK(!nabto_platform_is_event_queue_empty(&pl));

    nabto_platform_poll_one(&pl);

    NABTO_TEST_CHECK(nabto_platform_is_event_queue_empty(&pl));

    NABTO_TEST_CHECK(state.called);
}


