#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <platform/np_event_queue.h>

#include "test_platform.hpp"

#include <thread>

namespace {

void stopFunction(void* userData)
{
    nabto::test::TestPlatform* tp = (nabto::test::TestPlatform*)userData;
    tp->stop();
}

}


BOOST_AUTO_TEST_SUITE(test_platform)

BOOST_DATA_TEST_CASE(start_stop, nabto::test::TestPlatform::multi(),tp)
{
    std::thread t([tp](){ tp->run(); });
    // HERE BE DRAGONS, wait for the thread to start the loop such that stop breaks the loop
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    tp->stop();
    t.join();
}


BOOST_DATA_TEST_CASE(stop_from_event, nabto::test::TestPlatform::multi(),tp)
{
    std::thread t([tp](){ tp->run(); });
    struct np_platform* pl = tp->getPlatform();
    struct np_event* stopEvent;
    np_event_queue_create_event(pl, &stopFunction, tp.get(), &stopEvent);
    np_event_queue_post(pl, stopEvent);
    t.join();
}

BOOST_DATA_TEST_CASE(stop_from_event_no_thread, nabto::test::TestPlatform::multi(),tp)
{
    struct np_platform* pl = tp->getPlatform();
    struct np_event* stopEvent;
    np_event_queue_create_event(pl, &stopFunction, tp.get(), &stopEvent);
    np_event_queue_post(pl, stopEvent);
    tp->run();
}

BOOST_AUTO_TEST_SUITE_END()
