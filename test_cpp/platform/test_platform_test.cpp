#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <platform/interfaces/np_event_queue.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_platform.h>

#include "test_platform.hpp"

#include <thread>

BOOST_AUTO_TEST_SUITE(test_platform)

BOOST_TEST_DECORATOR(*boost::unit_test::timeout(120))

BOOST_DATA_TEST_CASE(start_stop, nabto::test::TestPlatformFactory::multi(),tpf)
{
    auto tp = tpf->create();
    // HERE BE DRAGONS, wait for the thread to start the loop such that stop breaks the loop
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    tp->stop();
}


// BOOST_DATA_TEST_CASE(stop_from_event, nabto::test::TestPlatformFactory::multi(),tpf)
// {
//     auto tp = tpf->create();
//     std::thread t([tp](){ tp->run(); });
//     struct np_platform* pl = tp->getPlatform();
//     struct np_event_queue* eq = &pl->eq;
//     struct np_event* stopEvent;
//     np_event_queue_create_event(eq, &stopFunction, tp.get(), &stopEvent);
//     np_event_queue_post(eq, stopEvent);
//     t.join();
//     np_event_queue_destroy_event(eq, stopEvent);
// }

// BOOST_DATA_TEST_CASE(stop_from_event_no_thread, nabto::test::TestPlatformFactory::multi(),tpf)
// {
//     auto tp = tpf->create();
//     struct np_platform* pl = tp->getPlatform();
//     struct np_event* stopEvent;
//     struct np_event_queue* eq = &pl->eq;
//     np_event_queue_create_event(eq, &stopFunction, tp.get(), &stopEvent);
//     np_event_queue_post(eq, stopEvent);
//     tp->run();
//     np_event_queue_destroy_event(eq, stopEvent);
// }

BOOST_AUTO_TEST_SUITE_END()
