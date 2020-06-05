#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <platform/interfaces/np_timestamp.h>

#include <test_platform.hpp>

#include <thread>
#include <chrono>

BOOST_AUTO_TEST_SUITE(timestamp)

BOOST_TEST_DECORATOR(* boost::unit_test::timeout(120))
BOOST_DATA_TEST_CASE(expire, nabto::test::TestPlatform::multi(), tp)
{
    struct np_platform* pl = tp->getPlatform();
    struct np_timestamp* ts = &pl->timestamp;
    uint32_t now = np_timestamp_now_ms(ts);
    uint32_t now2 = np_timestamp_now_ms(ts);
    BOOST_TEST(np_timestamp_less_or_equal(now, now2));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    uint32_t now3 = np_timestamp_now_ms(ts);
    BOOST_TEST(np_timestamp_less_or_equal(now, now3));
    BOOST_TEST(np_timestamp_passed_or_now(ts, now));
    BOOST_TEST(np_timestamp_passed_or_now(ts, now2));
    BOOST_TEST(np_timestamp_passed_or_now(ts, now3));

}


BOOST_AUTO_TEST_SUITE_END()
