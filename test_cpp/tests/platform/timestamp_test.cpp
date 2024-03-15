#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <platform/interfaces/np_timestamp.h>
#include <platform/np_timestamp_wrapper.h>
#include <platform/np_platform.h>

#include <test_platform.hpp>

#include <thread>
#include <chrono>

BOOST_AUTO_TEST_SUITE(timestamp)

BOOST_TEST_DECORATOR(* boost::unit_test::timeout(120))
BOOST_DATA_TEST_CASE(expire, nabto::test::TestPlatformFactory::multi(), tps)
{
    auto tp = tps->create();
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

BOOST_DATA_TEST_CASE(difference, nabto::test::TestPlatformFactory::multi(), tps)
{
    uint32_t s1 = 0;
    uint32_t s2 = 1;
    uint32_t s3 = INT32_MAX;
    uint32_t s4 = INT32_MAX; s4 += 42;
    uint32_t s5 = (uint32_t)INT32_MIN;
    uint32_t s6 = (uint32_t)INT32_MIN; s6 -= 42;
    uint32_t s7 = (uint32_t)-1;

    BOOST_TEST(np_timestamp_difference(s1, s1) >= 0);
    BOOST_TEST(np_timestamp_difference(s1, s2) < 0);
    BOOST_TEST(np_timestamp_difference(s7, s2) < 0);
    BOOST_TEST(np_timestamp_difference(s1, s3) < 0);
    BOOST_TEST(np_timestamp_difference(s4, s1) < 0);
    BOOST_TEST(np_timestamp_difference(s5, s7) < 0);
    BOOST_TEST(np_timestamp_difference(s6, s5) < 0);
    BOOST_TEST(np_timestamp_difference(s2, s6) < 0);
    BOOST_TEST(np_timestamp_difference(s5, s6) >= 0);
}


BOOST_AUTO_TEST_SUITE_END()
