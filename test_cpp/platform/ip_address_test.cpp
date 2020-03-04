#include <boost/test/unit_test.hpp>

#include <platform/np_ip_address.h>

BOOST_AUTO_TEST_SUITE(ip_address)

BOOST_AUTO_TEST_CASE(assign_ipv4)
{
    struct np_ip_address ip;
    np_ip_address_assign_v4(&ip, 2130706433 /*127.0.0.1*/);

    const char* str = np_ip_address_to_string(&ip);
    BOOST_TEST(std::string(str) == "127.0.0.1");
}


BOOST_AUTO_TEST_SUITE_END()
