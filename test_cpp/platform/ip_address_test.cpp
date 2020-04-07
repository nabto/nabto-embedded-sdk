#include <boost/test/unit_test.hpp>

#include <platform/np_ip_address.h>

#include <boost/asio.hpp>

BOOST_AUTO_TEST_SUITE(ip_address)

BOOST_AUTO_TEST_CASE(assign_ipv4)
{
    struct np_ip_address ip;
    np_ip_address_assign_v4(&ip, 2130706433 /*127.0.0.1*/);

    const char* str = np_ip_address_to_string(&ip);
    BOOST_TEST(std::string(str) == "127.0.0.1");
}

BOOST_AUTO_TEST_CASE(is_v4_mapped)
{
    struct np_ip_address ip;
    np_ip_address_assign_v4(&ip, 2130706433 /*127.0.0.1*/);

    struct np_ip_address v6;
    np_ip_convert_v4_to_v4_mapped(&ip, &v6);

    BOOST_TEST(np_ip_is_v4_mapped(&v6));

    const char* str = np_ip_address_to_string(&v6);
    BOOST_TEST(std::string(str) == "0000:0000:0000:0000:0000:FFFF:7F00:0001");
}

BOOST_AUTO_TEST_SUITE_END()
