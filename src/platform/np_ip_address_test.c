#include "np_ip_address.h"
#include "np_unit_test.h"
#include "np_tests.h"

void np_ip_address_test_is_v4()
{
    struct np_ip_address ip;
    ip.type = NABTO_IPV4;
    NABTO_TEST_CHECK(np_ip_is_v4(&ip));
}

void np_ip_address_test_is_v6()
{
    struct np_ip_address ip;
    ip.type = NABTO_IPV6;
    NABTO_TEST_CHECK(np_ip_is_v6(&ip));
}


void np_ip_address_tests()
{
    np_ip_address_test_is_v4();
    np_ip_address_test_is_v6();
}
