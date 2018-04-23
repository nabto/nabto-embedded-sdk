#include "ip_address.h"
#include "unit_test.h"
#include "ip_address_test.h"

void nabto_ip_address_test_is_v4()
{
    struct nabto_ip_address ip;
    ip.type = NABTO_IPV4;
    NABTO_TEST_CHECK(nabto_ip_is_v4(&ip));
}

void nabto_ip_address_test_is_v6()
{
    struct nabto_ip_address ip;
    ip.type = NABTO_IPV6;
    NABTO_TEST_CHECK(nabto_ip_is_v6(&ip));
}
