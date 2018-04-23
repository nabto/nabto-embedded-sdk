#include "ip_address.h"
#include "unit_test.h"
#include "ip_address_test.h"

void unabto_ip_address_test_is_v4()
{
    struct unabto_ip_address ip;
    ip.type = UNABTO_IPV4;
    UNABTO_TEST_CHECK(unabto_ip_is_v4(&ip));
}

void unabto_ip_address_test_is_v6()
{
    struct unabto_ip_address ip;
    ip.type = UNABTO_IPV6;
    UNABTO_TEST_CHECK(unabto_ip_is_v6(&ip));
}
