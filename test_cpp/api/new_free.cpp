#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>

BOOST_AUTO_TEST_SUITE(device_api)

BOOST_AUTO_TEST_CASE(new_free, *boost::unit_test::timeout(10))
{
    NabtoDevice* device = nabto_device_new();
    BOOST_TEST(device != (NabtoDevice*)NULL);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_SUITE_END();
