#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

BOOST_AUTO_TEST_SUITE(device_api)

BOOST_AUTO_TEST_CASE(create_sct, *boost::unit_test::timeout(10))
{
    NabtoDevice* device = nabto_device_new();

    char* sct;
    BOOST_TEST(nabto_device_create_server_connect_token(device, &sct) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(sct != (void*)NULL);
    BOOST_TEST(strlen(sct) > (size_t)0);
    nabto_device_string_free(sct);

    nabto_device_free(device);
}

BOOST_AUTO_TEST_SUITE_END();
