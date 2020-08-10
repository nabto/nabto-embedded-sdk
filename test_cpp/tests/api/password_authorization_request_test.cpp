#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

BOOST_AUTO_TEST_SUITE(password_authorization_request)

BOOST_AUTO_TEST_CASE(double_register)
{
    NabtoDevice* device = nabto_device_new();
    NabtoDeviceListener* listener = nabto_device_listener_new(device);
    BOOST_TEST(nabto_device_password_authentication_request_init_listener(device, listener) == NABTO_DEVICE_EC_OK);

    BOOST_TEST(nabto_device_password_authentication_request_init_listener(device, listener) == NABTO_DEVICE_EC_IN_USE);

    nabto_device_listener_free(listener);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_CASE(init_free_init_free)
{
    NabtoDevice* device = nabto_device_new();
    for (int i = 0; i < 2; i++)
    {
        NabtoDeviceListener* listener = nabto_device_listener_new(device);
        BOOST_TEST(nabto_device_password_authentication_request_init_listener(device, listener) == NABTO_DEVICE_EC_OK);
        nabto_device_listener_stop(listener);
        nabto_device_listener_free(listener);
    }

    nabto_device_free(device);
}

BOOST_AUTO_TEST_SUITE_END()
