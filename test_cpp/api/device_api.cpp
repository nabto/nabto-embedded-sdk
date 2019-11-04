#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>

namespace nabto {
namespace test {

static NabtoDevice* createTestDevice()
{
    NabtoDeviceError ec;
    NabtoDevice* dev = nabto_device_new();
    BOOST_TEST(dev);
//    ec = nabto_device_set_log_std_out_callback(dev);
//    ec = nabto_device_set_log_level(dev, "trace");

    ec = nabto_device_set_server_url(dev, "server.foo.bar");
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    char* key;
    nabto_device_create_private_key(dev, &key);
    ec = nabto_device_set_private_key(dev, key);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    nabto_device_string_free(key);
    nabto_device_set_product_id(dev, "test");
    nabto_device_set_device_id(dev, "test");
    return dev;
}

} } // namespace

BOOST_AUTO_TEST_SUITE(device_api)

BOOST_AUTO_TEST_CASE(stop_without_close, *boost::unit_test::timeout(10))
{
    NabtoDeviceError ec;
    NabtoDevice* dev = nabto::test::createTestDevice();
    ec = nabto_device_start(dev);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    nabto_device_stop(dev);
    nabto_device_free(dev);
}


BOOST_AUTO_TEST_SUITE_END()
