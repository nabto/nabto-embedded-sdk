#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>

#include <thread>

namespace nabto {
namespace test {

static NabtoDevice* createTestDevice()
{
    NabtoDeviceError ec;
    NabtoDevice* dev = nabto_device_new();
    BOOST_TEST(dev);
    char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        ec = nabto_device_set_log_std_out_callback(dev);
        ec = nabto_device_set_log_level(dev, logLevel);
    }

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
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    nabto_device_stop(dev);
    nabto_device_free(dev);
}

BOOST_AUTO_TEST_CASE(stop_without_close_imediately, *boost::unit_test::timeout(10))
{
    NabtoDeviceError ec;
    NabtoDevice* dev = nabto::test::createTestDevice();
    ec = nabto_device_start(dev);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    nabto_device_stop(dev);
    nabto_device_free(dev);
}

BOOST_AUTO_TEST_CASE(fingerprints)
{
    NabtoDevice* dev = nabto::test::createTestDevice();
    char* truncatedFp;
    char* fullFp;
    BOOST_TEST(nabto_device_get_device_fingerprint_hex(dev, &truncatedFp) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_get_device_fingerprint_full_hex(dev, &fullFp) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(strlen(truncatedFp) == (size_t)32);
    BOOST_TEST(strlen(fullFp) == (size_t)64);

    BOOST_TEST(memcmp(truncatedFp, fullFp, 32) == 0);

    nabto_device_string_free(truncatedFp);
    nabto_device_string_free(fullFp);

}

BOOST_AUTO_TEST_SUITE_END()
