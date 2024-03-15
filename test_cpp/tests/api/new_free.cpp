#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>

#include <thread>
#include <chrono>

BOOST_AUTO_TEST_SUITE(device_api)

BOOST_AUTO_TEST_CASE(new_free, *boost::unit_test::timeout(300))
{
    const char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        nabto_device_set_log_level(NULL, logLevel);
        nabto_device_set_log_std_out_callback(NULL);
    }
    NabtoDevice* device = nabto_device_new();
    BOOST_TEST(device != (NabtoDevice*)NULL);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_SUITE_END()
