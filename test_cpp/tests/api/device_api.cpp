#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_test.h>

#include <modules/libevent/nm_libevent_udp.h>

#include <api/nabto_device_defines.h>

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
    nabto_device_set_local_port(dev, 0);
    nabto_device_set_p2p_port(dev, 0);
    return dev;
}

} } // namespace

BOOST_AUTO_TEST_SUITE(device_api)

BOOST_AUTO_TEST_CASE(has_default_server_url)
{
    NabtoDeviceError ec;
    char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        ec = nabto_device_set_log_std_out_callback(NULL);
        ec = nabto_device_set_log_level(NULL, logLevel);
    }

    NabtoDevice* dev = nabto_device_new();
    BOOST_TEST(dev);
    char* key;
    nabto_device_create_private_key(dev, &key);
    ec = nabto_device_set_private_key(dev, key);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    nabto_device_string_free(key);
    nabto_device_set_product_id(dev, "test");
    nabto_device_set_device_id(dev, "test");
    nabto_device_set_local_port(dev, 0);
    nabto_device_set_p2p_port(dev, 0);
    NabtoDeviceFuture* fut = nabto_device_future_new(dev);
    nabto_device_start(dev, fut);
    ec = nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    struct nabto_device_context* d = (struct nabto_device_context*)dev;
    BOOST_TEST(strcmp(d->core.hostname, "test.devices.nabto.net") == 0);
    nabto_device_free(dev);
}

static void log_callback(NabtoDeviceLogMessage* msg, void* data)
{
    (void)msg;
    int* logLines = (int*)data;
    (*logLines)++;
}

BOOST_AUTO_TEST_CASE(remove_log_callback)
{
    int logLines = 0;
    NabtoDevice* dev = nabto::test::createTestDevice();
    nabto_device_set_log_callback(dev, log_callback, &logLines);
    nabto_device_test_logging(dev);
    BOOST_TEST(logLines > 0);
    nabto_device_set_log_callback(dev, NULL, NULL);
    int cached = logLines;
    nabto_device_test_logging(dev);
    BOOST_TEST(logLines == cached);
    nabto_device_stop(dev);
    nabto_device_free(dev);
}

BOOST_AUTO_TEST_CASE(udp_recv_error_event, *boost::unit_test::timeout(10))
{
    NabtoDevice* dev = nabto::test::createTestDevice();

    auto listener = nabto_device_listener_new(dev);
    NabtoDeviceEvent event = NABTO_DEVICE_EVENT_ATTACHED;

    NabtoDeviceFuture* evFut = nabto_device_future_new(dev);
    nabto_device_device_events_init_listener(dev, listener);
    nabto_device_listener_device_event(listener, evFut, &event);


    NabtoDeviceFuture* fut = nabto_device_future_new(dev);
    nabto_device_start(dev, fut);

    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_OK);
    nabto_device_future_free(fut);

    struct nabto_device_context* internalDevice = (struct nabto_device_context*)dev;

    nm_libevent_udp_test_recv_failure(internalDevice->core.udp.sock);

    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    BOOST_TEST(event == NABTO_DEVICE_EVENT_PLATFORM_FATAL_FAILURE);

    nabto_device_stop(dev);
    nabto_device_free(dev);
}


BOOST_AUTO_TEST_CASE(stop_without_close, *boost::unit_test::timeout(10))
{
    NabtoDevice* dev = nabto::test::createTestDevice();
    NabtoDeviceFuture* fut = nabto_device_future_new(dev);
    nabto_device_start(dev, fut);

    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_OK);
    nabto_device_future_free(fut);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    nabto_device_stop(dev);
    nabto_device_free(dev);
}

BOOST_AUTO_TEST_CASE(stop_without_close_imediately, *boost::unit_test::timeout(10))
{
    NabtoDeviceError ec;
    NabtoDevice* dev = nabto::test::createTestDevice();
    NabtoDeviceFuture* fut = nabto_device_future_new(dev);
    nabto_device_start(dev, fut);
    ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    nabto_device_future_free(fut);
    nabto_device_stop(dev);
    nabto_device_free(dev);
}

BOOST_AUTO_TEST_CASE(fingerprints)
{
    NabtoDevice* dev = nabto::test::createTestDevice();
    char* truncatedFp;
    char* fullFp;
    BOOST_TEST(nabto_device_get_device_fingerprint_hex(dev, &truncatedFp) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_get_device_fingerprint(dev, &fullFp) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(strlen(truncatedFp) == (size_t)32);
    BOOST_TEST(strlen(fullFp) == (size_t)64);

    BOOST_TEST(memcmp(truncatedFp, fullFp, 32) == 0);

    nabto_device_string_free(truncatedFp);
    nabto_device_string_free(fullFp);
    nabto_device_free(dev);

}

BOOST_AUTO_TEST_CASE(new_device_after_free, *boost::unit_test::timeout(10))
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

    NabtoDeviceFuture* fut = nabto_device_future_new(dev);
    nabto_device_start(dev, fut);

    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_OK);
    nabto_device_future_free(fut);
    nabto_device_stop(dev);
    nabto_device_free(dev);

    dev = nabto_device_new();
    BOOST_TEST(dev);
    if (logLevel != NULL) {
        ec = nabto_device_set_log_std_out_callback(dev);
        ec = nabto_device_set_log_level(dev, logLevel);
    }

    ec = nabto_device_set_server_url(dev, "server.foo.bar");
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    nabto_device_create_private_key(dev, &key);
    ec = nabto_device_set_private_key(dev, key);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    nabto_device_string_free(key);
    nabto_device_set_product_id(dev, "test");
    nabto_device_set_device_id(dev, "test");

    fut = nabto_device_future_new(dev);
    nabto_device_start(dev, fut);

    BOOST_TEST(nabto_device_future_wait(fut) == NABTO_DEVICE_EC_OK);
    nabto_device_future_free(fut);
    nabto_device_stop(dev);
    nabto_device_free(dev);
}


BOOST_AUTO_TEST_SUITE_END()
