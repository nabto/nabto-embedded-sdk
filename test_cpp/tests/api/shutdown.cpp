#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>

#include <thread>

/*
 * This file serves as an example of how to correctly shutdown a NabtoDevice.
 */


static std::string productId = "pr-test";
static std::string deviceId = "de-test";
static std::string privateKey =
R"(-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHxWdMEFcRau4bjeJqgFCLvi5hHoRYdw7DE1GGaAnOa/oAoGCCqGSM49
AwEHoUQDQgAE6U8x3ZEgcO0Ol3zEBP2JFqWFo09WGTd2Topfpt7sAt+tPQyRKZYP
p2qM4nklumnOhhW2FhfHVP8UmNeVublcXQ==
-----END EC PRIVATE KEY-----
)";


BOOST_AUTO_TEST_SUITE(shutdown)

BOOST_AUTO_TEST_CASE(graceful_shutdown)
{
    /**
     * This shows a graceful shutdown of a nabto device.
    */
    NabtoDevice* device = nabto_device_new();
    BOOST_TEST(device);
    char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        BOOST_TEST(nabto_device_set_log_std_out_callback(device) == NABTO_DEVICE_EC_OK);
        BOOST_TEST(nabto_device_set_log_level(device, logLevel) == NABTO_DEVICE_EC_OK);
    }
    BOOST_TEST(nabto_device_set_private_key(device, privateKey.c_str()) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_set_product_id(device, productId.c_str()) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_set_device_id(device, deviceId.c_str()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* f = nabto_device_future_new(device);
    BOOST_TEST(f);
    nabto_device_start(device, f);
    BOOST_TEST(nabto_device_future_wait(f) == NABTO_DEVICE_EC_OK);

    // let the device run until we need to shutdown.

    // do a graceful shutdown, send a close notify packet on all active
    // connections and deregister the device in mdns.
    nabto_device_close(device, f);
    BOOST_TEST(nabto_device_future_wait(f) == NABTO_DEVICE_EC_OK);

    nabto_device_future_free(f);

    // call a blocking stop operation such that all outstanding io operations
    // are stopped and the threads are stopped.
    nabto_device_stop(device);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_CASE(nongraceful_shutdown)
{
    /**
     * This shows a nongraceful shutdown of a nabto device. This means that the
     * device will not send close notify packets on established connections.
     * This means that connected clients need to see the connection timeout
     * before they observe that the connection is dead.
    */
    NabtoDevice* device = nabto_device_new();
    BOOST_TEST(device);
    BOOST_TEST(nabto_device_set_private_key(device, privateKey.c_str()) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_set_product_id(device, productId.c_str()) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_set_device_id(device, deviceId.c_str()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* f = nabto_device_future_new(device);
    BOOST_TEST(f);
    nabto_device_start(device, f);
    BOOST_TEST(nabto_device_future_wait(f) == NABTO_DEVICE_EC_OK);
    nabto_device_future_free(f);

    // let the device run until we need to shutdown.

    // call a blocking stop operation such that all outstanding io operations
    // are stopped and the threads are stopped. If stop is not called, then free
    // will call the stop function.
    nabto_device_stop(device);
    nabto_device_free(device);
}

static void coap_listener(NabtoDevice* device, NabtoDeviceListener* listener)
{
    NabtoDeviceCoapRequest* coapRequest;
    NabtoDeviceError ec;
    while (true) {
        NabtoDeviceFuture* f = nabto_device_future_new(device);
        nabto_device_listener_new_coap_request(listener, f, &coapRequest);
        ec = nabto_device_future_wait(f);
        nabto_device_future_free(f);
        if (ec == NABTO_DEVICE_EC_STOPPED) {
            // the listener has been stopped

            return;
        } else if (ec == NABTO_DEVICE_EC_OK) {
            // handle coap request
        } else {
            // some else error.
        }
    }
}

BOOST_AUTO_TEST_CASE(shutdown_listener)
{
    /**
     * This example shows how to shutdown the device when there's a listener
     * running. This example will create a coap request listener.
     */
    NabtoDevice* device = nabto_device_new();
    BOOST_TEST(device);
    BOOST_TEST(nabto_device_set_private_key(device, privateKey.c_str()) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_set_product_id(device, productId.c_str()) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_set_device_id(device, deviceId.c_str()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* f = nabto_device_future_new(device);
    BOOST_TEST(f);
    nabto_device_start(device, f);
    BOOST_TEST(nabto_device_future_wait(f) == NABTO_DEVICE_EC_OK);

    NabtoDeviceListener* listener = nabto_device_listener_new(device);
    BOOST_TEST(listener);

    const char* pathSegments[] = {"/helloworld", NULL};
    nabto_device_coap_init_listener(device, listener, NABTO_DEVICE_COAP_GET, (const char**)pathSegments);

    std::thread t([device, listener](){ coap_listener(device, listener); } );


    // let the device run until we need to shutdown.


    // stop the listener and join the request handler thread
    BOOST_TEST(nabto_device_listener_stop(listener) == NABTO_DEVICE_EC_OK);
    t.join();

    // do a graceful shutdown, send a close notify packet on all active
    // connections and deregister the device in mdns.
    nabto_device_close(device, f);
    BOOST_TEST(nabto_device_future_wait(f) == NABTO_DEVICE_EC_OK);

    // call a blocking stop operation such that all outstanding io operations
    // are stopped and the threads are stopped. If stop is not called, then free
    // will call the stop function.
    nabto_device_stop(device);
    nabto_device_free(device);
}


BOOST_AUTO_TEST_SUITE_END()
