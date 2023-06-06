#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <nabto/nabto_device_test.h>

#include <api/nabto_device_defines.h>

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

}
} // namespace

BOOST_AUTO_TEST_SUITE(virtual_connection)

BOOST_AUTO_TEST_CASE(new_free_connection)
{
    NabtoDevice* dev = nabto::test::createTestDevice();
    NabtoDeviceListener* l = nabto_device_listener_new(dev);
    nabto_device_connection_events_init_listener(dev, l);
    NabtoDeviceFuture* fut = nabto_device_future_new(dev);
    NabtoDeviceConnectionRef ref;
    NabtoDeviceConnectionEvent ev;
    nabto_device_listener_connection_event(l, fut, &ref, &ev);

    NabtoDeviceVirtualConnection* conn = nabto_device_virtual_connection_new(dev);

    nabto_device_future_wait(fut);
    BOOST_TEST(ev == NABTO_DEVICE_CONNECTION_EVENT_OPENED);
    nabto_device_listener_connection_event(l, fut, &ref, &ev);

    nabto_device_virtual_connection_free(conn);

    nabto_device_future_wait(fut);
    BOOST_TEST(ev == NABTO_DEVICE_CONNECTION_EVENT_CLOSED);
    nabto_device_listener_connection_event(l, fut, &ref, &ev);

    nabto_device_stop(dev);
    nabto_device_future_free(fut);
    nabto_device_listener_free(l);
    nabto_device_free(dev);
}

BOOST_AUTO_TEST_SUITE_END()
