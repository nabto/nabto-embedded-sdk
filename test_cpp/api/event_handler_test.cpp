#ifdef HAVE_EPOLL
#include <boost/test/unit_test.hpp>

#include <api/nabto_device_event_handler.h>
#include <api/nabto_api_future_queue.h>

#include <platform/np_platform.h>
#include <test_platform.hpp>

#include <test_platform_epoll.hpp>

#include <platform/np_platform.h>
#include <api/nabto_device_defines.h>

#include <util/io_service.hpp>
#include <lib/span.hpp>

#include <boost/asio.hpp>

namespace nabto {
namespace test {

} } // namespace

BOOST_AUTO_TEST_SUITE(event_handler)

BOOST_AUTO_TEST_CASE(event_test)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    bool dataSet = false;
    NabtoDeviceFuture* fut;
    struct nabto_device_event_handler* handler = nabto_device_event_handler_new(dev, [](const np_error_code ec, struct nabto_device_future* future, void* data) {
                                                                                         nabto_api_future_set_error_code(future, NABTO_DEVICE_EC_OK);
                                                                                         bool* d = (bool*)data;
                                                                                         *d = true;
                                                                                     });
    np_error_code ec = nabto_device_event_handler_add_event(handler, &dataSet);
    BOOST_TEST(ec == NABTO_EC_OK);

    NabtoDeviceError ec2 = nabto_device_event_handler_create_future((NabtoDeviceEventHandler*)handler, &fut);
    BOOST_TEST(ec2 == NABTO_DEVICE_EC_OK);
    nabto_api_future_queue_execute_all(&dev->queueHead);
    BOOST_TEST(nabto_device_future_ready(fut) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(dataSet == true);
    ec2 = nabto_device_future_error_code(fut);
    BOOST_TEST(ec2 == NABTO_DEVICE_EC_OK);
}

BOOST_AUTO_TEST_CASE(event_test_free_with_events)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    bool dataSet = false;
    struct nabto_device_event_handler* handler = nabto_device_event_handler_new(dev, [](const np_error_code ec, struct nabto_device_future* future, void* data) {
                                                                                         BOOST_TEST(!future);
                                                                                         BOOST_TEST(ec == NABTO_EC_ABORTED);
                                                                                         bool* d = (bool*)data;
                                                                                         *d = true;
                                                                                     });
    np_error_code ec = nabto_device_event_handler_add_event(handler, &dataSet);
    BOOST_TEST(ec == NABTO_EC_OK);
    nabto_device_event_handler_free((NabtoDeviceEventHandler*)handler);
    BOOST_TEST(dataSet == true);
}

BOOST_AUTO_TEST_SUITE_END()

#endif // HAVE_EPOLL
