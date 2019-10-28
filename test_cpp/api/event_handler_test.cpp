#include <boost/test/unit_test.hpp>

#include <api/nabto_device_event_handler.h>
#include <api/nabto_api_future_queue.h>

#include <platform/np_platform.h>
#include <test_platform.hpp>

#include <platform/np_platform.h>
#include <api/nabto_device_defines.h>

#include <util/io_service.hpp>
#include <lib/span.hpp>

#include <boost/asio.hpp>

namespace nabto {
namespace test {
enum eventState {
    UNHANDLED,
    RESOLVED,
    ABORTED
};

static np_error_code eventHandlerCallback(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* handlerData) {
    BOOST_TEST(handlerData);
    np_error_code* d = (np_error_code*)handlerData;
    *d = ec;
    np_error_code err;
    if (ec == NABTO_EC_OK) {
        BOOST_TEST(future);
        BOOST_TEST(eventData);
        err = NABTO_EC_OK;
        nabto::test::eventState* d = (nabto::test::eventState*)eventData;
        *d = nabto::test::RESOLVED;
    } else if (ec == NABTO_EC_STOPPED) {
        BOOST_TEST(!future);
        BOOST_TEST(eventData);
        nabto::test::eventState* e = (nabto::test::eventState*)eventData;
        *e = nabto::test::ABORTED;
        err = ec;
    } else if (ec == NABTO_EC_ABORTED) {
        BOOST_TEST(!future);
        BOOST_TEST(!eventData);
        err = ec;
    } else {
        err = ec;
        BOOST_TEST(false, "event handler called back with invalid error code: " << ec);
    }
    return err;
}

} } // namespace

BOOST_AUTO_TEST_SUITE(listener)

BOOST_AUTO_TEST_CASE(event_test)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    dev->eventMutex = nabto_device_threads_create_mutex();
    nabto::test::eventState event = nabto::test::UNHANDLED;
    np_error_code listener = NABTO_EC_OK;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)dev);
    struct nabto_device_listener* handler = (struct nabto_device_listener*)nabto_device_listener_new((NabtoDevice*)dev);
    BOOST_TEST(handler);
    np_error_code ec = nabto_device_listener_init(dev, handler, NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS, nabto::test::eventHandlerCallback, &listener);
    BOOST_TEST(ec == NABTO_EC_OK);

    ec = nabto_device_listener_add_event(handler, &event);
    BOOST_TEST(ec == NABTO_EC_OK);

    ec = nabto_device_listener_init_future(handler, (struct nabto_device_future*)fut);
    BOOST_TEST(ec == NABTO_EC_OK);
    nabto_api_future_queue_execute_all(dev);
    BOOST_TEST(nabto_device_future_ready(fut) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(event == nabto::test::RESOLVED);
    BOOST_TEST(listener == NABTO_EC_OK);
    NabtoDeviceError ec2 = nabto_device_future_error_code(fut);
    BOOST_TEST(ec2 == NABTO_DEVICE_EC_OK);

    nabto_device_future_free(fut);
    nabto_device_listener_free((NabtoDeviceListener*)handler);
    BOOST_TEST(event == nabto::test::RESOLVED);
    BOOST_TEST(listener == NABTO_EC_ABORTED);
    nabto_device_threads_free_mutex(dev->eventMutex);
    free(dev);
}

BOOST_AUTO_TEST_CASE(event_test_multi_events)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    dev->eventMutex = nabto_device_threads_create_mutex();
    nabto::test::eventState event1 = nabto::test::UNHANDLED;
    nabto::test::eventState event2 = nabto::test::UNHANDLED;
    np_error_code listener = NABTO_EC_OK;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)dev);
    struct nabto_device_listener* handler = (struct nabto_device_listener*)nabto_device_listener_new((NabtoDevice*)dev);
    BOOST_TEST(handler);

    np_error_code ec = nabto_device_listener_init(dev, handler, NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS, nabto::test::eventHandlerCallback, &listener);
    ec = nabto_device_listener_add_event(handler, &event1);
    BOOST_TEST(ec == NABTO_EC_OK);
    ec = nabto_device_listener_add_event(handler, &event2);
    BOOST_TEST(ec == NABTO_EC_OK);

    NabtoDeviceError ec2 = nabto_device_listener_init_future(handler, (struct nabto_device_future*)fut);
    BOOST_TEST(ec2 == NABTO_DEVICE_EC_OK);
    nabto_api_future_queue_execute_all(dev);
    BOOST_TEST(nabto_device_future_ready(fut) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_future_error_code(fut) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(event1 == nabto::test::RESOLVED);
    BOOST_TEST(event2 == nabto::test::UNHANDLED);
    BOOST_TEST(listener == NABTO_EC_OK);
    nabto_device_future_free(fut);

    fut = nabto_device_future_new((NabtoDevice*)dev);
    ec2 = nabto_device_listener_init_future(handler, (struct nabto_device_future*)fut);
    BOOST_TEST(ec2 == NABTO_DEVICE_EC_OK);
    nabto_api_future_queue_execute_all(dev);
    BOOST_TEST(nabto_device_future_ready(fut) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_future_error_code(fut) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(event1 == nabto::test::RESOLVED);
    BOOST_TEST(event2 == nabto::test::RESOLVED);
    BOOST_TEST(listener == NABTO_EC_OK);
    nabto_device_future_free(fut);

    nabto_device_listener_free((NabtoDeviceListener*)handler);
    BOOST_TEST(event1 == nabto::test::RESOLVED);
    BOOST_TEST(event2 == nabto::test::RESOLVED);
    BOOST_TEST(listener == NABTO_EC_ABORTED);
    nabto_device_threads_free_mutex(dev->eventMutex);
    free(dev);
}

BOOST_AUTO_TEST_CASE(event_test_free_with_events)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    dev->eventMutex = nabto_device_threads_create_mutex();
    nabto::test::eventState event = nabto::test::UNHANDLED;
    np_error_code listener = NABTO_EC_OK;
    struct nabto_device_listener* handler = (struct nabto_device_listener*)nabto_device_listener_new((NabtoDevice*)dev);
    BOOST_TEST(handler);
    np_error_code ec = nabto_device_listener_init(dev, handler, NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS, nabto::test::eventHandlerCallback, &listener);
    BOOST_TEST(ec == NABTO_EC_OK);
    ec = nabto_device_listener_add_event(handler, &event);
    BOOST_TEST(ec == NABTO_EC_OK);
    nabto_device_listener_free((NabtoDeviceListener*)handler);
    BOOST_TEST(event == nabto::test::ABORTED);
    BOOST_TEST(listener == NABTO_EC_ABORTED);
    nabto_device_threads_free_mutex(dev->eventMutex);
    free(dev);
}

BOOST_AUTO_TEST_CASE(event_test_free_with_future)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    dev->eventMutex = nabto_device_threads_create_mutex();
    np_error_code listener = NABTO_EC_OK;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)dev);
    struct nabto_device_listener* handler = (struct nabto_device_listener*)nabto_device_listener_new((NabtoDevice*)dev);
    BOOST_TEST(handler);
    np_error_code ec = nabto_device_listener_init(dev, handler, NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS, nabto::test::eventHandlerCallback, &listener);
    BOOST_TEST(ec == NABTO_EC_OK);
    NabtoDeviceError ec2 = nabto_device_listener_init_future(handler, (struct nabto_device_future*)fut);
    BOOST_TEST(ec2 == NABTO_DEVICE_EC_OK);
    nabto_device_listener_free((NabtoDeviceListener*)handler);
    nabto_api_future_queue_execute_all(dev);
    BOOST_TEST(nabto_device_future_ready(fut) == NABTO_DEVICE_EC_ABORTED);
    BOOST_TEST(listener == NABTO_EC_ABORTED);
    BOOST_TEST(nabto_device_future_error_code(fut) == NABTO_DEVICE_EC_ABORTED);
    nabto_device_future_free(fut);
    nabto_device_threads_free_mutex(dev->eventMutex);
    free(dev);
}

BOOST_AUTO_TEST_SUITE_END()
