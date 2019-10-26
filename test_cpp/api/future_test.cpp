#include <boost/test/unit_test.hpp>

#include <api/nabto_api_future_queue.h>
#include <api/nabto_device_future.h>

#include <platform/np_platform.h>
#include <test_platform.hpp>

#include <test_platform_epoll.hpp>

#include <platform/np_platform.h>
#include <api/nabto_device_defines.h>

#include <util/io_service.hpp>
#include <lib/span.hpp>

#include <boost/asio.hpp>


BOOST_AUTO_TEST_SUITE(futures)

BOOST_AUTO_TEST_CASE(resolve_a_future)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    dev->eventMutex = nabto_device_threads_create_mutex();
    struct nabto_device_future* fut = nabto_device_future_new(dev);
    BOOST_TEST(nabto_device_future_ready((NabtoDeviceFuture*)fut) == NABTO_DEVICE_EC_API_FUTURE_NOT_READY);
    nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_future_ready((NabtoDeviceFuture*)fut) == NABTO_DEVICE_EC_OK);
}

BOOST_AUTO_TEST_CASE(resolve_a_future_with_cb)
{
    bool called = false;
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    dev->eventMutex = nabto_device_threads_create_mutex();
    struct nabto_device_future* fut = nabto_device_future_new(dev);
    BOOST_TEST(nabto_device_future_ready((NabtoDeviceFuture*)fut) == NABTO_DEVICE_EC_API_FUTURE_NOT_READY);
    nabto_device_future_set_callback((NabtoDeviceFuture*)fut, [](NabtoDeviceFuture* fut, NabtoDeviceError ec, void* userData){
                                                                  *((bool*)userData) = true;
                                                              }, &called);
    nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OK);
    nabto_api_future_queue_execute_all(dev);
    BOOST_TEST(called);
}

BOOST_AUTO_TEST_CASE(set_cb_after_resolved)
{
    bool called = false;
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    dev->eventMutex = nabto_device_threads_create_mutex();
    struct nabto_device_future* fut = nabto_device_future_new(dev);
    nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OK);
    nabto_api_future_queue_execute_all(dev);
    nabto_device_future_set_callback((NabtoDeviceFuture*)fut, [](NabtoDeviceFuture* fut, NabtoDeviceError ec, void* userData){
                                                                  *((bool*)userData) = true;
                                                              }, &called);
    BOOST_TEST(!called);
    nabto_api_future_queue_execute_all(dev);
    BOOST_TEST(called);
}

BOOST_AUTO_TEST_CASE(resolve_multiple_callbacks)
{
    bool called1 = false;
    bool called2 = false;
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    dev->eventMutex = nabto_device_threads_create_mutex();
    struct nabto_device_future* fut1 = nabto_device_future_new(dev);
    struct nabto_device_future* fut2 = nabto_device_future_new(dev);
    nabto_device_future_resolve(fut1, NABTO_DEVICE_EC_OK);
    nabto_device_future_resolve(fut2, NABTO_DEVICE_EC_OK);
    nabto_api_future_queue_execute_all(dev);
    nabto_device_future_set_callback((NabtoDeviceFuture*)fut1, [](NabtoDeviceFuture* fut, NabtoDeviceError ec, void* userData){
                                                                  *((bool*)userData) = true;
                                                              }, &called1);
    nabto_device_future_set_callback((NabtoDeviceFuture*)fut2, [](NabtoDeviceFuture* fut, NabtoDeviceError ec, void* userData){
                                                                  *((bool*)userData) = true;
                                                              }, &called2);
    BOOST_TEST(!called1);
    BOOST_TEST(!called2);
    nabto_api_future_queue_execute_all(dev);
    BOOST_TEST(called2);
    BOOST_TEST(called1);
}

BOOST_AUTO_TEST_CASE(future_queue_empty_after_resolving)
{
    bool called1 = false;
    bool called2 = false;
    struct nabto_device_context* dev = (struct nabto_device_context*)calloc(1, sizeof(struct nabto_device_context));
    dev->eventMutex = nabto_device_threads_create_mutex();
    struct nabto_device_future* fut1 = nabto_device_future_new(dev);
    struct nabto_device_future* fut2 = nabto_device_future_new(dev);
    nabto_device_future_resolve(fut1, NABTO_DEVICE_EC_OK);
    nabto_device_future_resolve(fut2, NABTO_DEVICE_EC_OK);
    nabto_api_future_queue_execute_all(dev);
    nabto_device_future_set_callback((NabtoDeviceFuture*)fut1, [](NabtoDeviceFuture* fut, NabtoDeviceError ec, void* userData){
                                                                  *((bool*)userData) = true;
                                                              }, &called1);
    nabto_device_future_set_callback((NabtoDeviceFuture*)fut2, [](NabtoDeviceFuture* fut, NabtoDeviceError ec, void* userData){
                                                                  *((bool*)userData) = true;
                                                              }, &called2);
    BOOST_TEST(!called1);
    BOOST_TEST(!called2);
    nabto_api_future_queue_execute_all(dev);
    BOOST_TEST(called2);
    BOOST_TEST(called1);
    BOOST_TEST((dev->queueHead == NULL));
    nabto_api_future_queue_execute_all(dev);
}

BOOST_AUTO_TEST_SUITE_END()
