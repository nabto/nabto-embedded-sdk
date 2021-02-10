#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "../../util/helper.hpp"
#include "attached_test_device.hpp"
#include "../attach/basestation_fixture.hpp"

#include <future>


BOOST_FIXTURE_TEST_SUITE(service_invoke, nabto::test::BasestationFixture)

BOOST_AUTO_TEST_CASE(create_destroy)
{
    NabtoDevice* device = nabto_device_new();
    NabtoDeviceServiceInvoke* s = nabto_device_service_invoke_new(device);
    BOOST_TEST((s != NULL));
    nabto_device_service_invoke_free(s);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_CASE(set_value_multiple_times)
{
    NabtoDevice* device = nabto_device_new();
    NabtoDeviceServiceInvoke* s = nabto_device_service_invoke_new(device);
    BOOST_TEST((s != NULL));
    BOOST_TEST(nabto_device_service_invoke_set_service_id(s, "foo") == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_service_invoke_set_service_id(s, "bar") == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_service_invoke_set_message(s, "foo") == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_service_invoke_set_message(s, "bar") == NABTO_DEVICE_EC_OK);

    nabto_device_service_invoke_free(s);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_CASE(not_attached)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    attachedTestDevice.noAttach();

    NabtoDevice* dev = attachedTestDevice.device();

    const char* serviceId = "foobar";
    const char* message = "foo";

    NabtoDeviceServiceInvoke* s = nabto_device_service_invoke_new(dev);
    nabto_device_service_invoke_set_service_id(s, serviceId);
    nabto_device_service_invoke_set_message(s, message);

    NabtoDeviceFuture* f = nabto_device_future_new(dev);
    nabto_device_service_invoke_execute(s, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_NOT_ATTACHED));

    nabto_device_future_free(f);
    nabto_device_service_invoke_free(s);
}

BOOST_AUTO_TEST_CASE(notification_send_ok)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    attachedTestDevice.attach(getHostname(), getPort(), getRootCerts());

    NabtoDevice* dev = attachedTestDevice.device();

    const char* serviceId = "foobar";
    const char* message = "foo";

    NabtoDeviceServiceInvoke* s = nabto_device_service_invoke_new(dev);
    nabto_device_service_invoke_set_service_id(s, serviceId);
    nabto_device_service_invoke_set_message(s, message);

    NabtoDeviceFuture* f = nabto_device_future_new(dev);
    nabto_device_service_invoke_execute(s, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_OK));

    BOOST_TEST(nabto_device_service_invoke_get_response_status_code(s) == 200);
    std::string desiredResponse = R"({"hello": "world"})";
    BOOST_TEST(nabto_device_service_invoke_get_response_message(s) == desiredResponse);

    nabto_device_future_free(f);
    nabto_device_service_invoke_free(s);
}

BOOST_AUTO_TEST_SUITE_END()