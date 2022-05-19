#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "../../util/helper.hpp"
#include "attached_test_device.hpp"
#include "../attach/basestation_fixture.hpp"

#include <future>


BOOST_AUTO_TEST_SUITE(service_invoke)

BOOST_AUTO_TEST_CASE(create_destroy)
{
    NabtoDevice* device = nabto_device_new();
    NabtoDeviceServiceInvocation* s = nabto_device_service_invocation_new(device);
    BOOST_TEST((s != NULL));
    nabto_device_service_invocation_free(s);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_CASE(set_value_multiple_times)
{
    NabtoDevice* device = nabto_device_new();
    NabtoDeviceServiceInvocation* s = nabto_device_service_invocation_new(device);
    BOOST_TEST((s != NULL));

    BOOST_TEST(nabto_device_service_invocation_set_service_id(s, "foo") == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_service_invocation_set_service_id(s, "bar") == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_service_invocation_set_message(s, (const uint8_t*)"foo", 3) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_service_invocation_set_message(s, (const uint8_t*)"bar", 3) == NABTO_DEVICE_EC_OK);

    nabto_device_service_invocation_free(s);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(service_invoke, nabto::test::BasestationFixture)

BOOST_AUTO_TEST_CASE(not_attached)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    NabtoDevice* dev = attachedTestDevice.device();

    // TODO: Remove with below comment
    nabto_device_set_server_url(dev, getHostname().c_str());
    nabto_device_set_server_port(dev, getPort());
    nabto_device_set_root_certs(dev, getRootCerts().c_str());

    attachedTestDevice.noAttach();

    const char* serviceId = "foobar";
    const char* message = "foo";

    NabtoDeviceServiceInvocation* s = nabto_device_service_invocation_new(dev);
    nabto_device_service_invocation_set_service_id(s, serviceId);
    nabto_device_service_invocation_set_message(s, (uint8_t*)message, strlen(message));

    NabtoDeviceFuture* f = nabto_device_future_new(dev);
    nabto_device_service_invocation_execute(s, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_NOT_ATTACHED));

    nabto_device_future_free(f);
    nabto_device_service_invocation_free(s);

    // TODO: BS test fixture hangs in stop() if no device attaches to it and it is running after another test which used the fixture. Fix test fixture so BS can stop without hanging, then remove this pointless attach.
    nabto_device_set_basestation_attach(dev, true);
    attachedTestDevice.waitForAttached();
}

BOOST_AUTO_TEST_CASE(notification_send_ok)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    attachedTestDevice.attach(getHostname(), getPort(), getRootCerts());

    NabtoDevice* dev = attachedTestDevice.device();

    const char* serviceId = "foobar";
    const char* message = "foo";

    NabtoDeviceServiceInvocation* s = nabto_device_service_invocation_new(dev);
    nabto_device_service_invocation_set_service_id(s, serviceId);
    nabto_device_service_invocation_set_message(s, (uint8_t*)message, strlen(message));

    NabtoDeviceFuture* f = nabto_device_future_new(dev);
    nabto_device_service_invocation_execute(s, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_OK));

    BOOST_TEST(nabto_device_service_invocation_get_response_status_code(s) == 200);
    BOOST_TEST(nabto_device_service_invocation_get_response_message_format(s) ==
               NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_BINARY);
    std::string desiredResponse = R"({"hello": "world"})";
    const uint8_t* responseData = nabto_device_service_invocation_get_response_message_data(s);
    size_t responseDataLength = nabto_device_service_invocation_get_response_message_size(s);
    BOOST_TEST(std::string(reinterpret_cast<const char*>(responseData), responseDataLength) == desiredResponse);

    nabto_device_future_free(f);
    nabto_device_service_invocation_free(s);
}

BOOST_AUTO_TEST_CASE(ok_text_format)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    attachedTestDevice.attach(getHostname(), getPort(), getRootCerts());

    NabtoDevice* dev = attachedTestDevice.device();

    const char* serviceId = "foobar";
    const char* message = "text-format";

    NabtoDeviceServiceInvocation* s = nabto_device_service_invocation_new(dev);
    nabto_device_service_invocation_set_service_id(s, serviceId);
    nabto_device_service_invocation_set_message(s, (uint8_t*)message, strlen(message));

    NabtoDeviceFuture* f = nabto_device_future_new(dev);
    nabto_device_service_invocation_execute(s, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_OK));

    BOOST_TEST(nabto_device_service_invocation_get_response_status_code(s) == 200);
    BOOST_TEST(nabto_device_service_invocation_get_response_message_format(s) ==
               NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_TEXT);

    std::string desiredResponse = "text string";
    const uint8_t* responseData = nabto_device_service_invocation_get_response_message_data(s);
    size_t responseDataLength = nabto_device_service_invocation_get_response_message_size(s);
    BOOST_TEST(std::string(reinterpret_cast<const char*>(responseData), responseDataLength) == desiredResponse);

    nabto_device_future_free(f);
    nabto_device_service_invocation_free(s);
}

BOOST_AUTO_TEST_SUITE_END()
