#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "../../util/helper.hpp"
#include "../attach/attach_server.hpp"
#include "../../util/io_service.hpp"
#include "attached_test_device.hpp"
#include "../attach/basestation_fixture.hpp"

#include <thread>
#include <future>

BOOST_FIXTURE_TEST_SUITE(fcm, nabto::test::BasestationFixture)

BOOST_AUTO_TEST_CASE(create_destroy_notification)
{
    NabtoDevice* dev = nabto_device_new();

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    nabto_device_fcm_notification_free(n);
    nabto_device_free(dev);
}

BOOST_AUTO_TEST_CASE(multi_set_on_notification)
{
    std::string s1 = "some string";
    std::string s2 = "some other string";

    NabtoDevice* dev = nabto_device_new();

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    nabto_device_fcm_notification_set_payload(n, s1.c_str());
    nabto_device_fcm_notification_set_payload(n, s2.c_str());
    nabto_device_fcm_notification_set_project_id(n, s1.c_str());
    nabto_device_fcm_notification_set_project_id(n, s2.c_str());
    nabto_device_fcm_notification_free(n);
    nabto_device_free(dev);
}

std::string testFcmPayload = R"(
{
    "message":{
        "notification": {
            "title": "foo",
            "body": "bar"
        },
        "token": "abcdef"
    }
}
)";

BOOST_AUTO_TEST_CASE(notification_set)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    attachedTestDevice.attach(getHostname(), getPort(), getRootCerts());

    NabtoDevice* dev = attachedTestDevice.device();

    const char* projectId = "foobar";

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    BOOST_REQUIRE(n != NULL);
    BOOST_TEST(nabto_device_fcm_notification_set_project_id(n, projectId) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_fcm_notification_set_payload(n, testFcmPayload.c_str()) == NABTO_DEVICE_EC_OK);

    nabto_device_fcm_notification_free(n);
}

BOOST_AUTO_TEST_CASE(notification_send_not_attached)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    attachedTestDevice.noAttach();

    NabtoDevice* dev = attachedTestDevice.device();

    const char* projectId = "foobar";

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    BOOST_REQUIRE(n != NULL);
    BOOST_TEST(nabto_device_fcm_notification_set_project_id(n, projectId) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_fcm_notification_set_payload(n, testFcmPayload.c_str()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* f = nabto_device_future_new(dev);
    nabto_device_fcm_send(n, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_NOT_ATTACHED));

    nabto_device_future_free(f);
    nabto_device_fcm_notification_free(n);
}

BOOST_AUTO_TEST_CASE(notification_send_ok)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    attachedTestDevice.attach(getHostname(), getPort(), getRootCerts());

    NabtoDevice* dev = attachedTestDevice.device();

    const char* projectId = "foobar";

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    BOOST_REQUIRE(n != NULL);
    BOOST_TEST(nabto_device_fcm_notification_set_project_id(n, projectId) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_fcm_notification_set_payload(n, testFcmPayload.c_str()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* f = nabto_device_future_new(dev);
    nabto_device_fcm_send(n, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_OK));


    BOOST_TEST(nabto_device_fcm_notification_get_response_status_code(n) == 200);

    const char* responseBody = nabto_device_fcm_notification_get_response_body(n);
    BOOST_REQUIRE(responseBody != NULL);

    auto root = nlohmann::json::parse(responseBody);
    std::string name = root["name"].get<std::string>();
    BOOST_TEST(!name.empty());

    nabto_device_future_free(f);
    nabto_device_fcm_notification_free(n);
}

BOOST_AUTO_TEST_CASE(notification_send_stop)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    attachedTestDevice.attach(getHostname(), getPort(), getRootCerts());

    NabtoDevice* dev = attachedTestDevice.device();

    const char* projectId = "foobar";

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    BOOST_REQUIRE(n != NULL);
    BOOST_TEST(nabto_device_fcm_notification_set_project_id(n, projectId) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_fcm_notification_set_payload(n, testFcmPayload.c_str()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* f = nabto_device_future_new(dev);
    nabto_device_fcm_send(n, f);
    nabto_device_fcm_stop(n);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_STOPPED));

    nabto_device_future_free(f);
    nabto_device_fcm_notification_free(n);
}

BOOST_AUTO_TEST_SUITE_END()
