#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "../../util/helper.hpp"
#include "../../util/io_service.hpp"
#include "attached_test_device.hpp"
#include "../attach/basestation_fixture.hpp"

#include <thread>
#include <future>

BOOST_AUTO_TEST_SUITE(fcm, *boost::unit_test::timeout(10))

BOOST_AUTO_TEST_CASE(create_destroy_notification)
{
    NabtoDevice* dev = nabto_device_new();

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    nabto_device_fcm_notification_free(n);
    nabto_device_stop(dev);
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
    nabto_device_stop(dev);
    nabto_device_free(dev);
}

BOOST_AUTO_TEST_SUITE_END()

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

BOOST_FIXTURE_TEST_SUITE(fcm, nabto::test::BasestationFixture, *boost::unit_test::timeout(30))

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

BOOST_AUTO_TEST_CASE(notification_send_not_attached)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    NabtoDevice* dev = attachedTestDevice.device();

    // TODO: Remove with below comment
    nabto_device_set_server_url(dev, getHostname().c_str());
    nabto_device_set_server_port(dev, getPort());
    nabto_device_set_root_certs(dev, getRootCerts().c_str());

    attachedTestDevice.noAttach();


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

    // TODO: BS test fixture hangs in stop() if no device attaches to it and it is running after another test which used the fixture. Fix test fixture so BS can stop without hanging, then remove this pointless attach.
    nabto_device_set_basestation_attach(dev, true);
    attachedTestDevice.waitForAttached();
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
