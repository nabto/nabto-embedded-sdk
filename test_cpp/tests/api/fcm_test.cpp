#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "../../util/helper.hpp"

#include <thread>

BOOST_AUTO_TEST_SUITE(fcm)

BOOST_AUTO_TEST_CASE(create_destroy_notification)
{
    NabtoDevice* dev = nabto_device_new();

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
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
    NabtoDevice* dev = nabto_device_new();

    const char* projectId = "foobar";

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    BOOST_REQUIRE(n != NULL);
    BOOST_TEST(nabto_device_fcm_notification_set_project_id(n, projectId) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_fcm_notification_set_payload(n, testFcmPayload.c_str()) == NABTO_DEVICE_EC_OK);

    nabto_device_fcm_notification_free(n);
    nabto_device_free(dev);
}

BOOST_AUTO_TEST_CASE(notification_send_not_attached)
{
    NabtoDevice* dev = nabto_device_new();
    NabtoDeviceFuture* f = nabto_device_future_new(dev);

    nabto_device_set_product_id(dev, "pr-12345678");
    nabto_device_set_device_id(dev, "de-abcdefgh");
    char* privateKey;
    nabto_device_create_private_key(dev, &privateKey);
    nabto_device_set_private_key(dev, privateKey);
    nabto_device_string_free(privateKey);

    nabto_device_set_local_port(dev, 0);
    nabto_device_set_p2p_port(dev, 0);


    nabto_device_start(dev, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_OK));

    const char* projectId = "foobar";

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    BOOST_REQUIRE(n != NULL);
    BOOST_TEST(nabto_device_fcm_notification_set_project_id(n, projectId) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_fcm_notification_set_payload(n, testFcmPayload.c_str()) == NABTO_DEVICE_EC_OK);

    nabto_device_fcm_send(n, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_NOT_ATTACHED));

    nabto_device_future_free(f);
    nabto_device_fcm_notification_free(n);
    nabto_device_free(dev);
}

BOOST_AUTO_TEST_SUITE_END()
