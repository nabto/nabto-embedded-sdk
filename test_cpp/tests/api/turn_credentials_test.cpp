#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "../../util/helper.hpp"
#include "../../util/io_service.hpp"
#include "attached_test_device.hpp"
#include "../attach/basestation_fixture.hpp"

#include <thread>
#include <future>

BOOST_AUTO_TEST_SUITE(turn_creds, *boost::unit_test::timeout(10))

BOOST_AUTO_TEST_CASE(create_destroy_request)
{
    NabtoDevice* dev = nabto_device_new();

    NabtoDeviceTurnCredentialRequest* req = nabto_device_turn_credential_request_new(dev);
    nabto_device_turn_credential_request_free(req);
    nabto_device_stop(dev);
    nabto_device_free(dev);
}


BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(turn_creds, nabto::test::BasestationFixture, *boost::unit_test::timeout(10))

BOOST_AUTO_TEST_CASE(get_turn_creds)
{
    nabto::test::AttachedTestDevice attachedTestDevice;

    attachedTestDevice.attach(getHostname(), getPort(), getRootCerts());

    NabtoDevice* dev = attachedTestDevice.device();

    NabtoDeviceTurnCredentialRequest* req = nabto_device_turn_credential_request_new(dev);
    NabtoDeviceFuture* f = nabto_device_future_new(dev);

    const char* id = "foobar";

    BOOST_TEST(EC(nabto_device_turn_credential_request_send(id, req, f)) == EC(NABTO_DEVICE_EC_OK));

    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_OK));

    size_t count = 0;
    BOOST_TEST(EC(nabto_device_turn_credential_get_results_count(req, &count)) == EC(NABTO_DEVICE_EC_OK));
    BOOST_TEST(count == (size_t)2);

    NabtoDeviceTurnCredentialResult* result = NULL;

    BOOST_TEST(EC(nabto_device_turn_credential_get_result(req, 0, &result)) == EC(NABTO_DEVICE_EC_OK));

    char* username = NULL;
    BOOST_TEST(EC(nabto_device_turn_credential_get_username(result, &username)) == EC(NABTO_DEVICE_EC_OK));
    BOOST_TEST(std::string(username) == "test:devTest:foobar");

    char* credential = NULL;
    BOOST_TEST(EC(nabto_device_turn_credential_get_credential(result, &credential)) == EC(NABTO_DEVICE_EC_OK));
    BOOST_TEST(std::string(credential) == "verySecretAccessKey");

    uint32_t ttl = 0;
    BOOST_TEST(EC(nabto_device_turn_credential_get_ttl(result, &ttl)) == EC(NABTO_DEVICE_EC_OK));
    BOOST_TEST(ttl == (size_t)86400);

    char** urls = NULL;
    size_t urlsLen = 0;
    BOOST_TEST(EC(nabto_device_turn_credential_get_urls(result, &urls, &urlsLen)) == EC(NABTO_DEVICE_EC_OK));

    BOOST_TEST(urlsLen == (size_t)2);
    BOOST_TEST(std::string(urls[0]) == "turn:turn.nabto.net:9991?transport=udp");
    BOOST_TEST(std::string(urls[1]) == "turn:turn.nabto.net:9991?transport=tcp");


    BOOST_TEST(EC(nabto_device_turn_credential_get_result(req, 1, &result)) == EC(NABTO_DEVICE_EC_OK));

    username = NULL;
    BOOST_TEST(EC(nabto_device_turn_credential_get_username(result, &username)) == EC(NABTO_DEVICE_EC_OK));
    BOOST_TEST(std::string(username) == "test:devTest:foobar");

    credential = NULL;
    BOOST_TEST(EC(nabto_device_turn_credential_get_credential(result, &credential)) == EC(NABTO_DEVICE_EC_OK));
    BOOST_TEST(std::string(credential) == "anotherVerySecretAccessKey");

    ttl = 0;
    BOOST_TEST(EC(nabto_device_turn_credential_get_ttl(result, &ttl)) == EC(NABTO_DEVICE_EC_OK));
    BOOST_TEST(ttl == (size_t)86400);

    urls = NULL;
    urlsLen = 0;
    BOOST_TEST(EC(nabto_device_turn_credential_get_urls(result, &urls, &urlsLen)) == EC(NABTO_DEVICE_EC_OK));

    BOOST_TEST(urlsLen == (size_t)1);
    BOOST_TEST(std::string(urls[0]) == "turns:turn.nabto.net:443?transport=tcp");

    nabto_device_turn_credential_request_free(req);
    nabto_device_future_free(f);
}

BOOST_AUTO_TEST_SUITE_END()
