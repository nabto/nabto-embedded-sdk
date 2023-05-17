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

    NabtoDeviceIceServersRequest* req = nabto_device_ice_servers_request_new(dev);
    nabto_device_ice_servers_request_free(req);
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

    NabtoDeviceIceServersRequest* req = nabto_device_ice_servers_request_new(dev);
    NabtoDeviceFuture* f = nabto_device_future_new(dev);

    const char* id = "foobar";

    BOOST_TEST(EC(nabto_device_ice_servers_request_send(id, req, f)) == EC(NABTO_DEVICE_EC_OK));

    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_OK));

    size_t count = nabto_device_ice_servers_request_get_server_count(req);
    BOOST_TEST(count == (size_t)2);

    const char* username = nabto_device_ice_servers_request_get_username(req, 0);
    BOOST_TEST(std::string(username) == "test:devTest:foobar");

    const char* credential = nabto_device_ice_servers_request_get_credential(req, 0);
    BOOST_TEST(std::string(credential) == "verySecretAccessKey");

    size_t urlsLen = nabto_device_ice_servers_request_get_urls_count(req, 0);
    BOOST_TEST(urlsLen == (size_t)2);
    const char* url = nabto_device_ice_servers_request_get_url(req, 0, 0);
    BOOST_TEST(std::string(url) == "turn:turn.nabto.net:9991?transport=udp");
    url = nabto_device_ice_servers_request_get_url(req, 0, 1);
    BOOST_TEST(std::string(url) == "turn:turn.nabto.net:9991?transport=tcp");


    username = nabto_device_ice_servers_request_get_username(req, 1);
    BOOST_TEST(std::string(username) == "test:devTest:foobar");

    credential = nabto_device_ice_servers_request_get_credential(req, 1);
    BOOST_TEST(std::string(credential) == "anotherVerySecretAccessKey");

    urlsLen = nabto_device_ice_servers_request_get_urls_count(req, 1);
    BOOST_TEST(urlsLen == (size_t)1);
    url = nabto_device_ice_servers_request_get_url(req, 1, 0);
    BOOST_TEST(std::string(url) == "turns:turn.nabto.net:443?transport=tcp");


    nabto_device_ice_servers_request_free(req);
    nabto_device_future_free(f);
}

BOOST_AUTO_TEST_SUITE_END()
