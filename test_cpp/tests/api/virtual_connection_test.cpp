#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <nabto/nabto_device_test.h>

#include <api/nabto_device_defines.h>
#include "../spake2/spake2_util.hpp"

#include <nlohmann/json.hpp>

#include <iostream>

namespace nabto {
namespace test {

const char* coapPath[] = { "hello", "{name}", NULL };

class TestDevice {
public:
    TestDevice()
    {
        reqListener_ = NULL;
        reqFut_ = NULL;
        passListener_ = NULL;
        passFut_ = NULL;
        NabtoDeviceError ec;
        device_ = nabto_device_new();
        BOOST_TEST(device_);
        char* logLevel = getenv("NABTO_LOG_LEVEL");
        if (logLevel != NULL) {
            ec = nabto_device_set_log_std_out_callback(device_);
            ec = nabto_device_set_log_level(device_, logLevel);
        }

        ec = nabto_device_set_server_url(device_, "server.foo.bar");
        BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
        char* key;
        nabto_device_create_private_key(device_, &key);
        ec = nabto_device_set_private_key(device_, key);
        BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
        nabto_device_string_free(key);
        nabto_device_set_product_id(device_, "test");
        nabto_device_set_device_id(device_, "test");
        nabto_device_set_local_port(device_, 0);
        nabto_device_set_p2p_port(device_, 0);
    }

    ~TestDevice()
    {
        if (connection_ != NULL) {
            // TODO: add close
            // nabto_device_virtual_connection_close(connection_)
            nabto_device_virtual_connection_free(connection_);
        }
        nabto_device_stop(device_);
        if (reqListener_ != NULL) {
            nabto_device_listener_free(reqListener_);
        }
        if (reqFut_ != NULL) {
            nabto_device_future_free(reqFut_);
        }
        if (passListener_ != NULL) {
            nabto_device_listener_free(passListener_);
        }
        if (passFut_ != NULL) {
            nabto_device_future_free(passFut_);
        }
        nabto_device_free(device_);

    }

    NabtoDeviceVirtualConnection* makeConnection()
    {
        connection_ = nabto_device_virtual_connection_new(device_);
        return connection_;
    }

    NabtoDeviceVirtualConnection* makeConnection(const std::string& devFp, const std::string& cliFp)
    {
        makeConnection();
        nabto_device_virtual_connection_set_device_fingerprint(connection_, devFp.c_str());
        nabto_device_virtual_connection_set_client_fingerprint(connection_, cliFp.c_str());
        return connection_;
    }

    static void get_request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        TestDevice* self = (TestDevice*)data;
        self->onRequest_(ec, self->request_);
        if (ec == NABTO_DEVICE_EC_OK) {
            nabto_device_listener_new_coap_request(self->reqListener_, self->reqFut_, &self->request_);
            nabto_device_future_set_callback(self->reqFut_, &get_request_callback, self);
        }
    }

    void setupCoapEndpoint(std::function<void(NabtoDeviceError ec, NabtoDeviceCoapRequest* req)> onRequest)
    {
        onRequest_ = onRequest;
        reqListener_ = nabto_device_listener_new(device_);
        reqFut_ = nabto_device_future_new(device_);
        BOOST_TEST(nabto_device_coap_init_listener(device_, reqListener_, NABTO_DEVICE_COAP_GET, coapPath) == NABTO_DEVICE_EC_OK);
        nabto_device_listener_new_coap_request(reqListener_, reqFut_, &request_);
        nabto_device_future_set_callback(reqFut_, &get_request_callback, this);

    }

    static void pass_request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        // TODO: rearm future if multiple requests are required
        TestDevice* self = (TestDevice*)data;
        self->onPass_(ec, self->passReq_);
    }

    void setupPassAuth(std::function<void(NabtoDeviceError ec, NabtoDevicePasswordAuthenticationRequest* req)> onRequest)
    {
        onPass_ = onRequest;
        passListener_ = nabto_device_listener_new(device_);
        passFut_ = nabto_device_future_new(device_);
        BOOST_TEST(nabto_device_password_authentication_request_init_listener(device_, passListener_) == NABTO_DEVICE_EC_OK);
        nabto_device_listener_new_password_authentication_request(passListener_, passFut_, &passReq_);
        nabto_device_future_set_callback(passFut_, &pass_request_callback, this);

    }


    NabtoDevice* device_;
    NabtoDeviceVirtualConnection* connection_ = NULL;

    NabtoDeviceListener* reqListener_;
    NabtoDeviceFuture* reqFut_;
    std::function<void(NabtoDeviceError ec, NabtoDeviceCoapRequest* req)> onRequest_;
    NabtoDeviceCoapRequest* request_;

    NabtoDeviceListener* passListener_;
    NabtoDeviceFuture* passFut_;
    std::function<void(NabtoDeviceError ec, NabtoDevicePasswordAuthenticationRequest* req)> onPass_;
    NabtoDevicePasswordAuthenticationRequest* passReq_;

};

static size_t fromHex(const std::string str, uint8_t* data)
{
    size_t dataLength = str.length() / 2;
    size_t i;
    int value;
    for (i = 0; i < dataLength && sscanf(str.data() + i * 2, "%2x", &value) == 1; i++) {
        data[i] = value;
    }
    return dataLength;
}

}
} // namespace

BOOST_AUTO_TEST_SUITE(virtual_connection)

BOOST_AUTO_TEST_CASE(new_free_connection)
{
    const char* cliFp = "1234567890123456789012345678901212345678901234567890123456789012";
    nabto::test::TestDevice td;
    NabtoDevice* dev = td.device_;
    NabtoDeviceListener* l = nabto_device_listener_new(dev);
    nabto_device_connection_events_init_listener(dev, l);
    NabtoDeviceFuture* fut = nabto_device_future_new(dev);
    NabtoDeviceConnectionRef ref;
    NabtoDeviceConnectionEvent ev;
    nabto_device_listener_connection_event(l, fut, &ref, &ev);

    NabtoDeviceVirtualConnection* conn = nabto_device_virtual_connection_new(dev);

    nabto_device_future_wait(fut);
    BOOST_TEST(ev == NABTO_DEVICE_CONNECTION_EVENT_OPENED);
    nabto_device_listener_connection_event(l, fut, &ref, &ev);

    BOOST_TEST(nabto_device_virtual_connection_set_client_fingerprint(conn, cliFp) == NABTO_DEVICE_EC_OK);

    BOOST_TEST(nabto_device_connection_is_virtual(dev, ref));
    char* cliFpGet = NULL;
    BOOST_TEST(nabto_device_connection_get_client_fingerprint(dev, ref, &cliFpGet) == NABTO_DEVICE_EC_OK);

    BOOST_TEST(memcmp(cliFp, cliFpGet, 64) == 0);
    nabto_device_string_free(cliFpGet);


    nabto_device_virtual_connection_free(conn);

    nabto_device_future_wait(fut);
    BOOST_TEST(ev == NABTO_DEVICE_CONNECTION_EVENT_CLOSED);
    nabto_device_listener_connection_event(l, fut, &ref, &ev);

    nabto_device_stop(dev);
    nabto_device_future_free(fut);
    nabto_device_listener_free(l);
}

BOOST_AUTO_TEST_CASE(virtual_connections_limit)
{
    nabto::test::TestDevice td;
    NabtoDevice* dev = td.device_;

    BOOST_TEST(nabto_device_limit_connections(dev, 1) == NABTO_DEVICE_EC_OK);

    NabtoDeviceVirtualConnection* conn = NULL;
    conn = td.makeConnection();
    NabtoDeviceVirtualConnection* conn2 = NULL;
    conn2 = nabto_device_virtual_connection_new(dev);

    BOOST_TEST((conn != NULL));
    BOOST_TEST((conn2 == NULL));

}

BOOST_AUTO_TEST_CASE(new_free_coap)
{
    const char* data = "FOOBAR";
    size_t dataLen = strlen(data);

    nabto::test::TestDevice td;
    NabtoDeviceVirtualConnection* conn = td.makeConnection();

    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_GET, nabto::test::coapPath);

    BOOST_TEST((req != NULL));

    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, data, dataLen) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8) == NABTO_DEVICE_EC_OK);

    nabto_device_virtual_coap_request_free(req);
}

BOOST_AUTO_TEST_CASE(execute_coap)
{
    const char* data = "FOOBAR";
    const char* coapPath[] = { "hello", "world", NULL };
    size_t dataLen = strlen(data);

    nabto::test::TestDevice td;
    bool first = true;
    td.setupCoapEndpoint([&](NabtoDeviceError ec, NabtoDeviceCoapRequest* req) {
        if (first) {
            first = false;
            BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
            char* payload;
            size_t len;
            if (nabto_device_coap_request_get_payload(req, (void**)&payload, &len) != NABTO_DEVICE_EC_OK) {
                nabto_device_coap_error_response(req, 400, "Missing payload");
                return;
            }
            BOOST_TEST(memcmp(payload, data, strlen(data)) == 0);
            uint16_t cf;
            BOOST_TEST(nabto_device_coap_request_get_content_format(req, &cf) == NABTO_DEVICE_EC_OK);
            BOOST_TEST(cf == NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);

            const char* key = nabto_device_coap_request_get_parameter(req, "name");

            BOOST_TEST(strcmp(key, coapPath[1]) == 0);


            nabto_device_coap_response_set_code(req, 205);
            nabto_device_coap_response_set_content_format(req, cf);
            nabto_device_coap_response_set_payload(req, data, dataLen);
            nabto_device_coap_response_ready(req);
            nabto_device_coap_request_free(req);
        }
        else {
            BOOST_TEST(ec == NABTO_DEVICE_EC_STOPPED);
            return;
        }

        });
    NabtoDeviceVirtualConnection* conn = td.makeConnection();

    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_GET, coapPath);

    BOOST_TEST((req != NULL));

    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, data, dataLen) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);

    nabto_device_virtual_coap_request_execute(req, fut);

    NabtoDeviceError ec = nabto_device_future_wait(fut);

    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 205);

    uint16_t cf;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_content_format(req, &cf) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(cf == NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);

    char* payload;
    size_t len;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_payload(req, (void**)&payload, &len) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(memcmp(payload, data, strlen(data)) == 0);


    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    nabto_device_future_free(fut);


    nabto_device_virtual_coap_request_free(req);
}

BOOST_AUTO_TEST_CASE(free_conn_with_coap)
{
    const char* data = "FOOBAR";
    const char* coapPath[] = { "hello", "world", NULL };
    size_t dataLen = strlen(data);

    nabto::test::TestDevice td;
    bool first = true;
    td.setupCoapEndpoint([&](NabtoDeviceError ec, NabtoDeviceCoapRequest* req) {
        if (first) {
            first = false;
            BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
            char* payload;
            size_t len;
            if (nabto_device_coap_request_get_payload(req, (void**)&payload, &len) != NABTO_DEVICE_EC_OK) {
                nabto_device_coap_error_response(req, 400, "Missing payload");
                return;
            }
            BOOST_TEST(memcmp(payload, data, strlen(data)) == 0);
            uint16_t cf;
            BOOST_TEST(nabto_device_coap_request_get_content_format(req, &cf) == NABTO_DEVICE_EC_OK);
            BOOST_TEST(cf == NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);

            const char* key = nabto_device_coap_request_get_parameter(req, "name");

            BOOST_TEST(strcmp(key, coapPath[1]) == 0);


            nabto_device_coap_response_set_code(req, 205);
            nabto_device_coap_response_set_content_format(req, cf);
            nabto_device_coap_response_set_payload(req, data, dataLen);
            nabto_device_coap_response_ready(req);
            nabto_device_coap_request_free(req);
        }
        else {
            BOOST_TEST(ec == NABTO_DEVICE_EC_STOPPED);
            return;
        }

        });
    NabtoDeviceVirtualConnection* conn = td.makeConnection();

    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_GET, coapPath);

    BOOST_TEST((req != NULL));

    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, data, dataLen) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);

    nabto_device_virtual_coap_request_execute(req, fut);

    nabto_device_virtual_connection_free(conn);
    td.connection_ = NULL; // Do not double free

    NabtoDeviceError ec = nabto_device_future_wait(fut);

    BOOST_TEST(ec == NABTO_DEVICE_EC_STOPPED);

    nabto_device_future_free(fut);
    nabto_device_virtual_coap_request_free(req);
}

BOOST_AUTO_TEST_CASE(coap_404)
{
    const char* coapPath[] = { "not", "found", NULL };

    nabto::test::TestDevice td;
    NabtoDeviceVirtualConnection* conn = td.makeConnection();

    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_GET, coapPath);

    BOOST_TEST((req != NULL));

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);

    nabto_device_virtual_coap_request_execute(req, fut);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    nabto_device_future_free(fut);

    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 404);

    nabto_device_virtual_coap_request_free(req);
}

BOOST_AUTO_TEST_CASE(execute_multiple_coap)
{
    const char* data = "FOOBAR";
    const char* coapPath[] = { "hello", "world", NULL };
    size_t dataLen = strlen(data);

    nabto::test::TestDevice td;
    td.setupCoapEndpoint([&](NabtoDeviceError ec, NabtoDeviceCoapRequest* req) {
        if (ec == NABTO_DEVICE_EC_OK) {

            nabto_device_coap_response_set_code(req, 205);
            nabto_device_coap_response_ready(req);
            nabto_device_coap_request_free(req);
        }
    });
    NabtoDeviceVirtualConnection* conn = td.makeConnection();

    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_GET, coapPath);
    NabtoDeviceVirtualCoapRequest* req2 = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_GET, coapPath);

    BOOST_TEST((req != NULL));
    BOOST_TEST((req2 != NULL));

    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, data, dataLen) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8) == NABTO_DEVICE_EC_OK);

    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req2, data, dataLen) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req2, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    NabtoDeviceFuture* fut2 = nabto_device_future_new(td.device_);

    nabto_device_virtual_coap_request_execute(req, fut);
    nabto_device_virtual_coap_request_execute(req2, fut2);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    ec = nabto_device_future_wait(fut2);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    nabto_device_future_free(fut);
    nabto_device_future_free(fut2);


    nabto_device_virtual_coap_request_free(req);
    nabto_device_virtual_coap_request_free(req2);
}


BOOST_AUTO_TEST_CASE(coap_get_tunnels)
{
    const char* coapPath[] = { "tcp-tunnels", "services", NULL };

    nabto::test::TestDevice td;
    NabtoDeviceVirtualConnection* conn = td.makeConnection();

    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_GET, coapPath);

    BOOST_TEST((req != NULL));

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);

    nabto_device_virtual_coap_request_execute(req, fut);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    nabto_device_future_free(fut);

    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 403); // Tunnels require IAM

    nabto_device_virtual_coap_request_free(req);
}

BOOST_AUTO_TEST_CASE(coap_pwd_auth)
{
    // CONSTANTS
    const std::string clientFp = "1234567890123456789012345678901212345678901234567890123456789012";
    const std::string deviceFp = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    const std::string username = "john";
    const std::string password = "FFzeqrpJTVF4";
    const char* auth1Path[] = { "p2p", "pwd-auth", "1", NULL };
    const char* auth2Path[] = { "p2p", "pwd-auth", "2", NULL };

    uint8_t clientFpBin[32];
    uint8_t deviceFpBin[32];

    nabto::test::fromHex(clientFp, clientFpBin);
    nabto::test::fromHex(deviceFp, deviceFpBin);
    // SETUP
    nabto::test::Spake2Client cli(password, clientFpBin, deviceFpBin);
    std::vector<uint8_t> T;
    BOOST_TEST(cli.calculateT(T) == 0);

    nabto::test::TestDevice td;
    NabtoDeviceVirtualConnection* conn = td.makeConnection(deviceFp, clientFp);

    td.setupPassAuth([&](NabtoDeviceError ec, NabtoDevicePasswordAuthenticationRequest* req) {
        if (ec == NABTO_DEVICE_EC_OK) {
            const char* uname = nabto_device_password_authentication_request_get_username(req);
            BOOST_TEST(std::string(uname) == username);
            BOOST_TEST(nabto_device_password_authentication_request_set_password(req, password.c_str()) == NABTO_DEVICE_EC_OK);
            nabto_device_password_authentication_request_free(req);
        }
        });

    // AUTH REQ 1
    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_POST, auth1Path);

    BOOST_TEST((req != NULL));

    nlohmann::json root;
    root["Username"] = username;
    root["T"] = nlohmann::json::binary(T);

    auto payload = nlohmann::json::to_cbor(root);

    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);

    nabto_device_virtual_coap_request_execute(req, fut);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    // AUTH RESP 1
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 201);

    uint16_t cf;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_content_format(req, &cf) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(cf == NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM);

    uint8_t* respPayload;
    size_t len;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_payload(req, (void**)&respPayload, &len) == NABTO_DEVICE_EC_OK);


    BOOST_TEST(cli.calculateK(respPayload, len) == 0);
    BOOST_TEST(cli.calculateKey());
    std::array<uint8_t, 32> req2Key;
    BOOST_TEST(nabto::test::Spake2Client::sha256(cli.key_.data(), cli.key_.size(), req2Key.data()) == 0);

    std::array<uint8_t, 32> req2KeyHash;
    BOOST_TEST(nabto::test::Spake2Client::sha256(req2Key.data(), req2Key.size(), req2KeyHash.data()) == 0);

    nabto_device_virtual_coap_request_free(req);


    // AUTH REQ 2
    req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_POST, auth2Path);

    BOOST_TEST((req != NULL));

    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, req2KeyHash.data(), req2KeyHash.size()) == NABTO_DEVICE_EC_OK);

    nabto_device_virtual_coap_request_execute(req, fut);

    ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    // AUTH RESP 2
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 201);

    BOOST_TEST(nabto_device_virtual_coap_request_get_response_content_format(req, &cf) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(cf == NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM);

    uint8_t* resp2Payload;
    size_t len2;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_payload(req, (void**)&resp2Payload, &len2) == NABTO_DEVICE_EC_OK);

    BOOST_TEST(memcmp(resp2Payload, req2Key.data(), req2Key.size()) == 0);


    nabto_device_future_free(fut);
    nabto_device_virtual_coap_request_free(req);
}

BOOST_AUTO_TEST_CASE(coap_get_endpoints)
{
    const char* coapPath[] = { "p2p", "endpoints", NULL };

    nabto::test::TestDevice td;
    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);
    nabto_device_start(td.device_, fut);
    nabto_device_future_wait(fut);

    NabtoDeviceVirtualConnection* conn = td.makeConnection();

    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_GET, coapPath);

    BOOST_TEST((req != NULL));


    nabto_device_virtual_coap_request_execute(req, fut);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    nabto_device_future_free(fut);

    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 205);

    nabto_device_virtual_coap_request_free(req);
}

BOOST_AUTO_TEST_CASE(coap_post_rendezvous)
{
    const char* coapPath[] = { "p2p", "rendezvous", NULL };

    nabto::test::TestDevice td;
    NabtoDeviceFuture* fut = nabto_device_future_new(td.device_);

    NabtoDeviceVirtualConnection* conn = td.makeConnection();

    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_POST, coapPath);

    BOOST_TEST((req != NULL));


    nabto_device_virtual_coap_request_execute(req, fut);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    nabto_device_future_free(fut);

    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 400); // Rendezvous not available on virtual connection

    nabto_device_virtual_coap_request_free(req);
}



BOOST_AUTO_TEST_SUITE_END()
