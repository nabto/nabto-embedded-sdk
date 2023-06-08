#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <nabto/nabto_device_test.h>

#include <api/nabto_device_defines.h>

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
        nabto_device_free(device_);

    }

    NabtoDeviceVirtualConnection* makeConnection()
    {
        connection_ = nabto_device_virtual_connection_new(device_);
        return connection_;
    }

    static void get_request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        TestDevice* self = (TestDevice*)data;
        self->onRequest_(ec, self->request_);
    }

    void setupCoapEndpoint(std::function<void (NabtoDeviceError ec, NabtoDeviceCoapRequest* req)> onRequest)
    {
        onRequest_ = onRequest;
        reqListener_ = nabto_device_listener_new(device_);
        reqFut_ = nabto_device_future_new(device_);
        BOOST_TEST(nabto_device_coap_init_listener(device_, reqListener_, NABTO_DEVICE_COAP_GET, coapPath) == NABTO_DEVICE_EC_OK);
        nabto_device_listener_new_coap_request(reqListener_, reqFut_, &request_);
        nabto_device_future_set_callback(reqFut_, &get_request_callback, this);

    }


    NabtoDevice* device_;
    NabtoDeviceVirtualConnection* connection_ = NULL;

    NabtoDeviceListener* reqListener_;
    NabtoDeviceFuture* reqFut_;
    std::function<void(NabtoDeviceError ec, NabtoDeviceCoapRequest* req)> onRequest_;
    NabtoDeviceCoapRequest* request_;

};

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
            BOOST_TEST(memcmp(payload, data, strlen(data))==0);
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
        } else {
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

BOOST_AUTO_TEST_SUITE_END()
