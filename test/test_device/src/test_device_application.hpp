#pragma once

#include "nabto_device_ptr.hpp"

#include "coap_get.hpp"
#include "coap_post.hpp"
#include "stream_echo.hpp"
#include "stream_recv.hpp"

#include <util/io_service.hpp>
#include <util/tcp_echo_server.hpp>
#include <util/test_logger.hpp>
#include <http_server/http_server.hpp>

#include <iostream>

namespace nabto {
namespace test {

NabtoDeviceError allow_anyone_to_connect(NabtoDeviceConnectionRef connectionReference, const char* action, void* attributes, size_t attributesLength, void* userData)
{
    return NABTO_DEVICE_EC_OK;
}


class TestDeviceApplication {
 public:
    TestDeviceApplication()
        : ioService_(IoService::create("test_device")),
          device_(nabto_device_new()),
          logger_(TestLogger::create()),
          getListener_(nabto_device_listener_new(device_.get())),
          postListener_(nabto_device_listener_new(device_.get())),
          tcpEchoServer_(ioService_->getIoService(),58165 /*chosen randomly*/),

          httpServer_(ioService_->getIoService(), logger_)
    {
    }

    ~TestDeviceApplication() {
        nabto_device_stop(device_.get());
    }
    void init(const std::string& productId, const std::string& deviceId, const std::string& server, const std::string& privateKey)
    {
        productId_ = productId;
        deviceId_ = deviceId;
        nabto_device_set_log_std_out_callback(device_.get());
        NabtoDeviceError ec;

        ec = nabto_device_set_private_key(device_.get(), privateKey.c_str());
        if (ec != NABTO_DEVICE_EC_OK) {
            return;
        }
        ec = nabto_device_set_server_url(device_.get(), server.c_str());
        if (ec != NABTO_DEVICE_EC_OK) {
            return;
        }

        nabto_device_set_product_id(device_.get(), productId.c_str());
        nabto_device_set_device_id(device_.get(), deviceId.c_str());

        ec = nabto_device_enable_mdns(device_.get());
        if (ec != NABTO_DEVICE_EC_OK) {
            return;
        }

        ec = nabto_device_enable_tcp_tunnelling(device_.get());
        if (ec != NABTO_DEVICE_EC_OK) {
            return;
        }

        //ec = nabto_device_iam_override_check_access_implementation(device_.get(), allow_anyone_to_connect, NULL);
        //if (ec) {
        //    std::cerr << "Could not override iam check access implementation" << std::endl;
        //}

        const char* coapTestGet[]  = {"test", "get", NULL};
        const char* coapTestPost[] = {"test", "post", NULL};
        nabto_device_coap_init_listener(device_.get(), getListener_.get(), NABTO_DEVICE_COAP_GET, coapTestGet);
        nabto_device_coap_init_listener(device_.get(), postListener_.get(), NABTO_DEVICE_COAP_POST, coapTestPost);

        getHandler_ = std::make_unique<GetHandler>(device_.get(), getListener_.get());
        postHandler_ = std::make_unique<PostHandler>(device_.get(), postListener_.get());

        echoListener_ = std::make_unique<EchoListener>(device_.get());
        recvListener_ = std::make_unique<RecvListener>(device_.get());
        echoListener_->startListen();
        recvListener_->startListen();

        initHttpServer();
    }

    void initHttpServer() {
        httpServer_.setPort(29281);
        lib::error_code ec = httpServer_.init();
        if (ec) {
            std::cout << "failed to init http server" << ec.message() << std::endl;
        }
        httpServer_.addResourceHandler(boost::beast::http::verb::get, "/hello-world", [](nabto::http_server::RequestPtr request, nabto::http_server::ResponsePtr response){
                response->setContentType("text/plain");
                response->setBody("Hello World");
                response->setStatusCode(200);
            });
    }

    void start() {
        NabtoDeviceError ec;
        ec = nabto_device_start(device_.get());
        if (ec != NABTO_DEVICE_EC_OK) {
            return;
        }
    }

    void setLogLevel(const std::string& logLevel) {
        NabtoDeviceError ec;
        ec = nabto_device_set_log_level(device_.get(), logLevel.c_str());
        if (ec != NABTO_DEVICE_EC_OK) {
            std::cerr << "Could not set log level: " << logLevel.c_str() << " " << nabto_device_error_get_message(ec) << std::endl;
        }
    }

    std::string getDeviceFingerprint() {
        char* fingerprint;

        NabtoDeviceError ec = nabto_device_get_device_fingerprint_hex(device_.get(), &fingerprint);
        if (ec != NABTO_DEVICE_EC_OK) {
            return "";
        }
        NabtoDeviceStringPtr str(fingerprint);
        return std::string(str.get());
    }

    void describe()
    {
        std::cout << "Test Device Application" << std::endl;
        std::cout << "  product id: " << productId_ << ", device id: " << deviceId_ << std::endl;
        std::cout << "  fingerprint: " << getDeviceFingerprint() << std::endl;
        std::cout << "  http server port: " << httpServer_.getPort() << ", tcp echo server port: " << tcpEchoServer_.getPort() << std::endl;

    }

 private:
    IoServicePtr ioService_;
    NabtoDevicePtr device_;
    log::LoggerPtr logger_;

    NabtoDeviceListenerPtr getListener_;
    NabtoDeviceListenerPtr postListener_;

    std::unique_ptr<GetHandler> getHandler_;
    std::unique_ptr<PostHandler> postHandler_;

    std::unique_ptr<EchoListener> echoListener_;
    std::unique_ptr<RecvListener> recvListener_;

    TcpEchoServer tcpEchoServer_;
    http_server::HttpServer httpServer_;
    std::string productId_;
    std::string deviceId_;

};

} } // namespace
