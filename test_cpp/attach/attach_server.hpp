#pragma once

#include <dtls/dtls_server.hpp>
#include <boost/asio/io_service.hpp>
#include <util/logger.hpp>

#include <nlohmann/json.hpp>

namespace nabto {
namespace test {

class AttachServer : public std::enable_shared_from_this<AttachServer> {
 public:
    AttachServer(boost::asio::io_context& io, log::LoggerPtr logger)
        : io_(io), logger_(logger), dtlsServer_(io, logger)
    {
    }

    static std::shared_ptr<AttachServer> create(boost::asio::io_context& io, log::LoggerPtr logger)
    {
        auto ptr = std::make_shared<AttachServer>(io, logger);
        ptr->init();
        return ptr;
    }

    void init() {
        auto self = shared_from_this();
        lib::error_code ec;
        dtlsServer_.setPort(0);
        dtlsServer_.setAlpnProtocols({"n5"});
        dtlsServer_.setSniCallback([](const std::string& sni){
                return DtlsServer::createCertificateContext(test::serverPrivateKey, test::serverPublicKey);
            });

        ec = dtlsServer_.init();
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach", [self](DtlsConnectionPtr connection, struct nabto_coap_server_request* request) {
            self->handleDeviceAttach(connection, request);
        });
    }

    void stop() {
        dtlsServer_.stop();
    }

    void handleDeviceAttach(DtlsConnectionPtr connection, struct nabto_coap_server_request* request)
    {
        nlohmann::json root;
        root["Status"] = 0;
        auto ka = root["KeepAlive"];
        ka["Interval"] = 30000;
        ka["RetryInterval"] = 2000;
        ka["MaxRetries"] = 15;

        std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);

        nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        nabto_coap_server_response_set_payload(request, cbor.data(), cbor.size());
        nabto_coap_server_response_set_code(request, NABTO_COAP_CODE_CREATED);
        nabto_coap_server_response_ready(request);
        nabto_coap_server_request_free(request);

    }

    uint16_t getPort()
    {
        return dtlsServer_.getPort();
    }
 private:
    boost::asio::io_context& io_;
    log::LoggerPtr logger_;
    DtlsServer dtlsServer_;

};

} }
