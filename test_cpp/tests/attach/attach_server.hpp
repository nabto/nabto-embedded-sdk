#pragma once

#include <boost/asio.hpp>
#include <fixtures/dtls_server/dtls_server.hpp>

#include "certificates.hpp"
//#include <util/test_future.hpp>
#include <tinycbor/cbor.h>

#include <fixtures/dtls_server/mbedtls_util.hpp>
#include <future>
#include <nlohmann/json.hpp>

namespace nabto {
namespace test {

static std::string serverHostname = "localhost-multi.nabto.net";

enum class ServiceErrorCode {
    NONE = 0,  // never sent on the protocol.
    INVALID_JWT_TOKEN = 1,
    DEVICE_NOT_ATTACHED = 2,  // used when the device is known by the
                              // basestation, but it is not attached.
    UNKNOWN_PRODUCT_ID =
        3,  // used when the product id does not exists in the basestation.
    UNKNOWN_DEVICE_ID =
        4,  // used when the device id does not exists in the basestation.
    UNKNOWN_DEVICE_FINGERPRINT =
        5,  // used when the basestation does not know the public key which the
            // device is using.
    REJECTED_SERVER_CONNECT_TOKEN = 6,  // used when the basestation rejects a
                                        // client for not having a valid SCT.
    WRONG_PRODUCT_ID = 7,  // used when the product id does not match the id
                           // configured in the basestation.
    WRONG_DEVICE_ID = 8,   // used when the device id does not match the device
                           // id configured in the basestation.
    AUTHORIZATION_TYPE_MISMATCH =
        9,  // used when the server key does not match the authorization type
            // the client is using.
    UNKNOWN_SERVER_KEY =
        10  // used when the server key is not known to the basestation.
};

enum class ServiceInvokeMessageFormat {
    BINARY = 0,  // message from base64 string
    NONE = 1,    // message is empty
    TEXT = 2,    // message from content type text/<plain|html>
};

class CoapError {
 public:
    CoapError(int coapErrorCode, ServiceErrorCode nabtoErrorCode,
              const std::string& message)
        : coapErrorCode_(coapErrorCode),
          nabtoErrorCode_(nabtoErrorCode),
          message_(message)
    {
    }

    CoapError(int coapErrorCode, const std::string& message)
        : coapErrorCode_(coapErrorCode), message_(message)
    {
    }

    void createCborError(std::shared_ptr<CoapServerResponse> response) const
    {
        nlohmann::json root;
        if (!message_.empty()) {
            root["Error"]["Message"] = message_;
        }
        if (nabtoErrorCode_) {
            root["Error"]["Code"] = static_cast<int>(*nabtoErrorCode_);
        }
        if (!root.empty()) {
            response->setContentFormat(
                NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
            std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);
            response->setPayload(cbor);
        }
        response->setCode((uint16_t)coapErrorCode_);
    }

 private:
    int coapErrorCode_;
    lib::optional<ServiceErrorCode> nabtoErrorCode_;
    std::string message_;
};

class AttachCoapServer {
 public:
    AttachCoapServer(boost::asio::io_context& io) : io_(io), dtlsServer_(io) {}

    AttachCoapServer(boost::asio::io_context& io, std::string ip, uint16_t port)
        : io_(io), dtlsServer_(io, ip)
    {
        port_ = port;
    }

    virtual ~AttachCoapServer() {}

    void init()
    {
        lib::error_code ec;
        dtlsServer_.setPort(port_);
        dtlsServer_.setAlpnProtocols({"n5"});
        dtlsServer_.setSniCallback([this](const std::string& sni) {
            (void)sni;
            return DtlsServer::createCertificateContext(privateKey_,
                                                        certificateChain_);
        });

        ec = dtlsServer_.init();
        initCoapHandlers();
    }

    void init(std::vector<std::string> alpns)
    {
        lib::error_code ec;
        dtlsServer_.setPort(port_);
        dtlsServer_.setAlpnProtocols(alpns);
        dtlsServer_.setSniCallback([this](const std::string& sni) {
            (void)sni;
            return DtlsServer::createCertificateContext(privateKey_,
                                                        certificateChain_);
        });

        ec = dtlsServer_.init();
        initCoapHandlers();
    }

    void stop()
    {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        std::promise<void> promise;
        std::future<void> future = promise.get_future();
        boost::asio::post(io_, [this, &promise]() {
            dtlsServer_.stop();
            promise.set_value();
        });
        future.get();
    }

    virtual void initCoapHandlers() = 0;

    uint16_t getPort() { return dtlsServer_.getPort(); }

    std::string getHostname() { return serverHostname; }

    std::string getRootCerts() { return rootCert_; }

    std::array<uint8_t, 16> getFingerprint()
    {
        auto fp = getFingerprintFromPem(certificateChain_[0]);
        std::array<uint8_t, 16> ret;
        memcpy(ret.data(), fp->data(), 16);
        return ret;
    }

    void setCertificateChain(const std::vector<std::string>& certificateChain)
    {
        certificateChain_ = certificateChain;
    }

 protected:
    boost::asio::io_context& io_;
    DtlsServer dtlsServer_;
    uint16_t port_ = 0;
    bool stopped_ = false;
    std::string privateKey_ = privateKey;
    std::vector<std::string> certificateChain_ = {localhostMultiNabtoNetCert,
                                                  testIntermediateCert};
    std::string rootCert_ = testRootCa;
};

static const std::string firebaseOkResponse = R"(
{
    "name": "foobar"
}
)";

class AttachServer : public AttachCoapServer,
                     public std::enable_shared_from_this<AttachServer> {
 public:
    AttachServer(boost::asio::io_context& io) : AttachCoapServer(io) {}

    AttachServer(boost::asio::io_context& io,
                 const std::vector<std::string>& certificateChain)
        : AttachCoapServer(io)
    {
    }

    AttachServer(boost::asio::io_context& io, std::string ip, uint16_t port)
        : AttachCoapServer(io, ip, port)
    {
    }

    static std::shared_ptr<AttachServer> create(boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<AttachServer>(io);
        ptr->init();
        return ptr;
    }

    static std::shared_ptr<AttachServer> create(
        boost::asio::io_context& io, std::vector<std::string> certificateChain)
    {
        auto ptr = std::make_shared<AttachServer>(io);
        ptr->setCertificateChain(certificateChain);
        ptr->init();
        return ptr;
    }

    static std::shared_ptr<AttachServer> create(boost::asio::io_context& io,
                                                std::string ip, uint16_t port)
    {
        auto ptr = std::make_shared<AttachServer>(io, ip, port);
        ptr->init();
        return ptr;
    }

    static std::shared_ptr<AttachServer> create_alpn(boost::asio::io_context& io, std::vector<std::string> alpns)
    {
        auto ptr = std::make_shared<AttachServer>(io);
        ptr->init(alpns);
        return ptr;
    }

    static std::shared_ptr<AttachServer> create(boost::asio::io_context& io, uint32_t min, uint32_t max)
    {
        auto ptr = std::make_shared<AttachServer>(io);
        ptr->setHandshakeTimeout(min, max);
        ptr->init();
        return ptr;
    }

    void dropNthPacket(int n) { dtlsServer_.dropNthPacket(n); }

    void setHandshakeTimeout(uint32_t min, uint32_t max) {
        dtlsServer_.setHandshakeTimeout(min, max);
    }

    void initCoapHandlers()
    {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(
            NABTO_COAP_CODE_POST, "/device/attach-start",
            [self](DtlsConnectionPtr connection,
                   std::shared_ptr<CoapServerRequest> request,
                   std::shared_ptr<CoapServerResponse> response) {
                if (self->attachCount_ == self->invalidAttach_) {
                    self->handleDeviceAttachWrongResponse(connection, request,
                                                          response);
                    self->attachCount_ += 1;
                } else {
                    self->handleDeviceAttach(connection, request, response);
                }
            });
        dtlsServer_.addResourceHandler(
            NABTO_COAP_CODE_POST, "/device/attach-end",
            [self](DtlsConnectionPtr connection,
                   std::shared_ptr<CoapServerRequest> request,
                   std::shared_ptr<CoapServerResponse> response) {
                (void)connection;
                (void)request;
                response->setCode(201);
                // self->attachCount_ += 1;
                return;
            });
        dtlsServer_.addResourceHandler(
            NABTO_COAP_CODE_PUT, "/device/sct",
            [self](DtlsConnectionPtr connection,
                   std::shared_ptr<CoapServerRequest> request,
                   std::shared_ptr<CoapServerResponse> response) {
                (void)connection;
                (void)request;
                response->setCode(201);
                return;
            });
        dtlsServer_.addResourceHandler(
            NABTO_COAP_CODE_POST, "/device/fcm/send",
            [self](DtlsConnectionPtr connection,
                   std::shared_ptr<CoapServerRequest> request,
                   std::shared_ptr<CoapServerResponse> response) {
                (void)connection;
                (void)request;
                response->setCode(201);
                response->setContentFormat(
                    NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
                nlohmann::json root;
                root["StatusCode"] = 200;
                root["Body"] = firebaseOkResponse;
                std::vector<uint8_t> b = nlohmann::json::to_cbor(root);
                response->setPayload(b);
                return;
            });
        dtlsServer_.addResourceHandler(
            NABTO_COAP_CODE_POST, "/device/service/invoke",
            [self](DtlsConnectionPtr connection,
                std::shared_ptr<CoapServerRequest> request,
                std::shared_ptr<CoapServerResponse> response) {
                    self->handleServiceInvoke(connection, request, response);
            });
        dtlsServer_.addResourceHandler(
            NABTO_COAP_CODE_POST, "/device/ice-servers",
            [self](DtlsConnectionPtr connection,
                std::shared_ptr<CoapServerRequest> request,
                std::shared_ptr<CoapServerResponse> response) {
                    self->handleTurn(connection, request, response);
            });
    }

    void handleTurn(DtlsConnectionPtr connection,
        std::shared_ptr<CoapServerRequest> request,
        std::shared_ptr<CoapServerResponse> response)
    {
        (void)request;
        if (request->getContentFormat() !=
            NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
            CoapError err = CoapError(415, "Bad content format");
            err.createCborError(response);
            return;
        }
        std::vector<uint8_t> payload = request->getPayload();
        nlohmann::json decodedRequest;
        try {
            decodedRequest = nlohmann::json::from_cbor(payload);
        }
        catch (std::exception& e) {
            CoapError err = CoapError(400, "Invalid cbor");
            err.createCborError(response);
            return;
        }
        std::string identifier;
        try {
            identifier = decodedRequest["Identifier"].get<std::string>();
        } catch (std::exception& e) {
            CoapError err = CoapError(400, "Missing or invalid Identifier");
            err.createCborError(response);
            return;
        }

        response->setCode(201);
        response->setContentFormat(
            NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        nlohmann::json s1;
        s1["Username"] = "test:devTest:" + identifier;
        s1["Credential"] = "verySecretAccessKey";
        s1["Urls"] = nlohmann::json::array({ "turn:turn.nabto.net:9991?transport=udp", "turn:turn.nabto.net:9991?transport=tcp" });
        nlohmann::json s2;
        s2["Username"] = "test:devTest:" + identifier;
        s2["Credential"] = "anotherVerySecretAccessKey";
        s2["Urls"] = nlohmann::json::array({ "turns:turn.nabto.net:443?transport=tcp" });
        nlohmann::json s3;
        s3["Urls"] = nlohmann::json::array({ "stun:stun.nabto.net:5874" });

        nlohmann::json root = nlohmann::json::array({s1, s2, s3});

        std::vector<uint8_t> b = nlohmann::json::to_cbor(root);
        response->setPayload(b);
    }

    void handleServiceInvoke(DtlsConnectionPtr connection,
                             std::shared_ptr<CoapServerRequest> request,
                             std::shared_ptr<CoapServerResponse> response)
    {
        (void)request;
        if (request->getContentFormat() !=
            NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
            CoapError err = CoapError(400, "Bad content format");
            err.createCborError(response);
            return;
        }
        std::vector<uint8_t> payload = request->getPayload();
        nlohmann::json decodedRequest;
        try {
            decodedRequest = nlohmann::json::from_cbor(payload);
        } catch (std::exception& e) {
            CoapError err = CoapError(400, "Invalid cbor");
            err.createCborError(response);
            return;
        }
        std::string serviceId;
        std::vector<uint8_t> message;
        try {
            serviceId = decodedRequest["ServiceId"].get<std::string>();
        } catch (std::exception& e) {
            CoapError err = CoapError(400, "Missing or invalid ServiceId");
            err.createCborError(response);
            return;
        }

        try {
            message = decodedRequest["Message"].get<nlohmann::json::binary_t>();
        } catch (std::exception& e) {
            CoapError err = CoapError(400, "Missing or invalid Message");
            err.createCborError(response);
            return;
        }

        std::string msg = std::string(
            reinterpret_cast<const char*>(message.data()), message.size());

        if (msg == "foo") {
            response->setCode(201);
            response->setContentFormat(
                NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
            nlohmann::json root;
            root["StatusCode"] = 200;
            std::string body = "{\"hello\": \"world\"}";
            root["MessageFormat"] = ServiceInvokeMessageFormat::BINARY;
            root["Message"] = nlohmann::json::binary_t(std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(body.data()),
                reinterpret_cast<const uint8_t*>(body.data() + body.size())));
            std::vector<uint8_t> b = nlohmann::json::to_cbor(root);
            response->setPayload(b);
        } else if (msg == "text-format") {
            response->setCode(201);
            response->setContentFormat(
                NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
            nlohmann::json root;
            root["StatusCode"] = 200;
            std::string body = "text string";
            root["MessageFormat"] = ServiceInvokeMessageFormat::TEXT;
            root["Message"] = nlohmann::json::binary_t(std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(body.data()),
                reinterpret_cast<const uint8_t*>(body.data() + body.size())));
            std::vector<uint8_t> b = nlohmann::json::to_cbor(root);
            response->setPayload(b);
        } else if (msg == "none-format") {
            response->setCode(201);
            response->setContentFormat(
                NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
            nlohmann::json root;
            root["StatusCode"] = 200;
            root["MessageFormat"] = ServiceInvokeMessageFormat::NONE;
            std::vector<uint8_t> b = nlohmann::json::to_cbor(root);
            response->setPayload(b);
        } else if (msg == "bad-response") {
            CoapError err = CoapError(502, "content type header missing");
            err.createCborError(response);
        } else if (msg == "invalid-service") {
            CoapError err = CoapError(404, "no such service ID");
            err.createCborError(response);
        } else if (msg == "back-compat") {
            response->setCode(201);
            response->setContentFormat(
                NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
            nlohmann::json root;
            root["StatusCode"] = 200;
            std::string body = "hello world";
            root["Message"] = nlohmann::json::binary_t(std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(body.data()),
                reinterpret_cast<const uint8_t*>(body.data() + body.size())));
            std::vector<uint8_t> b = nlohmann::json::to_cbor(root);
            response->setPayload(b);
        }
    }

    void handleDeviceAttach(DtlsConnectionPtr connection,
                            std::shared_ptr<CoapServerRequest> request,
                            std::shared_ptr<CoapServerResponse> response)
    {
        (void)connection;
        (void)request;
        nlohmann::json req = nlohmann::json::from_cbor(request->getPayload());

        if (deviceFp_) {
            std::array<uint8_t, 32> fp =
                *(connection->getOtherPeerFingerprint());
            for (size_t i = 0; i < 32; i++) {
                if (*(deviceFp_ + i) != fp[i]) {
                    CoapError err = CoapError(
                        404, ServiceErrorCode::UNKNOWN_DEVICE_FINGERPRINT,
                        "Unknown device fingerprint");
                    err.createCborError(response);
                    return;
                }
            }
        }

        if (deviceId_ &&
            req["DeviceId"].get<std::string>().compare(deviceId_) != 0) {
            CoapError err = CoapError(400, ServiceErrorCode::WRONG_DEVICE_ID,
                                      "Wrong device ID");
            err.createCborError(response);
            return;
        }

        if (productId_ &&
            req["ProductId"].get<std::string>().compare(productId_) != 0) {
            std::ostringstream oss;
            oss << "Wrong product ID. Got: \""
                << req["ProductId"].get<std::string>() << "\" expected: \""
                << productId_ << "\"";
            CoapError err =
                CoapError(400, ServiceErrorCode::WRONG_PRODUCT_ID, oss.str());
            err.createCborError(response);
            return;
        }

        nlohmann::json root;
        root["Status"] = 0;
        nlohmann::json ka;
        ka["Interval"] = keepAliveInterval_;
        ka["RetryInterval"] = keepAliveRetryInterval_;
        ka["MaxRetries"] = keepAliveMaxRetries_;
        root["KeepAlive"] = ka;
        nlohmann::json stun;
        stun["Host"] = "stun.nabto.net";
        stun["Port"] = 3478;
        root["Stun"] = stun;

        std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);

        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setPayload(cbor);
        response->setCode(201);
        attachCount_ += 1;
    }

    void handleDeviceAttachWrongResponse(
        DtlsConnectionPtr connection,
        std::shared_ptr<CoapServerRequest> request,
        std::shared_ptr<CoapServerResponse> response)
    {
        (void)connection;
        (void)request;
        nlohmann::json root;
        root["FOOBAR"] = "BAZ";

        std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);

        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setPayload(cbor);
        response->setCode(201);
    }

    void setKeepAliveSettings(uint64_t interval, uint64_t retryInterval,
                              uint64_t maxRetries)
    {
        keepAliveInterval_ = interval;
        keepAliveRetryInterval_ = retryInterval;
        keepAliveMaxRetries_ = maxRetries;
    }

    void niceClose()
    {
        std::promise<void> promise;
        std::future<void> future = promise.get_future();
        boost::asio::post(io_, [this, &promise]() {
            dtlsServer_.asyncNiceClose([&promise](const lib::error_code& ec) {
                promise.set_value();
                (void)ec;
                // all current connections is closed nicely.
            });
        });
        future.get();
    }

    uint64_t keepAliveInterval_ = 30000;
    uint64_t keepAliveRetryInterval_ = 2000;
    uint64_t keepAliveMaxRetries_ = 15;

    std::atomic<uint64_t> attachCount_ = {0};
    uint64_t invalidAttach_ = 42;
    uint8_t* deviceFp_ = NULL;
    const char* deviceId_ = NULL;
    const char* productId_ = NULL;
};

class RedirectServer : public AttachCoapServer,
                       public std::enable_shared_from_this<RedirectServer> {
 public:
    RedirectServer(boost::asio::io_context& io) : AttachCoapServer(io) {}

    static std::shared_ptr<RedirectServer> create(boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<RedirectServer>(io);
        ptr->init();
        return ptr;
    }

    void initCoapHandlers()
    {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(
            NABTO_COAP_CODE_POST, "/device/attach-start",
            [self](DtlsConnectionPtr connection,
                   std::shared_ptr<CoapServerRequest> request,
                   std::shared_ptr<CoapServerResponse> response) {
                (void)connection;
                (void)request;
                if (self->invalidRedirect_ == self->redirectCount_) {
                    self->handleDeviceRedirectInvalidResponse(connection,
                                                              response);
                } else {
                    self->handleDeviceRedirect(connection, response);
                }
                self->redirectCount_++;
            });
    }

    void handleDeviceRedirectInvalidResponse(
        DtlsConnectionPtr connection,
        std::shared_ptr<CoapServerResponse> response)
    {
        (void)connection;
        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setCode(201);
    }

    void handleDeviceRedirect(DtlsConnectionPtr connection,
                              std::shared_ptr<CoapServerResponse> response)
    {
        (void)connection;
        uint8_t buffer[128];

        CborEncoder encoder;
        CborEncoder map;
        cbor_encoder_init(&encoder, buffer, 128, 0);
        cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

        cbor_encode_text_stringz(&map, "Status");
        uint8_t redirect = 1;
        cbor_encode_uint(&map, redirect);

        cbor_encode_text_stringz(&map, "Host");
        cbor_encode_text_stringz(&map, host_.c_str());

        cbor_encode_text_stringz(&map, "Port");
        cbor_encode_uint(&map, port_);

        cbor_encode_text_stringz(&map, "Fingerprint");
        cbor_encode_byte_string(&map, fingerprint_.data(), fingerprint_.size());

        cbor_encoder_close_container(&encoder, &map);

        BOOST_TEST(cbor_encoder_get_extra_bytes_needed(&encoder) == (size_t)0);

        size_t length = cbor_encoder_get_buffer_size(&encoder, buffer);

        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setPayload(lib::span<const uint8_t>(buffer, length));
        response->setCode(201);
    }

    void setRedirect(const std::string& host, uint16_t port,
                     std::array<uint8_t, 16> fingerprint)
    {
        host_ = host;
        port_ = port;
        fingerprint_ = fingerprint;
    }

    std::atomic<uint64_t> redirectCount_ = {0};

    // if the count matches this number send an invalid redirect
    uint64_t invalidRedirect_ = 42;

 private:
    std::string host_;
    uint16_t port_;
    std::array<uint8_t, 16> fingerprint_;
};

class AccessDeniedServer
    : public AttachCoapServer,
      public std::enable_shared_from_this<AccessDeniedServer> {
 public:
    AccessDeniedServer(boost::asio::io_context& io) : AttachCoapServer(io) {}

    static std::shared_ptr<AccessDeniedServer> create(
        boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<AccessDeniedServer>(io);
        ptr->init();
        return ptr;
    }

    void initCoapHandlers()
    {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(
            NABTO_COAP_CODE_POST, "/device/attach-start",
            [self](DtlsConnectionPtr connection,
                   std::shared_ptr<CoapServerRequest> request,
                   std::shared_ptr<CoapServerResponse> response) {
                (void)response;
                (void)request;
                connection->accessDenied();
                self->coapRequestCount_++;
            });
    }

    std::atomic<uint64_t> coapRequestCount_ = {0};
};

}  // namespace test
}  // namespace nabto
